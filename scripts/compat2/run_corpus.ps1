<#
.SYNOPSIS
    Xenolith compatibility harness - full corpus run (from-zero rewrite, PS 5.1, zero dependencies).

.DESCRIPTION
    Runs scripts/compat2/run_one.ps1 for every sample listed in a manifest, with at
    most 4 samples in flight (native .NET RunspacePool - no modules, no PS 7).

    Manifest formats (auto-detected):
      1. Plain text, UTF-8: one sample path per line. Blank lines and lines
         starting with '#' are ignored. Relative lines resolve against the
         manifest's own directory.
      2. JSON: an array of path strings, an array of sample objects, or
         { "samples": [ ... ] }. For objects the path field is the first
         non-empty of: path, file, input, sample, name (relative values
         resolve against the manifest directory); "origin" is an
         existence-checked fallback. Unusable lines become per-sample
         failures recorded in summary.json - they never abort the run.
    The manifest line/value is recorded verbatim in each result's "file" field.

    Output: <ResultsDir>\summary.json = { "total": n, "passed": n, "results": [ ... ] }
    (ConvertTo-Json -Depth 6). run_one.ps1 also drops <ResultsDir>\<sample>.json per
    sample and keeps packed artifacts under <ResultsDir>\packed\ for inspection.

    Samples and packed artifacts are never executed; samples are never modified.

.PARAMETER Manifest
    Path to the manifest file.

.PARAMETER ResultsDir
    Directory for summary.json and per-sample results (created if missing).

.PARAMETER ToolPath
    Path to xenolith.exe. Default: <repo>\target\release\xenolith.exe where <repo>
    is two levels above this script's directory.

.EXITCODES
    0 every sample passed | 1 at least one sample failed/crashed/timed out |
    2 harness-level error (manifest or tool missing/unreadable, no samples listed)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Manifest,
    [Parameter(Mandatory = $true)][string]$ResultsDir,
    [string]$ToolPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Diag {
    param([string]$Msg)
    [Console]::Error.WriteLine("run_corpus: $Msg")
}

# --- harness-level preflight: exit 2 before touching any sample ----------------
$runOne = Join-Path $PSScriptRoot 'run_one.ps1'
if (-not (Test-Path -LiteralPath $runOne -PathType Leaf)) {
    Write-Diag "run_one.ps1 not found next to this script: $runOne"
    exit 2
}
if (-not $ToolPath) {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ToolPath = Join-Path $repo 'target\release\xenolith.exe'
}
if (-not (Test-Path -LiteralPath $ToolPath -PathType Leaf)) {
    Write-Diag "tool not found: $ToolPath (build with 'cargo build --release' or pass -ToolPath)"
    exit 2
}
$toolAbs = (Resolve-Path -LiteralPath $ToolPath).ProviderPath

if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    Write-Diag "manifest not found: $Manifest"
    exit 2
}
$manifestAbs = (Resolve-Path -LiteralPath $Manifest).ProviderPath
$manifestDir = Split-Path $manifestAbs -Parent

try {
    if (-not (Test-Path -LiteralPath $ResultsDir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $ResultsDir -Force
    }
    $resultsDirAbs = (Resolve-Path -LiteralPath $ResultsDir).ProviderPath
} catch {
    Write-Diag "ResultsDir unusable: $($_.Exception.Message)"
    exit 2
}

# Each corpus run regenerates its own packed artifacts; leftovers from earlier
# runs (older binaries, multi-hundred-MB giants) otherwise accumulate until the
# disk fills and the tool's final fs::write fails with ENOSPC mid-run. Purge
# only the regenerable .xl.exe artifacts - per-sample JSON records are kept.
$stalePackedDir = Join-Path $resultsDirAbs 'packed'
if (Test-Path -LiteralPath $stalePackedDir -PathType Container) {
    Get-ChildItem -LiteralPath $stalePackedDir -File -Filter '*.xl.exe' -ErrorAction SilentlyContinue |
        ForEach-Object {
            try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop }
            catch { Write-Diag ("cannot remove stale artifact " + $_.FullName + ": " + $_.Exception.Message) }
        }
}

try {
    $manifestText = [System.IO.File]::ReadAllText($manifestAbs)   # BOM-aware, else UTF-8
} catch {
    Write-Diag "manifest unreadable: $($_.Exception.Message)"
    exit 2
}

# Resolve one manifest path value to an absolute path; $null on illegal characters.
# Never throws: a bad line becomes a recorded per-sample failure, not a harness crash.
function Resolve-ManifestEntryPath {
    param([string]$Value, [string]$BaseDir)
    try {
        if ([System.IO.Path]::IsPathRooted($Value)) { return [System.IO.Path]::GetFullPath($Value) }
        return [System.IO.Path]::GetFullPath((Join-Path $BaseDir $Value))
    } catch { return $null }
}
function Get-JsonProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

$entries = New-Object System.Collections.ArrayList
$trimmedHead = $manifestText.TrimStart()
$isJson = $trimmedHead.StartsWith('[') -or $trimmedHead.StartsWith('{')

if ($isJson) {
    # JSON manifest: array of path strings, array of sample objects, or
    # { "samples": [ ... ] }. Object fields tried in order: path, file, input,
    # sample, name (relative values resolve against the manifest directory);
    # "origin" is used as an existence-checked fallback when the preferred
    # field does not point at a file.
    try {
        $parsed = $manifestText | ConvertFrom-Json
        # PS 5.1: a top-level JSON array comes out of the pipeline as ONE
        # Object[] item (it is NOT enumerated into its elements), which would
        # collapse the whole corpus into a single bogus "manifest JSON entry 1
        # has no path/name field" failure. @($parsed) flattens the array into
        # its elements; a single JSON object stays a single element either way.
        $jsonItems = @($parsed)
    } catch {
        Write-Diag ("manifest is JSON-shaped but unparseable: " + $_.Exception.Message)
        exit 2
    }
    if ($jsonItems.Count -eq 1) {
        $inner = Get-JsonProperty $jsonItems[0] 'samples'
        if ($null -ne $inner) { $jsonItems = @($inner) }
    }
    $idx = 0
    foreach ($el in $jsonItems) {
        $idx++
        if ($el -is [string]) {
            $t = $el.Trim()
            if ($t.Length -eq 0) { continue }
            $abs = Resolve-ManifestEntryPath $t $manifestDir
            if ($abs) {
                $null = $entries.Add([pscustomobject]@{ Line = $t; Abs = $abs; Bad = $null })
            } else {
                $null = $entries.Add([pscustomobject]@{ Line = $t; Abs = $null; Bad = "illegal path in manifest: $t" })
            }
            continue
        }
        $cand = $null
        foreach ($f in @('path', 'file', 'input', 'sample', 'name')) {
            $v = Get-JsonProperty $el $f
            if ($v -is [string] -and $v.Trim().Length -gt 0) { $cand = $v.Trim(); break }
        }
        if (-not $cand) {
            $null = $entries.Add([pscustomobject]@{ Line = ("manifest-entry-" + $idx); Abs = $null; Bad = "manifest JSON entry $idx has no path/name field" })
            continue
        }
        $abs = Resolve-ManifestEntryPath $cand $manifestDir
        if ((-not $abs) -or -not (Test-Path -LiteralPath $abs -PathType Leaf)) {
            $origin = Get-JsonProperty $el 'origin'
            if ($origin -is [string] -and $origin.Trim().Length -gt 0) {
                $oAbs = Resolve-ManifestEntryPath $origin.Trim() $manifestDir
                if ($oAbs -and (Test-Path -LiteralPath $oAbs -PathType Leaf)) { $abs = $oAbs; $cand = $origin.Trim() }
            }
        }
        if ($abs) {
            $null = $entries.Add([pscustomobject]@{ Line = $cand; Abs = $abs; Bad = $null })
        } else {
            $null = $entries.Add([pscustomobject]@{ Line = $cand; Abs = $null; Bad = "illegal path in manifest: $cand" })
        }
    }
} else {
    # Plain-text manifest: one sample path per line; blank lines and '#' comments ignored.
    foreach ($raw in ($manifestText -split "\r?\n")) {
        $t = $raw.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
        $abs = Resolve-ManifestEntryPath $t $manifestDir
        if ($abs) {
            $null = $entries.Add([pscustomobject]@{ Line = $t; Abs = $abs; Bad = $null })
        } else {
            $null = $entries.Add([pscustomobject]@{ Line = $t; Abs = $null; Bad = "illegal path in manifest: $t" })
        }
    }
}
if ($entries.Count -eq 0) {
    Write-Diag "manifest lists no samples: $manifestAbs"
    exit 2
}

# --- dispatch: RunspacePool, max 4 concurrent samples ---------------------------
$jobScript = @'
param($RunOnePath, $InAbs, $OutDirAbs, $ToolAbs, $Label)
try {
    $out = & $RunOnePath -InputFile $InAbs -OutDir $OutDirAbs -ToolPath $ToolAbs -FileLabel $Label
    return ,@($out)
} catch {
    return ,@("RUNONE_EXCEPTION: $($_.Exception.Message)")
}
'@

function Get-SafeFileName {
    param([string]$Value)
    try { return [System.IO.Path]::GetFileName($Value) } catch { return $Value }
}

$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 4)
$pool.Open()
$jobsByIndex = @{}
for ($i = 0; $i -lt $entries.Count; $i++) {
    $e = $entries[$i]
    if ($e.Bad) { continue }   # recorded directly at harvest; never dispatched
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($jobScript).
        AddArgument($runOne).
        AddArgument($e.Abs).
        AddArgument($resultsDirAbs).
        AddArgument($toolAbs).
        AddArgument($e.Line)
    $handle = $ps.BeginInvoke()
    $jobsByIndex[$i] = [pscustomobject]@{ Ps = $ps; Handle = $handle; Entry = $e }
}

function New-SynthFail {
    param([string]$Name, [string]$File, [string]$Why)
    return [pscustomobject]@{
        name         = $Name
        file         = $File
        status       = 'fail'
        toolExitCode = -1
        seconds      = 0
        errorDigest  = $Why
    }
}

# --- harvest in manifest order ---------------------------------------------------
$results = New-Object System.Collections.ArrayList
$done = 0
for ($i = 0; $i -lt $entries.Count; $i++) {
    $done++
    $entry = $entries[$i]
    $obj = $null
    if ($entry.Bad) {
        $obj = New-SynthFail -Name (Get-SafeFileName $entry.Line) -File $entry.Line -Why $entry.Bad
    } else {
        $j = $jobsByIndex[$i]
        try {
            $outputs = @($j.Ps.EndInvoke($j.Handle))    # blocks until this job finishes
            $errText = ''
            foreach ($er in $j.Ps.Streams.Error) { $errText += ($er.ToString() + ' | ') }
            $line = $null
            foreach ($o in $outputs) {
                if ($null -ne $o) { $s = "$o".Trim(); if ($s.Length -gt 0) { $line = $s } }
            }
            if ($line -and $line.StartsWith('RUNONE_EXCEPTION:')) {
                $obj = New-SynthFail -Name (Get-SafeFileName $entry.Abs) -File $entry.Line -Why ($line.Substring('RUNONE_EXCEPTION:'.Length).Trim())
            } elseif ($line -and $line.StartsWith('{')) {
                try { $obj = $line | ConvertFrom-Json } catch { $obj = $null }
                if ($obj) {
                    # normalize: schema must hold even if run_one misbehaved
                    $st = "$($obj.status)"
                    if (@('pass', 'fail', 'crash', 'timeout') -notcontains $st) { $obj = $null }
                }
            }
            if (-not $obj) {
                $why = 'run_one produced no valid result JSON'
                if ($errText) { $why += ' (' + $errText.Trim(' |').Substring(0, [math]::Min(300, $errText.Trim(' |').Length)) + ')' }
                $obj = New-SynthFail -Name (Get-SafeFileName $entry.Abs) -File $entry.Line -Why $why
            }
        } catch {
            $obj = New-SynthFail -Name (Get-SafeFileName $entry.Abs) -File $entry.Line -Why ("run_one invoke failed: " + $_.Exception.Message)
        } finally {
            $j.Ps.Dispose()
        }
    }
    $null = $results.Add($obj)
    Write-Host ("[{0}/{1}] {2} -> {3}" -f $done, $entries.Count, $obj.name, $obj.status)
}
$pool.Close()
$pool.Dispose()

# --- summary ----------------------------------------------------------------------
$passed = @($results | Where-Object { $_.status -eq 'pass' }).Count
$summary = [pscustomobject]@{
    total   = $results.Count
    passed  = $passed
    results = @($results)
}
$summaryPath = Join-Path $resultsDirAbs 'summary.json'
try {
    [System.IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
} catch {
    Write-Diag "cannot write summary: $($_.Exception.Message)"
    exit 2
}

Write-Host ("corpus done: {0}/{1} passed; summary: {2}" -f $passed, $results.Count, $summaryPath)
if ($passed -eq $results.Count) { exit 0 } else { exit 1 }
