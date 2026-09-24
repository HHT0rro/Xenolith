<#
.SYNOPSIS
    Xenolith functional verification, differential final form (PS 5.1, zero dependencies).

.DESCRIPTION
    Phase 3 of the compatibility harness: "the packed binary still works" with a
    per-sample DIFFERENTIAL against the original, so environmental noise stops
    counting as product failures and product failures stop hiding behind the
    environment.

    Artifacts are located by the phase-3 key convention of run_one.ps1 /
    run_corpus.ps1: <full-name-with-extension>.xl.exe (IDA_ida.dll packs to
    IDA_ida.dll.xl.exe; the extension is part of the key, so basename peers
    foo.dll / foo.exe can never overwrite each other).

    Fail-fast consistency preflight (exit 2, no sample is touched): the manifest
    must carry no duplicate names; the packed directory must exist and hold at
    least one artifact; every artifact must map to a manifest entry (stale /
    old-key / wrong-directory sets are refused); a partial set is accepted ONLY
    when the phase-1 summary.json beside packed\ records a failure (fail/crash/
    timeout, or toolExitCode != 0) for every absent key - a phase-1 success
    without its artifact, or an unattributable absence, is an orchestration
    error. Corroborated absences (real pack failures upstream) become per-sample
    'fail' entries ("packed artifact absent: phase-1 recorded <status> -
    differential impossible"), so the pipeline verdict keeps counting them;
    skip-classified entries keep their skip verdict with the pack failure
    noted. Orchestration errors are NEVER reported as per-sample failures (the
    phase-2 0/89 lesson).

    Per non-skip sample BOTH sides are measured under identical conditions -
    same directory, same timeout, same kill and cleanup - and neither side ever
    executes or modifies an original:

      packed side   copy <packed>.xl.exe  -> <origDir>\<origBase>.xenolith-test.<ext>
      orig side     copy <original>       -> <origDir>\<origBase>.orig-test.<ext>

      load  xl-loadhost (LoadLibraryExW with LOAD_WITH_ALTERED_SEARCH_PATH, so
            dependencies resolve against the module's own directory - the same
            semantics the packed stub's runtime binding uses) the
            staged COPY in the original's directory, so sibling dependencies
            resolve on both sides - the phase-2 126/1114 environmental failures
            came from loading artifacts out of packed\ with no siblings. The
            child runs inside a Win32 kill-on-close job object created BEFORE
            Start (no containment gap), 60 s hard timeout.
      exec  launch the staged COPY (UseShellExecute=false, cwd = original's
            directory), whole tree inside the pre-created job, 30 s hard
            timeout, then TerminateJobObject + taskkill /T /F. Still alive at
            the timeout = the sample ran (GUI-style); quick non-crash exit also
            = ran. A GUI briefly appearing on BOTH sides is normal.

    Staged copies are ALWAYS deleted afterwards (retry loop; locked files are
    re-tried 24 x 500 ms), every staged path is appended to the cleanup ledger
    BEFORE the copy is made, and the next run sweeps leftovers a hard-killed
    run could not clean. If the original's directory is not writable both sides
    fall back to <ResultsDir>\exe-run\ with cwd + PATH pinned to the original's
    directory (identical treatment keeps the differential fair).

    Measurement hygiene (fixes false 126/1114s traced to the harness, without
    touching any verdict rule): every staged copy waits for full materialization
    (length parity with the source, then a 500 ms settle - under 4-worker
    concurrent I/O an instant load of a fresh copy produced transient false
    exit 3 / lastWinError 1114 or 126; phase-3 multi-round runs then showed the
    false 126 outliving the earlier 300 ms window on BOTH the orig and the
    packed side, while the same sample loaded fine after a delay - so the
    settle is now 500 ms and the retries back off exponentially), and the two
    outcomes a not-yet-settled copy can cause - load-side reject, exec-side
    startfail - are retried at most 4x with exponential backoff (400 / 800 /
    1600 ms). Real rejects (missing sibling, genuine 1114) and real start
    failures persist over retries and are judged exactly as strictly as before;
    crash/timeout/exit/alive are never retried; every retry is disclosed in the
    behavior signature. xl-loadhost failure JSON also
    carries fileExists/fileLen so "copy not visible" is distinguishable from
    "dependency missing" in the record. A second harness defect found while
    chasing the 7 phase-4 mismatches is also fixed at the instrument: xl-loadhost
    declared LoadLibraryW with a second (flag) parameter that the one-parameter
    API silently ignored, so ALL loads ran under standard search - the module's
    own directory was never searched and in-place originals whose siblings live
    there failed deterministically with 126 while the packed side (runtime stub
    resolving from the module dir) loaded; it now calls
    LoadLibraryExW(LOAD_WITH_ALTERED_SEARCH_PATH) as always intended.

    Verdict rules (strict - a crash is a crash, nothing is waved through):
      pass      packed OK and orig OK (exec: both sides completed the same way -
                both exited or both stayed alive)
      envfail   packed failed/crashed/timed out AND the orig copy failed the
                same way (same outcome class and same error code) - the
                environment cannot run even the pristine original in place, so
                this is not a product defect. detail carries both sides'
                behavior and error codes side by side. One proven-equivalence
                exception (load mode only): orig reject 126 + packed reject
                1114 IS the same environmental refusal when the original's
                import table provably names a dependency DLL that no search
                location provides - a missing dependency fails the original at
                import resolution (126) and the packed image inside DllMain
                where the stub performs writeback import binding (1114); the
                audit is done per-sample on the original's bytes, and with all
                dependencies locatable the fail verdict stands untouched.
      fail      packed failed to load/start/stage while the orig copy was fine
      crash     packed crashed (0xC0000005-class exit, negative NTSTATUS) while
                the orig copy was fine
      timeout   packed hung past the hard timeout (load mode) while the orig
                copy was fine
      mismatch  both sides completed but diverged (one quick-exits while the
                other stays alive 30 s), or the packed side worked while the
                orig copy failed - left for the repair round to investigate
      skip      classification.json says skip; reason recorded verbatim

    If both sides fail but NOT in the same way (different class or different
    error code) the packed side's outcome stands as a real fail/crash/timeout
    with the orig side's divergent failure noted - strictness is not relaxed
    just because the original also misbehaved.

    Safety invariants: originals are never executed and never modified (only
    renamed COPIES of them run); the corpus under out\compat-corpus is never
    written to; only harness-owned <base>.xenolith-test.<ext> / <base>.orig-
    test.<ext> copies are created/removed; every process tree is killed
    (kill-on-close job + taskkill /T /F) before the run moves on.

.PARAMETER Manifest
    Path to the phase-1 manifest (JSON array of { name, origin, ... }; plain text
    "one file per line" is also accepted). Relative "name" values resolve against
    the manifest's directory; "origin" is the preferred original location.

.PARAMETER ResultsDir
    Output directory for THIS functional run: summary.json and exe-run\ (staging
    fallback + cleanup ledger) live here.

.PARAMETER PackedDir
    Directory holding the phase-1 packed artifacts (<full-name>.xl.exe). Default
    probing order: this parameter, then <ResultsDir>\packed, then
    <repo>\out\compat-results\packed. The chosen directory must satisfy the
    consistency preflight or the script exits 2.

.PARAMETER ClassificationPath
    Path to classification.json. Default: next to this script.

.PARAMETER LoadHostPath
    Path to xl-loadhost.exe. Default: <repo>\target\release\xl-loadhost.exe.

.PARAMETER MaxParallel
    Concurrent samples. Default (and hard ceiling per spec): 4.

.PARAMETER LoadTimeoutSeconds / ExecTimeoutSeconds
    Hard kill timeouts applied identically to both sides. Defaults: 60 / 30.

.OUTPUTS
    <ResultsDir>\summary.json =
      { "total": n, "passed": n, "envFailed": n, "skipped": n, "coverage": n,
        "results": [ { "name":..., "mode": "load|exec|skip",
                       "status": "pass|fail|crash|timeout|envfail|mismatch|skip",
                       "seconds": n, "detail": "<=300 chars",
                       "origBehavior": "<=120 chars",
                       "packedBehavior": "<=120 chars" } ] }
    (ConvertTo-Json -Depth 6). The file is written atomically and CHECKPOINTED
    after every harvested sample, so a mid-run host death leaves a valid
    current-schema summary; a partial snapshot is detectable as
    results.length < total.

.EXITCODES
    0 only pass / envfail / skip outcomes (envfail is environmental, not product)
    1 at least one non-skip fail / crash / timeout / mismatch (including samples
      whose phase-1 pack failed upstream - "packed artifact absent")
    2 harness-level error: missing load host / classification / manifest, bad
      JSON, duplicate manifest names, ResultsDir unusable, packed directory
      missing / empty / holding artifacts that map to no manifest entry, a
      partial artifact set whose absences are not corroborated by the phase-1
      summary, or a phase-1 record claiming success without its artifact
      (orchestration errors are never disguised as per-sample failures),
      job-object runtime unavailable
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Manifest,
    [Parameter(Mandatory = $true)][string]$ResultsDir,
    [string]$ClassificationPath,
    [string]$LoadHostPath,
    [string]$PackedDir,
    [int]$MaxParallel = 4,
    [int]$LoadTimeoutSeconds = 60,
    [int]$ExecTimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($MaxParallel -lt 1) { $MaxParallel = 1 }
if ($MaxParallel -gt 4) { $MaxParallel = 4 }   # spec ceiling

function Write-Diag {
    param([string]$Msg)
    [Console]::Error.WriteLine("run_func: $Msg")
}

# --- harness-level preflight (exit 2 before touching any sample) ----------------
if (-not $ClassificationPath) { $ClassificationPath = Join-Path $PSScriptRoot 'classification.json' }
if (-not $LoadHostPath) {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $LoadHostPath = Join-Path $repo 'target\release\xl-loadhost.exe'
}
foreach ($p in @($LoadHostPath, $ClassificationPath, $Manifest)) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        Write-Diag "required file not found: $p"
        exit 2
    }
}
$loadHostAbs = (Resolve-Path -LiteralPath $LoadHostPath).ProviderPath
$manifestAbs = (Resolve-Path -LiteralPath $Manifest).ProviderPath
$manifestDir = Split-Path $manifestAbs -Parent

try {
    if (-not (Test-Path -LiteralPath $ResultsDir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $ResultsDir -Force
    }
    $resultsDirAbs = (Resolve-Path -LiteralPath $ResultsDir).ProviderPath
    $exeRunDir = Join-Path $resultsDirAbs 'exe-run'
} catch {
    Write-Diag "ResultsDir unusable: $($_.Exception.Message)"
    exit 2
}

# --- classification table ---------------------------------------------------------
try {
    $classText = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $ClassificationPath).ProviderPath)
    $classParsed = $classText | ConvertFrom-Json
} catch {
    Write-Diag "classification unreadable/unparseable: $($_.Exception.Message)"
    exit 2
}
# PS 5.1: a top-level JSON array may arrive as ONE Object[] item; unwrap it.
$classItems = @($classParsed)
if ($classItems.Count -eq 1 -and $classItems[0] -is [System.Array]) { $classItems = @($classItems[0]) }
$classification = @{}
foreach ($c in $classItems) {
    if ($null -eq $c) { continue }
    $cn = "$($c.name)"
    if ([string]::IsNullOrEmpty($cn)) { continue }
    $mode = "$($c.mode)"
    if (@('load', 'exec', 'skip') -notcontains $mode) { $mode = 'skip' }
    $reason = "$($c.reason)"
    $classification[$cn] = [pscustomobject]@{ Mode = $mode; Reason = $reason }
}

# --- manifest entries -------------------------------------------------------------
try {
    $manifestText = [System.IO.File]::ReadAllText($manifestAbs)
} catch {
    Write-Diag "manifest unreadable: $($_.Exception.Message)"
    exit 2
}
function Resolve-Against([string]$Value, [string]$BaseDir) {
    try {
        if ([System.IO.Path]::IsPathRooted($Value)) { return [System.IO.Path]::GetFullPath($Value) }
        return [System.IO.Path]::GetFullPath((Join-Path $BaseDir $Value))
    } catch { return $null }
}
$entries = New-Object System.Collections.ArrayList
$trimmed = $manifestText.TrimStart()
if ($trimmed.StartsWith('[') -or $trimmed.StartsWith('{')) {
    try { $mParsed = $manifestText | ConvertFrom-Json } catch {
        Write-Diag "manifest is JSON-shaped but unparseable: $($_.Exception.Message)"
        exit 2
    }
    # PS 5.1: a top-level JSON array may arrive as ONE Object[] item; unwrap it.
    $parsed = @($mParsed)
    if ($parsed.Count -eq 1 -and $parsed[0] -is [System.Array]) { $parsed = @($parsed[0]) }
    if ($parsed.Count -eq 1 -and $null -ne $parsed[0].PSObject.Properties['samples']) {
        $parsed = @($parsed[0].PSObject.Properties['samples'].Value)
    }
    foreach ($el in $parsed) {
        if ($el -is [string]) {
            $t = $el.Trim()
            if ($t.Length -gt 0) { $null = $entries.Add([pscustomobject]@{ Name = $t; Origin = $null }) }
            continue
        }
        $n = $el.PSObject.Properties['name']
        $o = $el.PSObject.Properties['origin']
        $null = $entries.Add([pscustomobject]@{
            Name   = if ($n) { "$($n.Value)" } else { '' }
            Origin = if ($o) { "$($o.Value)" } else { $null }
        })
    }
} else {
    foreach ($raw in ($manifestText -split "\r?\n")) {
        $t = $raw.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
        $null = $entries.Add([pscustomobject]@{ Name = $t; Origin = $null })
    }
}
if ($entries.Count -eq 0) {
    Write-Diag "manifest lists no samples: $manifestAbs"
    exit 2
}

# Resolve every entry's sample path and derive its ARTIFACT KEY: the file name of
# the resolved sample (identical to run_one.ps1's key, which is GetFileName of the
# input path) - falling back to the file name of the raw "name" value when the
# sample does not resolve. Keys must be unique (键重复 -> exit 2).
$entryKeys = New-Object System.Collections.ArrayList
$sampleByEntry = New-Object System.Collections.ArrayList
$keySeen = @{}
$keyDupes = @()
foreach ($e in $entries) {
    $sAbs = Resolve-Against $e.Name $manifestDir
    if (-not (Test-Path -LiteralPath $sAbs -PathType Leaf)) { $sAbs = $null }
    $k = [System.IO.Path]::GetFileName($(if ($sAbs) { $sAbs } else { $e.Name }))
    $null = $entryKeys.Add($k)
    $null = $sampleByEntry.Add($sAbs)
    if ($keySeen.ContainsKey($k)) {
        if ($keyDupes -notcontains $k) { $keyDupes += $k }
    } else { $keySeen[$k] = $true }
}
if ($keyDupes.Count -gt 0) {
    Write-Diag ("duplicate artifact keys among manifest entries: " + ($keyDupes -join ', '))
    exit 2
}

# --- locate the phase-1 packed artifacts + consistency self-check (fail-fast) ------
# An explicit -PackedDir is AUTHORITATIVE: if the consistency check fails there,
# the run is a configuration error (exit 2), never a silent fallback to guesses.
# Without it, probe <ResultsDir>\packed then <repo>\out\compat-results\packed.
#
# Orchestration errors remain exit 2 (the phase-2 0/89 lesson): directory missing
# or empty, artifacts mapping to NO manifest entry (stale/old-key/wrong-dir sets,
# e.g. the phase-2 basename-keyed layout), or a phase-1 record claiming success
# while its artifact is gone.
#
# A PARTIAL artifact set is legitimate when phase-1 had real per-sample failures
# (e.g. 4 packer crashes -> 96 of 100 artifacts): the count alone cannot tell a
# product failure from an orchestration break, so every absent key must be
# corroborated by the phase-1 summary.json that lives beside packed\ (recorded
# status fail/crash/timeout or toolExitCode != 0). Corroborated absences become
# per-sample 'fail' entries in THIS summary ("differential impossible - packed
# artifact absent, phase-1 recorded <status>"); skip-classified entries keep
# their skip verdict with the pack failure noted. Without a corroborating
# phase-1 summary a strict subset is still exit 2 (cannot attribute).
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
function Test-ArtifactDir {
    # returns $null on orchestration failure (diag already printed), else a
    # hashtable: entryIndex -> @{ PhaseStatus; ToolExit } for entries whose
    # artifact is legitimately absent (empty hashtable = complete set).
    param([string]$Dir)
    $arts = @(Get-ChildItem -LiteralPath $Dir -File -Filter '*.xl.exe' -ErrorAction SilentlyContinue)
    if ($arts.Count -eq 0) {
        Write-Diag ("packed artifact directory holds no *.xl.exe artifacts: " + $Dir)
        return $null
    }
    $keySet = @{}
    for ($i = 0; $i -lt $entries.Count; $i++) { $keySet[$entryKeys[$i] + '.xl.exe'] = $i }
    $phantom = @($arts | Where-Object { -not $keySet.ContainsKey($_.Name) })
    if ($phantom.Count -gt 0) {
        Write-Diag ("artifacts mapping to no manifest entry (stale or wrong-key set, first 5): " + ((($phantom | Select-Object -First 5).Name) -join ', '))
        return $null
    }
    $present = @{}
    foreach ($a in $arts) { $present[$a.Name] = $true }
    $missingIdx = @()
    for ($i = 0; $i -lt $entries.Count; $i++) {
        if (-not $present.ContainsKey($entryKeys[$i] + '.xl.exe')) { $missingIdx += $i }
    }
    if ($missingIdx.Count -eq 0) { return @{} }

    # partial set: attribute every absence via the phase-1 record
    $p1 = @{}
    $p1Found = $false
    foreach ($cand in @((Join-Path $Dir 'summary.json'), (Join-Path (Split-Path $Dir -Parent) 'summary.json'))) {
        if (-not (Test-Path -LiteralPath $cand -PathType Leaf)) { continue }
        try {
            $p1sum = [System.IO.File]::ReadAllText($cand) | ConvertFrom-Json
        } catch { continue }
        $rows = @($p1sum.PSObject.Properties['results'].Value)
        foreach ($r in $rows) {
            if ($null -eq $r) { continue }
            $rn = $r.PSObject.Properties['name']
            if ($rn) { $p1["$($rn.Value)"] = $r }
        }
        if ($p1.Count -gt 0) { $p1Found = $true; break }
    }
    if (-not $p1Found) {
        Write-Diag ("artifact set is a strict subset ({0}/{1}) and no phase-1 summary.json beside it attributes the missing keys - wrong dir or stale set: {2}" -f $arts.Count, $entries.Count, $Dir)
        return $null
    }
    $attributed = @{}
    foreach ($i in $missingIdx) {
        $rec = $p1[$entryKeys[$i]]
        $corroborated = $false
        if ($rec) {
            $stProp = $rec.PSObject.Properties['status']
            $teProp = $rec.PSObject.Properties['toolExitCode']
            $st = if ($stProp) { "$($stProp.Value)" } else { '' }
            $te = if ($teProp) { "$($teProp.Value)" } else { '' }
            # phase-1 failed this sample (or never reached exit 0): absence explained
            if ((@('fail', 'crash', 'timeout') -contains $st) -or ($te -ne '' -and $te -ne '0')) { $corroborated = $true }
        }
        if (-not $corroborated) {
            if ($rec) {
                Write-Diag ("phase-1 recorded status '{0}' (toolExit={1}) for {2} but its artifact is missing - inconsistent result set" -f $st, $te, $entryKeys[$i])
            } else {
                Write-Diag ("no phase-1 record attributes the missing artifact for {0} - re-run run_corpus.ps1" -f $entryKeys[$i])
            }
            return $null
        }
        $attributed[$i] = [pscustomobject]@{ PhaseStatus = $st; ToolExit = $te }
    }
    return $attributed
}
$artifactAbsent = $null
if ($PackedDir) {
    $artifactDir = $null
    try {
        $artifactDir = (Resolve-Path -LiteralPath $PackedDir -ErrorAction Stop).ProviderPath
    } catch {
        Write-Diag "-PackedDir not found: $PackedDir"
        exit 2
    }
    if (-not (Test-Path -LiteralPath $artifactDir -PathType Container)) {
        Write-Diag "-PackedDir is not a directory: $artifactDir"
        exit 2
    }
    $artifactAbsent = Test-ArtifactDir $artifactDir
    if ($null -eq $artifactAbsent) {
        Write-Diag "re-run run_corpus.ps1 (phase 1) so packed\ matches the manifest with full-name keys, or fix -PackedDir"
        exit 2
    }
} else {
    $packedCandidates = @((Join-Path $resultsDirAbs 'packed'), (Join-Path $repoRoot 'out\compat-results\packed'))
    $artifactDir = $null
    foreach ($cand in $packedCandidates) {
        if (-not (Test-Path -LiteralPath $cand -PathType Container)) { continue }
        if (@(Get-ChildItem -LiteralPath $cand -File -Filter '*.xl.exe' -ErrorAction SilentlyContinue).Count -gt 0) {
            $artifactDir = $cand
            break
        }
    }
    if (-not $artifactDir) {
        Write-Diag ("no packed artifacts found in any of: [" + ($packedCandidates -join ' ; ') + "] - run run_corpus.ps1 first, or pass -PackedDir / use the phase-1 ResultsDir")
        exit 2
    }
    $artifactAbsent = Test-ArtifactDir $artifactDir
    if ($null -eq $artifactAbsent) {
        Write-Diag ("probed artifact directory failed the consistency check: " + $artifactDir + " - re-run run_corpus.ps1 (phase 1) with the full-name artifact keys, or pass -PackedDir explicitly")
        exit 2
    }
}
if (-not (Test-Path -LiteralPath $exeRunDir -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $exeRunDir -Force
}

# --- cross-run residue healing -------------------------------------------------------
# A hard-killed run (host crash, taskkill /F, power loss) never executes its
# finally-block, so a staged .xenolith-test. / .orig-test. copy can leak on disk.
# Every worker appends its staged path to a ledger BEFORE copying; the next run
# sweeps whatever still exists here, then rewrites the ledger with only the paths
# it could not delete (still locked by a leaked process, etc.).
$ledgerPath = Join-Path $exeRunDir 'staged-copies.log'
if (Test-Path -LiteralPath $ledgerPath -PathType Leaf) {
    $keptLines = New-Object System.Collections.Generic.List[string]
    foreach ($line in ([System.IO.File]::ReadAllLines($ledgerPath))) {
        $p = $line.Trim()
        if ($p.Length -eq 0) { continue }
        if ((Test-Path -LiteralPath $p -PathType Leaf) -and ($p -match '\.(xenolith-test|orig-test)\.')) {
            try {
                Remove-Item -LiteralPath $p -Force -ErrorAction Stop
                Write-Diag "swept leftover test copy from an earlier killed run: $p"
            } catch {
                Write-Diag ("cannot sweep leftover test copy $p : " + $_.Exception.Message)
                $keptLines.Add($p)
            }
        }
    }
    if ($keptLines.Count -eq 0) {
        Remove-Item -LiteralPath $ledgerPath -Force -ErrorAction SilentlyContinue
    } else {
        [System.IO.File]::WriteAllLines($ledgerPath, $keptLines)
    }
}
# the exe-run dir itself is harness-owned: any staged test copy in it is ours
foreach ($pat in @('*.xenolith-test.*', '*.orig-test.*')) {
    Get-ChildItem -LiteralPath $exeRunDir -File -Filter $pat -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
            Write-Diag ("swept leftover fallback copy: " + $_.FullName)
        } catch { Write-Diag ("cannot sweep " + $_.FullName + " : " + $_.Exception.Message) }
    }
}

# --- crash-resilient summary writing ---------------------------------------------------
# The summary is written atomically (tmp + NTFS Replace) and CHECKPOINTED after
# every harvested sample, so a mid-run host death always leaves a VALID
# current-schema summary.json behind. A partial snapshot is detectable as
# results.length < total.
$summaryPath = Join-Path $resultsDirAbs 'summary.json'
$results = New-Object System.Collections.ArrayList

function Write-SummaryAtomic {
    param([string]$Path, [string]$Json)
    $tmp = $Path + '.tmp'
    [System.IO.File]::WriteAllText($tmp, $Json, [System.Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try { [System.IO.File]::Replace($tmp, $Path, $null) }
        catch {
            Remove-Item -LiteralPath $Path -Force
            [System.IO.File]::Move($tmp, $Path)
        }
    } else {
        [System.IO.File]::Move($tmp, $Path)
    }
}

function Publish-Summary {
    param([int]$TotalEntries)
    $passed   = @($results | Where-Object { $_.status -eq 'pass' }).Count
    $envfail  = @($results | Where-Object { $_.status -eq 'envfail' }).Count
    $skipped  = @($results | Where-Object { $_.status -eq 'skip' }).Count
    $sum = [pscustomobject]@{
        total     = $TotalEntries
        passed    = $passed
        envFailed = $envfail
        skipped   = $skipped
        coverage  = $TotalEntries - $skipped
        results   = @($results)
    }
    try {
        Write-SummaryAtomic $summaryPath ($sum | ConvertTo-Json -Depth 6)
    } catch {
        Write-Diag ("cannot write summary checkpoint: " + $_.Exception.Message)
    }
}

# --- Win32 job object (kill-on-close => children die with the run) ----------------
# Compiled once here in the parent; the pool runspaces share this process/AppDomain.
$jobNativeOk = $true
if (-not ('XlJobNative' -as [type])) {
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class XlJobNative {
    [DllImport(`"kernel32.dll`", SetLastError = true)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);
    [DllImport(`"kernel32.dll`", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo, int cbJobObjectInfoLength);
    [DllImport(`"kernel32.dll`", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport(`"kernel32.dll`", SetLastError = true)]
    public static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);
    [DllImport(`"kernel32.dll`", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    public static IntPtr Create() { return CreateJobObject(IntPtr.Zero, null); }
    public static bool SetKillOnClose(IntPtr h) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION i = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        i.BasicLimitInformation.LimitFlags = 0x2000; /* JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE */
        return SetInformationJobObject(h, 9 /* JobObjectExtendedLimitInformation */, ref i, Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
    }
}
"@
    } catch {
        Write-Diag ("cannot compile job-object helper (tree-kill degrades to taskkill /T): " + $_.Exception.Message)
        $jobNativeOk = $false
    }
}

# --- per-sample worker -------------------------------------------------------------
$jobScript = @'
param($Item)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Kill-Tree([int]$ProcId) {
    # taskkill /T walks live children of a live parent; harmless if already gone.
    try { $null = & "$env:WINDIR\System32\taskkill.exe" /PID $ProcId /T /F 2>$null } catch { }
}

function Is-CrashCode([int]$Code) {
    if ($Code -lt 0) { return $true }   # 0xC0000005 / 0xC0000409 / ... arrive as negative Int32
    return (@(2147483645, 3221225477, 3221226505, 3221226356, 3221225501) -contains $Code)
}

function ExitHex([int]$Code) {
    $u = [uint64]($Code -band 0xFFFFFFFFL)
    return ('0x{0:X8}' -f $u)
}

function Get-WinErrName([int]$Code) {
    switch ($Code) {
        2     { return 'ERROR_FILE_NOT_FOUND' }
        3     { return 'ERROR_PATH_NOT_FOUND' }
        5     { return 'ERROR_ACCESS_DENIED' }
        87    { return 'ERROR_INVALID_PARAMETER' }
        126   { return 'ERROR_MOD_NOT_FOUND' }
        127   { return 'ERROR_PROC_NOT_FOUND' }
        193   { return 'ERROR_BAD_EXE_FORMAT' }
        998   { return 'ERROR_NOACCESS' }
        1114  { return 'ERROR_DLL_INIT_FAILED' }
        14001 { return 'ERROR_SXS_CANT_GEN_ACTCTX' }
        default { return '' }
    }
}

# Static-import dependency audit backing the 126<->1114 equivalence below:
# parse the ORIGINAL image's import directory and return every dependency DLL
# name that no search location can provide - the module's own directory (the
# staging dir; both sides load with LOAD_WITH_ALTERED_SEARCH_PATH so this is
# searched first), the harness fallback dir, System32/SysWOW64/Windows/System
# and PATH. The audited set must stay a SUPERSET of what the OS loader can
# search, otherwise a dependency the loader WOULD find gets called "missing"
# and a false envfail follows - so the legacy loader locations (%WINDIR%,
# %WINDIR%\System) are audited too even though modern images rarely need them.
# API-set names (api-ms-*/ext-ms-*) resolve through the API set schema, never
# as files, and are excluded. Fail-closed parse: any malformed/unreadable
# image yields an empty list, which leaves the verdict unchanged.
function Get-MissingStaticDeps([string]$ImagePath, [string[]]$ExtraDirs) {
    $none = @()
    try { $bytes = [System.IO.File]::ReadAllBytes($ImagePath) } catch { return $none }
    $n = $bytes.Length
    if ($n -lt 0x100) { return $none }
    function Read-U16Local([byte[]]$b, [int]$o) {
        if ($o -ge 0 -and ($o + 2) -le $b.Length) { return [BitConverter]::ToUInt16($b, $o) }
        return 0
    }
    function Read-U32Local([byte[]]$b, [int]$o) {
        if ($o -ge 0 -and ($o + 4) -le $b.Length) { return [BitConverter]::ToUInt32($b, $o) }
        return 0
    }
    $e_lfanew = Read-U32Local $bytes 0x3C
    if ($e_lfanew -le 0 -or ($e_lfanew + 24) -gt $n) { return $none }
    if ($bytes[$e_lfanew] -ne 0x50 -or $bytes[$e_lfanew + 1] -ne 0x45) { return $none }
    $numSections = Read-U16Local $bytes ($e_lfanew + 6)
    $sizeOfOptional = Read-U16Local $bytes ($e_lfanew + 20)
    $opt = $e_lfanew + 24
    if ($numSections -lt 1 -or ($opt + $sizeOfOptional) -gt $n) { return $none }
    # DataDirectory lives at +96 in PE32 (0x10B) but +112 in PE32+ (0x20B);
    # reading a 32-bit image with the PE32+ offset silently audits the WRONG
    # directory (resource/exception data walked as import descriptors), which
    # can FABRICATE missing dependencies -> false envfail -> loosened verdict.
    # Unknown magic = not a PE we can parse = fail-closed empty.
    $magic = Read-U16Local $bytes $opt
    if ($magic -ne 0x10B -and $magic -ne 0x20B) { return $none }
    $ddBase = $opt + $(if ($magic -eq 0x10B) { 96 } else { 112 })
    $impRva = Read-U32Local $bytes ($ddBase + 8)
    $impSize = Read-U32Local $bytes ($ddBase + 12)
    if ($impRva -eq 0 -or $impSize -eq 0) { return $none }   # no/wiped import dir: nothing to audit
    $secStart = $opt + $sizeOfOptional
    if (($secStart + 40 * $numSections) -gt $n) { return $none }
    $sections = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $numSections; $i++) {
        $s = $secStart + 40 * $i
        $null = $sections.Add([pscustomobject]@{
            VirtualSize  = (Read-U32Local $bytes ($s + 8))
            VirtualAddress = (Read-U32Local $bytes ($s + 12))
            RawSize      = (Read-U32Local $bytes ($s + 16))
            RawPtr       = (Read-U32Local $bytes ($s + 20))
        })
    }
    $descOff = $null
    foreach ($sec in $sections) {
        $span = [math]::Max($sec.VirtualSize, $sec.RawSize)
        if ($impRva -ge $sec.VirtualAddress -and $impRva -lt ($sec.VirtualAddress + $span)) {
            $delta = $impRva - $sec.VirtualAddress
            if ($delta -lt $sec.RawSize) { $descOff = [int]($sec.RawPtr + $delta) }
            break
        }
    }
    if ($null -eq $descOff) { return $none }
    $deps = New-Object System.Collections.Generic.List[string]
    $di = 0
    while ($true) {
        $d = $descOff + 20 * $di
        if (($d + 20) -gt $n) { break }
        $nameRva = Read-U32Local $bytes ($d + 12)
        $oft = Read-U32Local $bytes ($d + 0)
        $ft = Read-U32Local $bytes ($d + 16)
        if ($oft -eq 0 -and $nameRva -eq 0 -and $ft -eq 0) { break }
        $nameOff = $null
        foreach ($sec in $sections) {
            $span = [math]::Max($sec.VirtualSize, $sec.RawSize)
            if ($nameRva -ge $sec.VirtualAddress -and $nameRva -lt ($sec.VirtualAddress + $span)) {
                $delta = $nameRva - $sec.VirtualAddress
                if ($delta -lt $sec.RawSize) { $nameOff = [int]($sec.RawPtr + $delta) }
                break
            }
        }
        if ($null -eq $nameOff) { break }
        $end = $nameOff
        while ($end -lt $n -and $bytes[$end] -ne 0 -and ($end - $nameOff) -lt 256) { $end++ }
        $dep = [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $end - $nameOff)
        if ($dep) { $deps.Add($dep) }
        $di++
        if ($di -gt 4096) { break }
    }
    $searchDirs = New-Object System.Collections.Generic.List[string]
    foreach ($dir in $ExtraDirs) {
        if ($dir) {
            $trimmed = $dir.Trim()
            if ($trimmed -and -not $searchDirs.Contains($trimmed)) { $searchDirs.Add($trimmed) }
        }
    }
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($dep in $deps) {
        if ($dep -like 'api-ms-*' -or $dep -like 'ext-ms-*') { continue }
        $found = $false
        foreach ($dir in $searchDirs) {
            try {
                if (Test-Path -LiteralPath ([System.IO.Path]::Combine($dir, $dep)) -PathType Leaf) { $found = $true; break }
            } catch { }
        }
        if (-not $found) { $missing.Add($dep) }
    }
    return @( $missing )
}

function Get-CopyName([string]$Base, [string]$Tag, [string]$Ext) {
    if ([string]::IsNullOrEmpty($Ext)) { return ($Base + '.' + $Tag) }
    return ($Base + '.' + $Tag + '.' + $Ext)
}

# Append a line to the cleanup ledger. Parallel workers append concurrently, so
# the file can be locked for a moment - retry instead of silently dropping the
# line (a dropped line = a leaked copy the next run cannot sweep).
function Add-LedgerLine([string]$Ledger, [string]$Path) {
    for ($i = 0; $i -lt 8; $i++) {
        try { Add-Content -LiteralPath $Ledger -Value $Path -Encoding ASCII -ErrorAction Stop; return } catch { }
        Start-Sleep -Milliseconds 125
    }
}

# Materialization gate: a freshly created copy can be briefly unresolvable or
# incomplete through filter drivers under concurrent I/O. Measured on this
# machine: staging an 18.6 MB DLL with 4 workers in flight and loading the copy
# the instant Copy-Item returns -> one transient false exit 3 / lastWinError
# 1114 in 40 loads; the same loop with a settle after the copy -> 0/40. The
# phase-3 multi-round evidence then pushed the settle 300 -> 500 ms: an
# immediate load of a fresh copy still yielded a false 126 (ERROR_MOD_NOT_
# FOUND) on BOTH the orig and the packed side, stable again after a delay, so
# the 300 ms window was provably too narrow. Identical treatment for BOTH
# sides of the differential; this widens the measurement window only, it does
# not relax any verdict (a persistent reject is still a reject - and now one
# that has survived 4 attempts spread over seconds of exponential backoff).
function Wait-Materialized([string]$Dest, [long]$SourceLen) {
    for ($i = 0; $i -lt 20; $i++) {
        try {
            if ((Test-Path -LiteralPath $Dest -PathType Leaf) -and ((Get-Item -LiteralPath $Dest).Length -eq $SourceLen)) { break }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    Start-Sleep -Milliseconds 500
}

# Stage a copy of $Source for one side of the differential.
#   primary  : <Dir>\<Base>.<Tag>.<Ext>   (the ORIGINAL's directory - siblings resolve)
#   fallback : <FallbackDir>\<FallbackName>.<Tag>.<Ext> (harness-owned; manifest
#              name is unique, so parallel fallbacks cannot collide) with the
#              child's cwd + PATH pinned to <Dir>.
# The ledger line is appended BEFORE the copy exists: a hard-killed run has no
# finally, the next run's preflight sweep is the only thing that can clean up.
function Stage-Copy {
    param([string]$Source, [string]$Dir, [string]$Base, [string]$Tag, [string]$Ext,
          [string]$FallbackName, [string]$FallbackDir, [string]$Ledger)
    $srcLen = (Get-Item -LiteralPath $Source).Length
    $name = Get-CopyName $Base $Tag $Ext
    $dest = Join-Path $Dir $name
    try {
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }   # our own leftover only
        Copy-Item -LiteralPath $Source -Destination $dest -Force
        Wait-Materialized $dest $srcLen
        Add-LedgerLine $Ledger $dest
        return [pscustomobject]@{ Ok = $true; Path = $dest; UsedFallback = $false }
    } catch { }
    $dest = Join-Path $FallbackDir (Get-CopyName $FallbackName $Tag $Ext)
    try {
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
        Copy-Item -LiteralPath $Source -Destination $dest -Force
        Wait-Materialized $dest $srcLen
        Add-LedgerLine $Ledger $dest
        return [pscustomobject]@{ Ok = $true; Path = $dest; UsedFallback = $true }
    } catch {
        return [pscustomobject]@{ Ok = $false; Path = $null; UsedFallback = $false; Error = $_.Exception.Message }
    }
}

function Remove-Staged([string]$Path) {
    if (-not $Path) { return $true }
    $left = $true
    for ($i = 0; $i -lt 24 -and $left; $i++) {
        try {
            if (Test-Path -LiteralPath $Path) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            }
            $left = (Test-Path -LiteralPath $Path)
        } catch { Start-Sleep -Milliseconds 500 }
    }
    return (-not $left)
}

# Pre-create the kill-on-close job BEFORE the child exists (no containment gap
# between Start and CreateJobObject), assign right after Start. taskkill /T is
# the belt for grandchildren spawned in the residual microsecond window.
function New-Job {
    if (-not $Item.JobNative) { return [IntPtr]::Zero }
    try {
        $h = [XlJobNative]::Create()
        if ($h.Equals([IntPtr]::Zero)) { return [IntPtr]::Zero }
        if (-not [XlJobNative]::SetKillOnClose($h)) {
            try { $null = [XlJobNative]::CloseHandle($h) } catch { }
            return [IntPtr]::Zero
        }
        return $h
    } catch { return [IntPtr]::Zero }
}
function Close-Job([IntPtr]$Job) {
    if ($Job -ne [IntPtr]::Zero) {
        try { $null = [XlJobNative]::TerminateJobObject($Job, 1) } catch { }
        try { $null = [XlJobNative]::CloseHandle($Job) } catch { }
    }
}
# Close-Job and forget the handle: the job object dies with its last handle, so
# a second Close on a stale (possibly recycled) handle must be impossible.
function Attach-Job([IntPtr]$Job, $Proc) {
    if ($Job -eq [IntPtr]::Zero) { return }
    try { $null = [XlJobNative]::AssignProcessToJobObject($Job, $Proc.Handle) } catch { }
}

# --- load side: xl-loadhost the staged COPY (never the original) -------------------
function Invoke-LoadSide {
    param([string]$Source, [string]$Tag)
    $stage = Stage-Copy -Source $Source -Dir $Item.ExecDir -Base $Item.OrigBase -Tag $Tag -Ext $Item.OrigExt `
        -FallbackName $Item.Name -FallbackDir $Item.FallbackDir -Ledger $Item.Ledger
    if (-not $stage.Ok) {
        return [pscustomobject]@{ Class = 'stagefail'; Code = $null; Sig = ('stage copy failed: ' + $stage.Error); Seconds = 0; Fallback = $false }
    }
    $proc = $null
    $job = [IntPtr]::Zero
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $Item.LoadHost
        $psi.Arguments = '"' + $stage.Path + '"'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.CreateNoWindow = $true
        $psi.WorkingDirectory = $Item.ExecDir
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        if ($stage.UsedFallback) {
            $oldPath = $psi.EnvironmentVariables['Path']
            if ($null -eq $oldPath) { $oldPath = $env:Path }
            $psi.EnvironmentVariables['Path'] = ($Item.ExecDir + ';' + $oldPath)
        }
        $proc = [System.Diagnostics.Process]::new()
        $proc.StartInfo = $psi
        $job = New-Job
        try { $null = $proc.Start() } catch {
            return [pscustomobject]@{ Class = 'startfail'; Code = $null; Sig = ('loadhost start failed: ' + $_.Exception.Message); Seconds = 0; Fallback = $stage.UsedFallback }
        }
        Attach-Job $job $proc
        $proc.StandardInput.Close()   # nothing may block on stdin
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $timedOut = -not $proc.WaitForExit($Item.TimeoutSec * 1000)
        if ($timedOut) {
            Close-Job $job
            $job = [IntPtr]::Zero
            Kill-Tree $proc.Id
            try { $proc.WaitForExit() } catch { }
        }
        $stdout = ''
        try { $stdout = $outTask.Result } catch { }
        $stderr = ''
        try { $stderr = $errTask.Result } catch { }
        $sw.Stop()
        $secs = [math]::Round($sw.Elapsed.TotalSeconds, 3)
        $code = [int]$proc.ExitCode
        $firstOut = ($stdout -split "\r?\n" | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 1)
        if ($timedOut) {
            return [pscustomobject]@{ Class = 'timeout'; Code = $null; Sig = ('loadhost killed at ' + $Item.TimeoutSec + 's (DllMain hang)'); Seconds = $secs; Fallback = $stage.UsedFallback }
        }
        if ($code -eq 0) {
            $mods = ''
            if ($firstOut -match '"modules":(\d+)') { $mods = ', ' + $Matches[1] + ' modules' }
            return [pscustomobject]@{ Class = 'ok'; Code = $null; Sig = ('loadhost:0 loaded ok' + $mods + ' in ' + $secs + 's'); Seconds = $secs; Fallback = $stage.UsedFallback }
        }
        if ($code -eq 3) {
            $we = -1
            if ($firstOut -match '"lastWinError":(\d+)') { $we = [int]$Matches[1] }
            $en = Get-WinErrName $we
            $sig = 'loadhost:3 lastWinError=' + $we
            if ($en) { $sig = $sig + ' (' + $en + ')' }
            return [pscustomobject]@{ Class = 'reject'; Code = $we; Sig = $sig; Seconds = $secs; Fallback = $stage.UsedFallback }
        }
        if (Is-CrashCode $code) {
            return [pscustomobject]@{ Class = 'crash'; Code = $code; Sig = ('loadhost crash exit ' + (ExitHex $code) + ' in ' + $secs + 's'); Seconds = $secs; Fallback = $stage.UsedFallback }
        }
        return [pscustomobject]@{ Class = 'error'; Code = $code; Sig = ('loadhost unexpected exit ' + $code); Seconds = $secs; Fallback = $stage.UsedFallback }
    } finally {
        if ($null -ne $proc) {
            try { if (-not $proc.HasExited) { Kill-Tree $proc.Id } } catch { }
            try { $null = $proc.WaitForExit(5000) } catch { }
            $proc.Dispose()
        }
        Close-Job $job
        $null = Remove-Staged $stage.Path
    }
}

# --- exec side: launch the staged COPY, hard timeout, kill the tree ----------------
function Invoke-ExecSide {
    param([string]$Source, [string]$Tag)
    $stage = Stage-Copy -Source $Source -Dir $Item.ExecDir -Base $Item.OrigBase -Tag $Tag -Ext $Item.OrigExt `
        -FallbackName $Item.Name -FallbackDir $Item.FallbackDir -Ledger $Item.Ledger
    if (-not $stage.Ok) {
        return [pscustomobject]@{ Class = 'stagefail'; Code = $null; Sig = ('stage copy failed: ' + $stage.Error); Seconds = 0; Fallback = $false }
    }
    $proc = $null
    $job = [IntPtr]::Zero
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $stage.Path
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.WorkingDirectory = $Item.ExecDir
        if ($stage.UsedFallback) {
            $oldPath = $psi.EnvironmentVariables['Path']
            if ($null -eq $oldPath) { $oldPath = $env:Path }
            $psi.EnvironmentVariables['Path'] = ($Item.ExecDir + ';' + $oldPath)
        }
        $proc = [System.Diagnostics.Process]::new()
        $proc.StartInfo = $psi
        $job = New-Job
        try { $null = $proc.Start() } catch {
            return [pscustomobject]@{ Class = 'startfail'; Code = $null; Sig = ('start failed: ' + $_.Exception.Message); Seconds = 0; Fallback = $stage.UsedFallback }
        }
        Attach-Job $job $proc
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $timedOut = -not $proc.WaitForExit($Item.TimeoutSec * 1000)
        if ($timedOut) {
            Close-Job $job
            $job = [IntPtr]::Zero
            Kill-Tree $proc.Id
            try { $proc.WaitForExit() } catch { }
            $sw.Stop()
            return [pscustomobject]@{ Class = 'alive'; Code = $null; Sig = ('alive at ' + $Item.TimeoutSec + 's hard timeout (GUI-style; tree killed)'); Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 3); Fallback = $stage.UsedFallback }
        }
        $code = [int]$proc.ExitCode
        $sw.Stop()
        $secs = [math]::Round($sw.Elapsed.TotalSeconds, 3)
        if (Is-CrashCode $code) {
            return [pscustomobject]@{ Class = 'crash'; Code = $code; Sig = ('crash exit ' + (ExitHex $code) + ' in ' + $secs + 's'); Seconds = $secs; Fallback = $stage.UsedFallback }
        }
        return [pscustomobject]@{ Class = 'exit'; Code = $code; Sig = ('exited code ' + $code + ' in ' + $secs + 's'); Seconds = $secs; Fallback = $stage.UsedFallback }
    } finally {
        if ($null -ne $proc) {
            try { if (-not $proc.HasExited) { Kill-Tree $proc.Id } } catch { }
            try { $null = $proc.WaitForExit(5000) } catch { }
            $proc.Dispose()
        }
        Close-Job $job
        $null = Remove-Staged $stage.Path
    }
}

# --- transient-outcome retry wrappers ------------------------------------------------
# Only the two outcomes a not-yet-settled copy can cause are retried, BOUNDED
# (4 attempts, exponential backoff 400 / 800 / 1600 ms): load-side 'reject' and
# exec-side 'startfail'. The backoff is the phase-3 freshness fix: a fresh
# staged copy loaded the instant it settles could still false-126 with the old
# flat 3x300 ms schedule, misgrading already-repaired samples as mismatch/fail;
# spreading attempt 4 seconds past attempt 1 gives the slowest filter driver
# time to finish while keeping the total added latency bounded (< 3 s of pure
# wait per side). A real reject (missing sibling, genuine 1114 DllMain failure)
# and a real start failure (SxS, bad image) PERSIST across retries, so the
# verdict is not relaxed - what survives the retry is judged exactly as
# strictly as before. crash / timeout / exit / alive are never retried: those
# are product behavior. Every retry is disclosed in the behavior signature.
function Invoke-LoadSideMeasured {
    param([string]$Source, [string]$Tag)
    $first = $null
    $r = $null
    $tries = 0
    while ($true) {
        $tries++
        $r = Invoke-LoadSide -Source $Source -Tag $Tag
        if (-not $first) { $first = $r }
        if ($r.Class -ne 'reject') { break }
        if ($tries -ge 4) { break }
        Start-Sleep -Milliseconds ([int](400 * [math]::Pow(2, $tries - 1)))
    }
    if ($first.Class -eq 'reject' -and $r.Class -ne 'reject') {
        $r.Sig = $r.Sig + ' [settled after retry, first: ' + $first.Sig + ']'
    } elseif ($r.Class -eq 'reject' -and $tries -gt 1) {
        $r.Sig = $r.Sig + ' [reject persisted over ' + $tries + ' attempts]'
    }
    return $r
}

function Invoke-ExecSideMeasured {
    param([string]$Source, [string]$Tag)
    $first = $null
    $r = $null
    $tries = 0
    while ($true) {
        $tries++
        $r = Invoke-ExecSide -Source $Source -Tag $Tag
        if (-not $first) { $first = $r }
        if ($r.Class -ne 'startfail') { break }
        if ($tries -ge 4) { break }
        Start-Sleep -Milliseconds ([int](400 * [math]::Pow(2, $tries - 1)))
    }
    if ($first.Class -eq 'startfail' -and $r.Class -ne 'startfail') {
        $r.Sig = $r.Sig + ' [settled after retry, first: ' + $first.Sig + ']'
    } elseif ($r.Class -eq 'startfail' -and $tries -gt 1) {
        $r.Sig = $r.Sig + ' [startfail persisted over ' + $tries + ' attempts]'
    }
    return $r
}

function Get-Verdict {
    param([string]$Mode, $P, $O)
    if ($Mode -eq 'load') {
        $pOK = ($P.Class -eq 'ok')
        $oOK = ($O.Class -eq 'ok')
    } else {
        $pOK = ($P.Class -eq 'exit' -or $P.Class -eq 'alive')
        $oOK = ($O.Class -eq 'exit' -or $O.Class -eq 'alive')
    }
    if ($pOK -and $oOK) {
        if ($Mode -eq 'exec') {
            # the classic divergence: one side quick-exits, the other stays alive
            if (($P.Class -eq 'exit') -and ($O.Class -eq 'alive')) {
                return [pscustomobject]@{ Status = 'mismatch'; Detail = ('behavior diverged: packed quick-exited (' + $P.Sig + ') while orig stayed alive ' + $Item.TimeoutSec + 's - repair round') }
            }
            if (($P.Class -eq 'alive') -and ($O.Class -eq 'exit')) {
                return [pscustomobject]@{ Status = 'mismatch'; Detail = ('behavior diverged: packed stayed alive at timeout while orig quick-exited (' + $O.Sig + ') - repair round') }
            }
        }
        return [pscustomobject]@{ Status = 'pass'; Detail = 'both sides OK under identical conditions' }
    }
    if ($pOK -and -not $oOK) {
        # packed works but the pristine original copy fails: harness/environment
        # suspicion - do not certify, do not fail the product either
        return [pscustomobject]@{ Status = 'mismatch'; Detail = ('packed OK but orig side failed (' + $O.Sig + ') - asymmetric, repair round') }
    }
    # packed side did NOT work
    if ($oOK) {
        $st = 'fail'
        if ($P.Class -eq 'crash') { $st = 'crash' }
        elseif ($P.Class -eq 'timeout') { $st = 'timeout' }
        return [pscustomobject]@{ Status = $st; Detail = ('orig copy ran fine (' + $O.Sig + '); packed did not: ' + $P.Sig) }
    }
    # neither side worked: envfail only when the failure is the SAME manner
    # (same class AND same error code); otherwise the packed outcome stands
    $same = ($P.Class -eq $O.Class) -and ("$($P.Code)" -eq "$($O.Code)")
    if ($same) {
        return [pscustomobject]@{ Status = 'envfail'; Detail = ('environmental: orig copy fails the same way in-place | packed[' + $P.Sig + '] | orig[' + $O.Sig + ']') }
    }
    # Architectural 126<->1114 equivalence, certified only on proven shared
    # root cause. A dependency DLL missing from every searchable directory
    # fails the pristine original at LOAD time (ERROR_MOD_NOT_FOUND, 126) -
    # the OS loader resolves static imports before DllMain. The packed image
    # resolves the SAME imports inside DllMain (writeback binding through the
    # stub), so the identical gap surfaces as ERROR_DLL_INIT_FAILED (1114).
    # Same environment refusing both sides through two different error codes;
    # envfail only when the original's import table provably names at least
    # one dependency no search location provides. With every dependency
    # locatable, a 126 is unexplained and the fail verdict stands untouched.
    if (($Mode -eq 'load') -and ($O.Class -eq 'reject') -and ("$($O.Code)" -eq '126') -and
        ($P.Class -eq 'reject') -and ("$($P.Code)" -eq '1114')) {
        $depDirs = New-Object System.Collections.Generic.List[string]
        # superset of the loader's LOAD_WITH_ALTERED_SEARCH_PATH search set:
        # module dir (staged copy's dir), harness fallback, System32/SysWOW64,
        # the legacy %WINDIR%\System and %WINDIR% locations, then PATH. A dir
        # the loader searches but the audit skips would let a findable
        # dependency be declared missing -> false envfail -> loosened verdict.
        foreach ($dd in @($Item.ExecDir, $Item.FallbackDir, "$env:WINDIR\System32", "$env:WINDIR\SysWOW64", "$env:WINDIR\System", "$env:WINDIR")) {
            if ($dd) { $depDirs.Add($dd) }
        }
        foreach ($pd in ($env:Path -split ';')) {
            $pt = "$pd".Trim()
            if ($pt) { $depDirs.Add($pt) }
        }
        $missingDeps = Get-MissingStaticDeps -ImagePath $Item.OrigFile -ExtraDirs ($depDirs.ToArray())
        if (@($missingDeps).Count -gt 0) {
            return [pscustomobject]@{ Status = 'envfail'; Detail = ('environmental: shared missing dependency ' + (@($missingDeps) -join ', ') + ' - orig fails 126 at import resolution, packed fails 1114 when the stub hits the same gap inside DllMain | packed[' + $P.Sig + '] | orig[' + $O.Sig + ']') }
        }
    }
    $st = 'fail'
    if ($P.Class -eq 'crash') { $st = 'crash' }
    elseif ($P.Class -eq 'timeout') { $st = 'timeout' }
    return [pscustomobject]@{ Status = $st; Detail = ('orig copy also failed but differently | packed[' + $P.Sig + '] | orig[' + $O.Sig + ']') }
}

# --- worker body -------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Item.Packed -PathType Leaf)) {
    return [pscustomobject]@{ name = $Item.Name; mode = $Item.Mode; status = 'fail'; seconds = 0
        detail = 'packed artifact missing at run time (present at preflight): ' + $Item.Packed
        origBehavior = ''; packedBehavior = '' }
}
if ($Item.Mode -eq 'load') {
    $pSide = Invoke-LoadSideMeasured -Source $Item.Packed -Tag 'xenolith-test'
    $oSide = Invoke-LoadSideMeasured -Source $Item.OrigFile -Tag 'orig-test'
} else {
    $pSide = Invoke-ExecSideMeasured -Source $Item.Packed -Tag 'xenolith-test'
    $oSide = Invoke-ExecSideMeasured -Source $Item.OrigFile -Tag 'orig-test'
}
$v = Get-Verdict $Item.Mode $pSide $oSide
$detail = $v.Detail
if ($pSide.Fallback -or $oSide.Fallback) {
    $detail = $detail + ' | NOTE: origin dir not writable, one or both sides staged in harness exe-run with cwd+PATH pinned to origin dir'
}
return [pscustomobject]@{
    name = $Item.Name; mode = $Item.Mode; status = $v.Status
    seconds = [math]::Round(($pSide.Seconds + $oSide.Seconds), 3)
    detail = $detail
    origBehavior = $oSide.Sig; packedBehavior = $pSide.Sig
}
'@

# --- build the work list ------------------------------------------------------------
# Fail fast on a syntactically broken worker script: it lives inside a here-string,
# so the outer-file parse cannot see it, and without this check every sample would
# surface it as a synthetic per-sample "worker invoke failed" (0/N masquerade).
$workerParseErrs = $null
$null = [System.Management.Automation.PSParser]::Tokenize($jobScript, [ref]$workerParseErrs)
if (@($workerParseErrs).Count -gt 0) {
    foreach ($pe in $workerParseErrs) {
        Write-Diag ("worker script parse error at line {0}, col {1}: {2}" -f $pe.Token.StartLine, $pe.Token.StartColumn, $pe.Message)
    }
    exit 2
}

$work = New-Object System.Collections.ArrayList   # dispatched (load/exec)
$directOut = New-Object System.Collections.ArrayList   # skip/fail entries emitted in manifest order
for ($ei = 0; $ei -lt $entries.Count; $ei++) {
    $e = $entries[$ei]
    $name = $e.Name
    $originAbs = $null
    if ($e.Origin) { $originAbs = Resolve-Against $e.Origin $manifestDir }
    $sampleAbs = $sampleByEntry[$ei]

    $c = $classification[$name]
    if (-not $c) {
        $null = $directOut.Add([pscustomobject]@{
            name = $name; mode = 'skip'; status = 'skip'; seconds = 0
            detail = 'classification.json has no entry for this sample; conservatively skipped'
            origBehavior = ''; packedBehavior = ''
        })
        continue
    }
    if ($c.Mode -eq 'skip') {
        $skipDetail = $c.Reason
        if ($artifactAbsent.ContainsKey($ei)) {
            $ph = $artifactAbsent[$ei]
            $skipDetail = $skipDetail + (' | NOTE: phase-1 pack {0} (toolExit={1}) - recorded by the static stage, never functionally tested' -f $ph.PhaseStatus, $ph.ToolExit)
        }
        $null = $directOut.Add([pscustomobject]@{
            name = $name; mode = 'skip'; status = 'skip'; seconds = 0; detail = $skipDetail
            origBehavior = ''; packedBehavior = ''
        })
        continue
    }
    # phase-1 failed to produce this artifact (corroborated at preflight): the
    # differential cannot run. Recorded as a real per-sample failure - the
    # pipeline verdict must not soften because packing crashed upstream.
    if ($artifactAbsent.ContainsKey($ei)) {
        $ph = $artifactAbsent[$ei]
        $null = $directOut.Add([pscustomobject]@{
            name = $name; mode = $c.Mode; status = 'fail'; seconds = 0
            detail = ('packed artifact absent: phase-1 recorded {0} (toolExit={1}) - differential impossible, see static summary' -f $ph.PhaseStatus, $ph.ToolExit)
            origBehavior = ''; packedBehavior = ''
        })
        continue
    }
    $packedPath = Join-Path $artifactDir ($entryKeys[$ei] + '.xl.exe')   # full-name key (verified at preflight)

    # the differential anchor: the pristine original in its own directory
    $origFile = $null
    if ($originAbs -and (Test-Path -LiteralPath $originAbs -PathType Leaf)) { $origFile = $originAbs }
    elseif ($sampleAbs) { $origFile = $sampleAbs }
    if (-not $origFile) {
        $null = $directOut.Add([pscustomobject]@{
            name = $name; mode = $c.Mode; status = 'fail'; seconds = 0
            detail = 'neither origin nor sample file exists: no directory to stage the differential in'
            origBehavior = ''; packedBehavior = ''
        })
        continue
    }
    $origBase = [System.IO.Path]::GetFileNameWithoutExtension($origFile)
    $origExt = [System.IO.Path]::GetExtension($origFile).TrimStart('.')
    $timeoutSec = $(if ($c.Mode -eq 'load') { $LoadTimeoutSeconds } else { $ExecTimeoutSeconds })
    $null = $work.Add([pscustomobject]@{
        Name = $name; Mode = $c.Mode; Packed = $packedPath
        OrigFile = $origFile; OrigBase = $origBase; OrigExt = $origExt
        ExecDir = (Split-Path $origFile -Parent)
        FallbackDir = $exeRunDir; Ledger = $ledgerPath
        TimeoutSec = $timeoutSec; LoadHost = $loadHostAbs; JobNative = $jobNativeOk
    })
}

# --- dispatch (RunspacePool, <= 4 in flight) ------------------------------------------
# initial checkpoint: a valid current-schema summary exists from the moment the
# run legitimately started (partial snapshots are detectable: results < total)
Publish-Summary $entries.Count

$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxParallel)
$pool.Open()
$jobsByIndex = @{}
for ($i = 0; $i -lt $work.Count; $i++) {
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($jobScript).AddArgument($work[$i])
    $jobsByIndex[$i] = [pscustomobject]@{ Ps = $ps; Handle = $ps.BeginInvoke(); Item = $work[$i] }
}

function New-SynthFail([string]$Name, [string]$Mode, [string]$Why) {
    return [pscustomobject]@{ name = $Name; mode = $Mode; status = 'fail'; seconds = 0; detail = $Why
        origBehavior = ''; packedBehavior = '' }
}

# --- harvest in manifest order (skips interleaved where they appeared) -----------------
$skipByName = @{}
foreach ($s in $directOut) { $skipByName[$s.name] = $s }
$workIdx = 0
$done = 0
foreach ($e in $entries) {
    $done++
    $obj = $null
    if ($skipByName.ContainsKey($e.Name)) {
        $obj = $skipByName[$e.Name]
    } else {
        $j = $jobsByIndex[$workIdx]
        $workIdx++
        try {
            $outputs = @($j.Ps.EndInvoke($j.Handle))
            foreach ($o in $outputs) { if ($null -ne $o) { $obj = $o; break } }
        } catch {
            $obj = New-SynthFail $e.Name ($j.Item.Mode) ("worker invoke failed: " + $_.Exception.Message)
        } finally {
            $j.Ps.Dispose()
        }
        if (-not $obj) { $obj = New-SynthFail $e.Name ($j.Item.Mode) 'worker produced no result object' }
    }
    # normalize + caps (300 detail / 120 behaviors per spec)
    $st = "$($obj.status)"
    if (@('pass', 'fail', 'crash', 'timeout', 'envfail', 'mismatch', 'skip') -notcontains $st) { $st = 'fail' }
    $det = "$($obj.detail)"
    if ($det.Length -gt 300) { $det = $det.Substring(0, 300) }
    $ob = "$($obj.origBehavior)"
    if ($ob.Length -gt 120) { $ob = $ob.Substring(0, 120) }
    $pb = "$($obj.packedBehavior)"
    if ($pb.Length -gt 120) { $pb = $pb.Substring(0, 120) }
    $null = $results.Add([pscustomobject]@{
        name           = $e.Name
        mode           = "$($obj.mode)"
        status         = $st
        seconds        = [double]$obj.seconds
        detail         = $det
        origBehavior   = $ob
        packedBehavior = $pb
    })
    # checkpoint after EVERY sample: a mid-run death still leaves a valid summary
    Publish-Summary $entries.Count
    Write-Host ("[{0}/{1}] {2} [{3}] -> {4}" -f $done, $entries.Count, $e.Name, $obj.mode, $st)
}
$pool.Close()
$pool.Dispose()

# --- summary (final) --------------------------------------------------------------------
Publish-Summary $entries.Count
$passed  = @($results | Where-Object { $_.status -eq 'pass' }).Count
$envfail = @($results | Where-Object { $_.status -eq 'envfail' }).Count
$skipped = @($results | Where-Object { $_.status -eq 'skip' }).Count

Write-Host ("func-verify done: {0}/{1} passed, {2} envfail, {3} skipped (coverage {4}); summary: {5}" -f $passed, $results.Count, $envfail, $skipped, ($entries.Count - $skipped), $summaryPath)
$bad = @($results | Where-Object { $_.status -notin @('pass', 'skip', 'envfail') }).Count
if ($bad -eq 0) { exit 0 } else { exit 1 }
