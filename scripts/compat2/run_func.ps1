<#
.SYNOPSIS
    Xenolith functional verification - "does the packed binary still work" (PS 5.1, zero dependencies).

.DESCRIPTION
    Phase 2 of the compatibility harness. Consumes the packed artifacts produced by
    phase 1 (scripts/compat2/run_one.ps1: <base>.xl.exe) and proves each one is
    functional, following scripts/compat2/classification.json. Packed artifacts are
    located by probing -PackedDir, then <ResultsDir>\packed, then
    <repo>\out\compat-results\packed (the split static/functional layout);
    summary.json and exe-run\ are always written under -ResultsDir.

      load  start target\release\xl-loadhost.exe <packed.dll> in a child process,
            hard 60 s timeout. Exit 0 = pass, 3 = fail (load rejected, lastWinError
            in its JSON), negative / 0xC0000005-class = crash, killed = timeout.
            xl-loadhost only LoadLibraryW's the artifact and GetProcAddress'es names;
            it never calls exports (DllMain runs implicitly - that is the point).
      exec  copy the packed EXE next to its ORIGINAL file as
            <base>.xenolith-test.<ext> (dependencies resolve; originals are never
            overwritten or modified - the test name is a fresh file we own), launch
            it, hard 30 s timeout, then kill the ENTIRE process tree (Win32 job
            object with KILL_ON_JOB_CLOSE + taskkill /T /F belt). Still alive at
            the timeout (GUI apps) = pass. Early exit: crash status codes
            (0xC0000005, 0xC0000409, ...) = crash, any other exit code = pass
            (the envelope decrypted and the original entry point really ran).
            The copy is ALWAYS deleted afterwards.
            If the original's directory is not writable (e.g. Program Files without
            elevation) the copy falls back to <ResultsDir>\exe-run\ and the child
            is launched with cwd + PATH pinned to the original's directory so
            sibling dependencies still resolve. The fallback is recorded in detail.
      skip  status=skip, classification reason recorded verbatim in detail.

    Safety invariants: originals are never executed and never modified; the corpus
    under out/compat-corpus is never written to; only our own <base>.xenolith-test.<ext>
    copies and harness-owned directories are created/removed; every launched process
    tree is killed (children included) before the run moves on.

.PARAMETER Manifest
    Path to the phase-1 manifest (JSON array of { name, origin, ... }; plain text
    "one file per line" is also accepted). Relative "name" values resolve against
    the manifest's directory.

.PARAMETER ResultsDir
    Output directory for THIS functional run: summary.json, exe-run\ and the
    staged-copy ledger live here. Packed artifacts are NOT required to be here -
    see -PackedDir.

.PARAMETER PackedDir
    Directory holding the phase-1 packed artifacts (<base>.xl.exe). Default
    probing order: this parameter, then <ResultsDir>\packed, then
    <repo>\out\compat-results\packed. If none holds *.xl.exe artifacts the
    script exits 2 without touching any sample.

.PARAMETER ClassificationPath
    Path to classification.json. Default: next to this script.

.PARAMETER LoadHostPath
    Path to xl-loadhost.exe. Default: <repo>\target\release\xl-loadhost.exe.

.PARAMETER MaxParallel
    Concurrent samples. Default (and hard ceiling per spec): 4.

.PARAMETER LoadTimeoutSeconds / ExecTimeoutSeconds
    Hard kill timeouts. Defaults: 60 / 30 (per spec).

.OUTPUTS
    <ResultsDir>\summary.json =
      { "total": n, "passed": n, "skipped": n, "coverage": n, "complete": bool,
        "results": [ { "name":..., "mode": "load|exec|skip",
                       "status": "pass|fail|crash|timeout|skip",
                       "seconds": n, "detail": "<=300 chars" } ] }
    The file is written atomically and CHECKPOINTED after every harvested sample:
    "complete": false marks a partial snapshot (run still going, or the host died
    mid-run - e.g. the observed AmsiScanBuffer AV in powershell.exe); only the
    final write sets "complete": true. A summary from a dead run is a valid,
    honestly-labeled partial result, never a missing or truncated file.

.EXITCODES
    0 every non-skip sample passed | 1 at least one failed/crashed/timed out |
    2 harness-level error (missing load host / classification / manifest, bad JSON,
    ResultsDir unusable, packed\ directory missing or holds no *.xl.exe - i.e. a
    wrong -ResultsDir, job-object runtime could not be compiled)
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

# --- locate the phase-1 packed artifacts (this script CONSUMES, never produces) -----
# An explicit -PackedDir is AUTHORITATIVE: if it holds no *.xl.exe the run is a
# configuration error (exit 2), never a silent fallback to guesses. Without it,
# probe <ResultsDir>\packed (shared-layout) then <repo>\out\compat-results\packed
# (split static/functional layout). All probes empty => exit 2 without touching
# any sample: treating this as per-sample failures once disguised a 0/N verdict.
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if ($PackedDir) {
    $artifactDir = $null
    try {
        $artifactDir = (Resolve-Path -LiteralPath $PackedDir -ErrorAction Stop).ProviderPath
    } catch {
        Write-Diag "-PackedDir not found: $PackedDir"
        exit 2
    }
    if (@(Get-ChildItem -LiteralPath $artifactDir -File -Filter '*.xl.exe' -ErrorAction SilentlyContinue).Count -eq 0) {
        Write-Diag "-PackedDir holds no *.xl.exe artifacts: $artifactDir"
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
}
if (-not (Test-Path -LiteralPath $exeRunDir -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $exeRunDir -Force
}

# --- cross-run residue healing -------------------------------------------------------
# A hard-killed run (host crash, taskkill /F, power loss) never executes its
# finally-block, so a staged *.xenolith-test.* copy can leak on disk. Every exec
# worker appends its staged path to a ledger BEFORE copying; the next run sweeps
# whatever still exists here, then rewrites the ledger with only the paths it
# could not delete (still locked by a leaked process, etc.).
$ledgerPath = Join-Path $exeRunDir 'staged-copies.log'
if (Test-Path -LiteralPath $ledgerPath -PathType Leaf) {
    $keptLines = New-Object System.Collections.Generic.List[string]
    foreach ($line in ([System.IO.File]::ReadAllLines($ledgerPath))) {
        $p = $line.Trim()
        if ($p.Length -eq 0) { continue }
        if ((Test-Path -LiteralPath $p -PathType Leaf) -and ($p -match '\.xenolith-test\.')) {
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
# the exe-run dir itself is harness-owned: any *.xenolith-test.* file in it is ours
Get-ChildItem -LiteralPath $exeRunDir -File -Filter '*.xenolith-test.*' -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
        Write-Diag ("swept leftover fallback copy: " + $_.FullName)
    } catch { Write-Diag ("cannot sweep " + $_.FullName + " : " + $_.Exception.Message) }
}

# --- crash-resilient summary writing ---------------------------------------------------
# The summary is written atomically (tmp + NTFS Replace) and CHECKPOINTED after
# every harvested sample, so a mid-run host death (observed: AmsiScanBuffer AV in
# powershell.exe) always leaves a VALID current-schema summary.json behind, with
# "complete": false marking it partial. The final write sets "complete": true.
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
    param([bool]$Complete, [int]$TotalEntries)
    $passed = @($results | Where-Object { $_.status -eq 'pass' }).Count
    $skipped = @($results | Where-Object { $_.status -eq 'skip' }).Count
    $sum = [pscustomobject]@{
        total    = $TotalEntries
        passed   = $passed
        skipped  = $skipped
        coverage = $TotalEntries - $skipped
        complete = $Complete
        results  = @($results)
    }
    try {
        Write-SummaryAtomic $summaryPath ($sum | ConvertTo-Json -Depth 6)
    } catch {
        Write-Diag ("cannot write summary checkpoint: " + $_.Exception.Message)
    }
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

# basename collision map (phase-1 packed path is keyed on name-without-extension:
# IDA_ida.dll / IDA_ida.exe and Weixin_Weixin.dll / Weixin_Weixin.exe share one artifact)
$baseCount = @{}
foreach ($e in $entries) {
    $b = [System.IO.Path]::GetFileNameWithoutExtension($e.Name)
    if (-not $baseCount.ContainsKey($b)) { $baseCount[$b] = New-Object System.Collections.ArrayList }
    $null = $baseCount[$b].Add($e.Name)
}
function Get-CollisionNote([string]$Name) {
    $b = [System.IO.Path]::GetFileNameWithoutExtension($Name)
    $peers = @($baseCount[$b] | Where-Object { $_ -ne $Name })
    if ($peers.Count -eq 0) { return '' }
    return ('packed artifact path shared with: ' + ($peers -join ', '))
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
        Write-Diag ("cannot compile job-object helper (exec tree-kill degrades to taskkill /T): " + $_.Exception.Message)
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

function New-Res([string]$Status, [double]$Seconds, [string]$Detail) {
    return [pscustomobject]@{ name = $Item.Name; mode = $Item.Mode; status = $Status; seconds = $Seconds; detail = $Detail }
}

if (-not (Test-Path -LiteralPath $Item.Packed -PathType Leaf)) {
    return (New-Res 'fail' 0 ("packed artifact missing: " + $Item.Packed + " (run run_corpus.ps1 first)"))
}

if ($Item.Mode -eq 'load') {
    # ---- load: xl-loadhost in a killable child process, 60 s hard timeout ----
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Item.LoadHost
    $psi.Arguments = '"' + $Item.Packed + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { $null = $proc.Start() } catch {
        return (New-Res 'fail' 0 ("failed to start xl-loadhost: " + $_.Exception.Message))
    }
    $proc.StandardInput.Close()   # nothing may block on stdin
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $timedOut = -not $proc.WaitForExit($Item.TimeoutSec * 1000)
    if ($timedOut) {
        Kill-Tree $proc.Id
        $proc.WaitForExit()
    }
    $stdout = ''
    try { $stdout = $outTask.Result } catch { }
    $stderr = ''
    try { $stderr = $errTask.Result } catch { }
    $sw.Stop()
    $code = [int]$proc.ExitCode
    $proc.Dispose()
    $firstOut = ($stdout -split "\r?\n" | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 1)
    $bits = @()
    if ($firstOut) { $bits += $firstOut.Trim() }
    $errTail = (($stderr -split "\r?\n" | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -Last 2) -join ' | ')
    if ($errTail) { $bits += $errTail }
    $digest = $bits -join ' | '
    if ($timedOut)      { return (New-Res 'timeout' ([math]::Round($sw.Elapsed.TotalSeconds,3)) ("xl-loadhost killed after " + $Item.TimeoutSec + "s" + $(if ($digest) { ' | ' + $digest }))) }
    if ($code -eq 0)    { return (New-Res 'pass'   ([math]::Round($sw.Elapsed.TotalSeconds,3)) ("xl-loadhost ok: " + $digest)) }
    if ($code -eq 3)    { return (New-Res 'fail'   ([math]::Round($sw.Elapsed.TotalSeconds,3)) ("load rejected (exit 3): " + $digest)) }
    if (Is-CrashCode $code) { return (New-Res 'crash' ([math]::Round($sw.Elapsed.TotalSeconds,3)) ("xl-loadhost crash exit " + (ExitHex $code) + ": " + $digest)) }
    return (New-Res 'fail' ([math]::Round($sw.Elapsed.TotalSeconds,3)) ("unexpected xl-loadhost exit " + $code + ": " + $digest))
}

# ---- exec: run a throwaway copy of the packed EXE next to its original ----
$dest = Join-Path $Item.ExecDir $Item.ExecCopyName
$usedFallback = $false
$copied = $false
try {
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }   # our own leftover only
    Copy-Item -LiteralPath $Item.Packed -Destination $dest -Force
    $copied = $true
    # record BEFORE anything can go wrong: a hard-killed run has no finally, the
    # next run's preflight sweep is the only thing that can clean this up
    try { Add-Content -LiteralPath $Item.Ledger -Value $dest -Encoding ASCII } catch { }
} catch {
    # Original directory not writable (e.g. Program Files without elevation):
    # fall back to the harness-owned exe-run dir and pin cwd + PATH to the
    # original's directory so sibling dependencies still resolve. Originals
    # are still never touched.
    $usedFallback = $true
    $dest = Join-Path $Item.FallbackDir $Item.ExecCopyName
    try {
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
        Copy-Item -LiteralPath $Item.Packed -Destination $dest -Force
        $copied = $true
        try { Add-Content -LiteralPath $Item.Ledger -Value $dest -Encoding ASCII } catch { }
    } catch {
        return (New-Res 'fail' 0 ("cannot stage test copy: " + $_.Exception.Message))
    }
}

$proc = $null
$job = [IntPtr]::Zero
$jobOk = $false
$status = $null
$detail = $null
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $dest
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $Item.ExecDir
    if ($usedFallback) {
        $oldPath = $psi.EnvironmentVariables['Path']
        if ($null -eq $oldPath) { $oldPath = $env:Path }
        $psi.EnvironmentVariables['Path'] = ($Item.ExecDir + ';' + $oldPath)
    }
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    try {
        $null = $proc.Start()
    } catch {
        $sw.Stop()
        # return inside try: finally still runs, so the staged copy is removed
        return (New-Res 'fail' ([math]::Round($sw.Elapsed.TotalSeconds,3)) ('failed to start test copy: ' + $_.Exception.Message))
    }

    # put the whole future tree into a kill-on-close job (children included)
    if ($Item.JobNative) {
        try {
            $job = [XlJobNative]::Create()
            if (-not $job.Equals([IntPtr]::Zero)) {
                if ([XlJobNative]::SetKillOnClose($job)) {
                    $jobOk = [XlJobNative]::AssignProcessToJobObject($job, $proc.Handle)
                }
            }
        } catch { $jobOk = $false }
    }

    $timedOut = -not $proc.WaitForExit($Item.TimeoutSec * 1000)
    if ($timedOut) {
        # hard timeout: kill the entire tree, then call it a pass (GUI-style long-runner)
        if ($jobOk) { $null = [XlJobNative]::TerminateJobObject($job, 1) }
        Kill-Tree $proc.Id
        $proc.WaitForExit()
        $status = 'pass'
        $detail = 'still alive at ' + $Item.TimeoutSec + 's hard timeout (GUI-style); process tree killed'
    } else {
        $code = [int]$proc.ExitCode
        if (Is-CrashCode $code) {
            $status = 'crash'
            $detail = 'crashed during run, exit ' + (ExitHex $code)
        } else {
            $status = 'pass'
            $detail = 'exited code ' + $code + ' (envelope decrypted, original entry point executed)'
        }
    }
    $sw.Stop()
} finally {
    # always: kill anything left (kill-on-close job covers orphans a dead parent
    # left behind), then delete the test copy.
    if ($null -ne $proc) {
        # guard every property touch: on a failed Start these throw
        try { if (-not $proc.HasExited) { Kill-Tree $proc.Id } } catch { }
        try { $null = $proc.WaitForExit(5000) } catch { }
        $proc.Dispose()
    }
    if ($jobOk -or -not $job.Equals([IntPtr]::Zero)) {
        try { $null = [XlJobNative]::TerminateJobObject($job, 1) } catch { }
        try { $null = [XlJobNative]::CloseHandle($job) } catch { }
    }
    if ($copied) {
        $left = $true
        for ($i = 0; $i -lt 24 -and $left; $i++) {
            try {
                if (Test-Path -LiteralPath $dest) {
                    Remove-Item -LiteralPath $dest -Force -ErrorAction Stop
                }
                $left = (Test-Path -LiteralPath $dest)
            } catch { Start-Sleep -Milliseconds 500 }
        }
        if ($left) {
            if ($null -eq $detail) { $detail = '' }
            $detail = $detail + ' | WARN: test copy could not be deleted: ' + $dest
        }
    }
}
if ($usedFallback -and $null -ne $detail) {
    $detail = $detail + ' | copy fell back to harness exe-run dir (origin dir not writable); cwd+PATH pinned to origin dir'
}
return (New-Res $status ([math]::Round($sw.Elapsed.TotalSeconds,3)) $detail)
'@

# --- build the work list ------------------------------------------------------------
$work = New-Object System.Collections.ArrayList   # dispatched (load/exec)
$directSkip = New-Object System.Collections.ArrayList
foreach ($e in $entries) {
    $name = $e.Name
    $originAbs = $null
    if ($e.Origin) { $originAbs = Resolve-Against $e.Origin $manifestDir }
    $sampleAbs = Resolve-Against $name $manifestDir
    if (-not (Test-Path -LiteralPath $sampleAbs -PathType Leaf)) { $sampleAbs = $null }

    $c = $classification[$name]
    if (-not $c) {
        $null = $directSkip.Add([pscustomobject]@{
            name = $name; mode = 'skip'; status = 'skip'; seconds = 0
            detail = 'classification.json has no entry for this sample; conservatively skipped'
        })
        continue
    }
    if ($c.Mode -eq 'skip') {
        $null = $directSkip.Add([pscustomobject]@{
            name = $name; mode = 'skip'; status = 'skip'; seconds = 0; detail = $c.Reason
        })
        continue
    }
    $base = [System.IO.Path]::GetFileNameWithoutExtension($name)
    $packedPath = Join-Path $artifactDir ($base + '.xl.exe')   # phase-1 run_one.ps1 output convention

    if ($c.Mode -eq 'load') {
        $null = $work.Add([pscustomobject]@{
            Name = $name; Mode = 'load'; Packed = $packedPath; LoadHost = $loadHostAbs
            TimeoutSec = $LoadTimeoutSeconds; JobNative = $false
        })
    } else {
        # exec: prefer the ORIGINAL's directory (dependencies live there)
        $execDir = $null; $srcForName = $null
        if ($originAbs -and (Test-Path -LiteralPath $originAbs -PathType Leaf)) {
            $execDir = Split-Path $originAbs -Parent; $srcForName = $originAbs
        } elseif ($sampleAbs) {
            $execDir = Split-Path $sampleAbs -Parent; $srcForName = $sampleAbs
        }
        if (-not $execDir) {
            $null = $directSkip.Add([pscustomobject]@{
                name = $name; mode = 'exec'; status = 'fail'; seconds = 0
                detail = 'neither origin nor sample file exists: no directory to stage the test copy in'
            })
            continue
        }
        $copyName = [System.IO.Path]::GetFileNameWithoutExtension($srcForName) + '.xenolith-test.' + [System.IO.Path]::GetExtension($srcForName).TrimStart('.')
        $null = $work.Add([pscustomobject]@{
            Name = $name; Mode = 'exec'; Packed = $packedPath
            ExecDir = $execDir; ExecCopyName = $copyName; FallbackDir = $exeRunDir
            Ledger = $ledgerPath
            TimeoutSec = $ExecTimeoutSeconds; JobNative = $jobNativeOk
        })
    }
}

# --- dispatch (RunspacePool, <= 4 in flight) ------------------------------------------
# initial checkpoint: a valid current-schema summary exists from the moment the
# run legitimately started; "complete": false marks everything before the end
Publish-Summary $false $entries.Count

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
    return [pscustomobject]@{ name = $Name; mode = $Mode; status = 'fail'; seconds = 0; detail = $Why }
}

# --- harvest in manifest order (skips interleaved where they appeared) -----------------
# directSkip entries were produced in manifest order alongside dispatched work; walk
# both lists by matching names in the original entry order.
$skipByName = @{}
foreach ($s in $directSkip) { $skipByName[$s.name] = $s }
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
    # normalize + collision note + detail cap (300 chars per spec)
    $st = "$($obj.status)"
    if (@('pass', 'fail', 'crash', 'timeout', 'skip') -notcontains $st) { $st = 'fail' }
    $det = "$($obj.detail)"
    $coll = Get-CollisionNote $e.Name
    if ($coll) { $det = ($det + ' | ' + $coll).Trim(' |') }
    if ($det.Length -gt 300) { $det = $det.Substring(0, 300) }
    $null = $results.Add([pscustomobject]@{
        name    = $e.Name
        mode    = "$($obj.mode)"
        status  = $st
        seconds = [double]$obj.seconds
        detail  = $det
    })
    # checkpoint after EVERY sample: a mid-run death still leaves a valid summary
    Publish-Summary $false $entries.Count
    Write-Host ("[{0}/{1}] {2} [{3}] -> {4}" -f $done, $entries.Count, $e.Name, $obj.mode, $st)
}
$pool.Close()
$pool.Dispose()

# --- summary (final: complete = true) ----------------------------------------------------
$passed = @($results | Where-Object { $_.status -eq 'pass' }).Count
$skipped = @($results | Where-Object { $_.status -eq 'skip' }).Count
Publish-Summary $true $entries.Count

Write-Host ("func-verify done: {0}/{1} passed, {2} skipped (coverage {3}); summary: {4}" -f $passed, $results.Count, $skipped, ($entries.Count - $skipped), $summaryPath)
$bad = @($results | Where-Object { $_.status -notin @('pass', 'skip') }).Count
if ($bad -eq 0) { exit 0 } else { exit 1 }
