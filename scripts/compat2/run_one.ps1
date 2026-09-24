<#
.SYNOPSIS
    Xenolith compatibility harness - single sample (from-zero rewrite, PS 5.1, zero dependencies).

.DESCRIPTION
    Packs one PE sample with the xenolith CLI (`pack <input> -o <output>`, fully
    non-interactive - confirmed against crates/xenolith-cli/src/main.rs and args.rs),
    captures stdout/stderr/exit code under a hard 600 s timeout, statically validates
    the packed output (MZ/PE signatures, x64 machine, PE32+ optional header + section
    table parseable, import directory data readable), and writes a per-sample JSON.

    The input sample and the packed artifact are NEVER executed. The sample is never
    written to. The tool only receives `fs::read` on the input (cli main.rs) and writes
    the single -o path, which lives under OutDir.

    Status taxonomy (strict - a check that does not pass is a failure):
      pass    tool exit 0 AND every static check passed
      fail    tool reported a clean error (exit != 0, no panic signature) OR
              validation of the output failed OR input sample missing
      crash   exit code 101 / negative NTSTATUS exit / panic text in output
      timeout tool killed after -TimeoutSeconds

.PARAMETER InputFile
    Path to the PE sample (relative paths resolve against the current directory).

.PARAMETER OutDir
    Result directory. Per-sample JSON is written to <OutDir>\<sample-file-name>.json.
    The packed artifact is kept for inspection at <OutDir>\packed\<name>.xl.exe.

.PARAMETER ToolPath
    Path to xenolith.exe.

.PARAMETER FileLabel
    Optional. Value recorded verbatim in the JSON "file" field (defaults to the
    -InputFile string as typed). run_corpus.ps1 passes the original manifest line
    so "file" stays the sample's relative path.

.PARAMETER TimeoutSeconds
    Per-sample wall-clock kill timeout. Default 600.

.OUTPUTS
    Exactly one line on stdout: the per-sample result as compact JSON (also written
    to the JSON file). Diagnostics go to stderr only.

.EXITCODES
    0 pass | 1 fail/crash/timeout | 2 harness-level error (tool missing, OutDir
    unwritable, process could not start - no JSON is written for these).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [Parameter(Mandatory = $true)][string]$ToolPath,
    [string]$FileLabel,
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Diag {
    param([string]$Msg)
    [Console]::Error.WriteLine("run_one: $Msg")
}

function Limit-Digest {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $s = [regex]::Replace($Text, "\r?\n", ' | ')
    $s = [regex]::Replace($s, '\s+', ' ').Trim()
    if ($s.Length -gt 500) { $s = $s.Substring(0, 500) }
    return $s
}

# Tool text (stdout+stderr) -> short digest: prefer explicit error lines, else tail.
function Get-ToolDigest {
    param([string]$Stdout, [string]$Stderr)
    $lines = @()
    foreach ($blob in @($Stdout, $Stderr)) {
        if ($blob) {
            foreach ($l in ($blob -split "\r?\n")) {
                if ($l.Trim().Length -gt 0) { $lines += $l.Trim() }
            }
        }
    }
    $err = @($lines | Where-Object { $_ -match '^error(\[|:)|error:|panicked|fatal' })
    $pick = if ($err.Count -gt 0) { $err } else { if ($lines.Count -gt 0) { $lines | Select-Object -Last 4 } else { @() } }
    return ($pick -join ' | ')
}

# ---------------------------------------------------------------------------
# Static PE validator. Returns an array of failure strings (empty = valid).
# Strict by design: every anomaly is a failure.
# ---------------------------------------------------------------------------
function Test-PackedImage {
    param([string]$Path)

    $bad = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $bad.Add("output file missing: $Path")
        return ,$bad.ToArray()
    }
    $len = (Get-Item -LiteralPath $Path).Length
    if ($len -lt 0x100) {
        $bad.Add("output file too small ($len bytes)")
        return ,$bad.ToArray()
    }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    } catch {
        $bad.Add("output file unreadable: $($_.Exception.Message)")
        return ,$bad.ToArray()
    }
    $n = $bytes.Length

    function Read-U16([byte[]]$b, [int]$o) {
        if ($o -ge 0 -and ($o + 2) -le $b.Length) { return [BitConverter]::ToUInt16($b, $o) }
        return -1
    }
    function Read-U32([byte[]]$b, [int]$o) {
        if ($o -ge 0 -and ($o + 4) -le $b.Length) { return [BitConverter]::ToUInt32($b, $o) }
        return -1  # sentinel; real u32 fields checked below never legitimately hit -1
    }
    function Read-U64([byte[]]$b, [int]$o) {
        if ($o -ge 0 -and ($o + 8) -le $b.Length) { return [BitConverter]::ToUInt64($b, $o) }
        return -1
    }

    # 1. MZ signature
    if ($n -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        $bad.Add('no MZ signature')
        return ,$bad.ToArray()
    }
    # 2. e_lfanew + PE signature
    $e_lfanew = Read-U32 $bytes 0x3C
    if ($e_lfanew -lt 0 -or ($e_lfanew + 4) -gt $n) {
        $bad.Add("e_lfanew 0x{0:x} out of file bounds" -f $e_lfanew)
        return ,$bad.ToArray()
    }
    if ($bytes[$e_lfanew] -ne 0x50 -or $bytes[$e_lfanew + 1] -ne 0x45 -or $bytes[$e_lfanew + 2] -ne 0 -or $bytes[$e_lfanew + 3] -ne 0) {
        $bad.Add('no PE\0\0 signature at e_lfanew')
        return ,$bad.ToArray()
    }
    # 3. machine type must be x64 (0x8664)
    $machine = Read-U16 $bytes ($e_lfanew + 4)
    if ($machine -ne 0x8664) {
        $bad.Add('machine type 0x{0:x4} is not x64 (0x8664)' -f $machine)
    }
    # 4. COFF header / optional header / section table fully parseable
    $numSections = Read-U16 $bytes ($e_lfanew + 6)
    $sizeOfOptional = Read-U16 $bytes ($e_lfanew + 20)
    if ($numSections -lt 1) { $bad.Add("section count $numSections < 1") }
    $opt = $e_lfanew + 24
    if (($opt + $sizeOfOptional) -gt $n) {
        $bad.Add("optional header (off 0x$($opt.ToString('x')), size $sizeOfOptional) exceeds file")
        return ,$bad.ToArray()
    }
    $magic = Read-U16 $bytes $opt
    if ($magic -ne 0x20B) { $bad.Add('optional header magic 0x{0:x4} is not PE32+ (0x20b)' -f $magic) }
    $numRva = Read-U32 $bytes ($opt + 108)
    if ($numRva -lt 2) { $bad.Add("NumberOfRvaAndSizes $numRva < 2 (no import directory slot)") }
    if ($sizeOfOptional -lt (112 + 16 * 8)) { $bad.Add("SizeOfOptionalHeader $sizeOfOptional < 240 (PE32+ minimum)") }
    $secStart = $opt + $sizeOfOptional
    if (($secStart + 40 * $numSections) -gt $n) {
        $bad.Add("section table ($numSections x 40B at 0x$($secStart.ToString('x'))) exceeds file")
        return ,$bad.ToArray()
    }
    $sizeOfHeaders = Read-U32 $bytes ($opt + 60)
    if (($sizeOfHeaders -le 0) -or ($sizeOfHeaders -gt $n)) { $bad.Add("SizeOfHeaders $sizeOfHeaders out of bounds") }

    # parse every section header; verify raw data stays inside the file
    $sections = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $numSections; $i++) {
        $s = $secStart + 40 * $i
        $vsize  = Read-U32 $bytes ($s + 8)
        $vaddr  = Read-U32 $bytes ($s + 12)
        $rsize  = Read-U32 $bytes ($s + 16)
        $rptr   = Read-U32 $bytes ($s + 20)
        if ($rsize -gt 0) {
            if ($rptr -gt $n -or $rsize -gt ($n - $rptr)) {
                $bad.Add("section $i raw data (ptr 0x$($rptr.ToString('x')), size 0x$($rsize.ToString('x'))) exceeds file")
            }
        }
        $null = $sections.Add([pscustomobject]@{
            VirtualAddress = [uint32]$vaddr; VirtualSize = [uint32]$vsize
            SizeOfRawData = [uint32]$rsize;  PointerToRawData = [uint32]$rptr
        })
    }

    # RVA -> file offset through the parsed section table (or the header block).
    function Convert-RvaToOffset([uint32]$Rva) {
        if ($Rva -lt $sizeOfHeaders -and $Rva -lt $n) { return [int]$Rva }
        foreach ($sec in $sections) {
            $span = [math]::Max($sec.VirtualSize, $sec.SizeOfRawData)
            if ($Rva -ge $sec.VirtualAddress -and $Rva -lt ($sec.VirtualAddress + $span)) {
                $delta = $Rva - $sec.VirtualAddress
                if ($delta -lt $sec.SizeOfRawData) { return [int]($sec.PointerToRawData + $delta) }
                return -1
            }
        }
        return -1
    }
    # bounded NUL scan (DLL/API names are short; cap guards against runaway scans)
    function Find-NulFrom([int]$Offset, [int]$MaxSpan) {
        $end = [math]::Min($Offset + $MaxSpan, $n)
        for ($k = $Offset; $k -lt $end; $k++) { if ($bytes[$k] -eq 0) { return $k } }
        return -1
    }
    # PS 5.1: 0x8000000000000000 literal parses as a negative Int64; parse exactly instead
    $ordinalBit = [Convert]::ToUInt64('8000000000000000', 16)

    # 5. import directory (data directory index 1) data must be readable
    #    Legit packed states: (a) RVA=0 and Size=0 - xenolith max-profile writeback
    #    mode zeroes the on-disk import directory (xenolith-pack/src/lib.rs);
    #    (b) RVA != 0 - every descriptor, thunk array and name must map to file data.
    $impRva  = Read-U32 $bytes ($opt + 112 + 8)
    $impSize = Read-U32 $bytes ($opt + 112 + 12)
    if ($impRva -eq 0 -and $impSize -eq 0) {
        # sealed/writeback IAT: nothing on disk to read - accepted by design
    } elseif ($impRva -eq 0) {
        $bad.Add("import directory size 0x$($impSize.ToString('x')) with rva 0")
    } else {
        $descOff = Convert-RvaToOffset $impRva
        if ($descOff -lt 0) {
            $bad.Add('import directory rva 0x{0:x} not mappable to file data' -f $impRva)
        } else {
            $di = 0
            while ($true) {
                $d = $descOff + 20 * $di
                if (($d + 20) -gt $n) { $bad.Add("import descriptor $di out of file bounds"); break }
                $oft     = Read-U32 $bytes ($d + 0)
                $nameRva = Read-U32 $bytes ($d + 12)
                $ft      = Read-U32 $bytes ($d + 16)
                if ($oft -eq 0 -and $nameRva -eq 0 -and $ft -eq 0) { break }   # terminator
                # DLL name must map and be NUL-terminated in the file
                $nameOff = Convert-RvaToOffset $nameRva
                if ($nameOff -lt 0) {
                    $bad.Add('import dll-name rva 0x{0:x} (descriptor {1}) not mappable' -f $nameRva, $di)
                } elseif ((Find-NulFrom $nameOff 4096) -lt 0) {
                    $bad.Add("import dll-name at 0x$($nameOff.ToString('x')) (descriptor $di) not NUL-terminated within 4096B")
                }
                # thunk array (INT preferred, else IAT) must map and parse to a terminator
                $thunkRva = $oft
                if ($thunkRva -eq 0) { $thunkRva = $ft }
                if ($thunkRva -eq 0) {
                    $bad.Add("import descriptor $di has no thunk array")
                } else {
                    $thunkOff = Convert-RvaToOffset $thunkRva
                    if ($thunkOff -lt 0) {
                        $bad.Add('import thunk rva 0x{0:x} (descriptor {1}) not mappable' -f $thunkRva, $di)
                    } else {
                        $j = 0
                        while ($true) {
                            $tOff = $thunkOff + 8 * $j
                            if (($tOff + 8) -gt $n) { $bad.Add("import thunk $j (descriptor $di) out of file bounds"); break }
                            $thunk = Read-U64 $bytes $tOff
                            if ($thunk -eq 0) { break }
                            if (($thunk -band $ordinalBit) -eq 0) {
                                $fnRva = [uint32]($thunk -band 0xFFFFFFFF)
                                $fnOff = Convert-RvaToOffset $fnRva
                                if ($fnOff -lt 0) {
                                    $bad.Add('import name rva 0x{0:x} (descriptor {1}, thunk {2}) not mappable' -f $fnRva, $di, $j)
                                } elseif ((Find-NulFrom ($fnOff + 2) 4096) -lt 0) {
                                    $bad.Add("import name at 0x$(($fnOff + 2).ToString('x')) (descriptor $di, thunk $j) not NUL-terminated within 4096B")
                                }
                            }
                            $j++
                            if ($j -gt 65535) { $bad.Add("runaway import thunk array (descriptor $di)"); break }
                        }
                    }
                }
                $di++
                if ($di -gt 65535) { $bad.Add('runaway import descriptor array'); break }
            }
        }
    }
    return ,$bad.ToArray()
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $ToolPath -PathType Leaf)) {
    Write-Diag "tool not found: $ToolPath"
    exit 2
}
$toolAbs = (Resolve-Path -LiteralPath $ToolPath).ProviderPath

if (-not $PSBoundParameters.ContainsKey('FileLabel') -or [string]::IsNullOrEmpty($FileLabel)) {
    $FileLabel = $InputFile
}
$name = [System.IO.Path]::GetFileName($InputFile)

try {
    if (-not (Test-Path -LiteralPath $OutDir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $OutDir -Force
    }
    $outDirAbs = (Resolve-Path -LiteralPath $OutDir).ProviderPath
} catch {
    Write-Diag "OutDir unusable: $($_.Exception.Message)"
    exit 2
}

$inAbs = $null
try { $inAbs = (Resolve-Path -LiteralPath $InputFile -ErrorAction Stop).ProviderPath } catch { }

$status = $null
$exitCode = -1
$seconds = 0
$digest = ''

if (-not $inAbs) {
    # missing sample: per-sample failure (harness keeps going), tool never invoked
    $status = 'fail'
    $digest = "input sample not found (tool not invoked): $InputFile"
} else {
    $packedDir = Join-Path $outDirAbs 'packed'
    if (-not (Test-Path -LiteralPath $packedDir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $packedDir -Force
    }
    $packedPath = Join-Path $packedDir ([System.IO.Path]::GetFileNameWithoutExtension($name) + '.xl.exe')
    if (Test-Path -LiteralPath $packedPath) { Remove-Item -LiteralPath $packedPath -Force }   # no stale-pass

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $toolAbs
    $psi.Arguments = 'pack "{0}" -o "{1}"' -f $inAbs, $packedPath
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true        # closed right after start: nothing interactive can ever block on stdin
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $null = $proc.Start()
    } catch {
        $sw.Stop()
        Write-Diag "failed to start tool: $($_.Exception.Message)"
        exit 2
    }
    $proc.StandardInput.Close()
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    $timedOut = $false
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        $timedOut = $true
        try { $proc.Kill() } catch { }
        $proc.WaitForExit()
    }
    $stdout = $outTask.Result
    $stderr = $errTask.Result
    $sw.Stop()
    $seconds = [math]::Round($sw.Elapsed.TotalSeconds, 3)
    $exitCode = [int]$proc.ExitCode
    $proc.Dispose()

    $panicText = ($stdout + ' ' + $stderr) -match 'panicked at|stack backtrace|RUST_BACKTRACE'
    if ($timedOut) {
        $status = 'timeout'
        $digest = Limit-Digest ("tool killed after {0}s (exit={1})" -f $TimeoutSeconds, $exitCode)
        $td = Get-ToolDigest $stdout $stderr
        if ($td) { $digest = Limit-Digest ($digest + ' | ' + $td) }
    } elseif ($exitCode -eq 101 -or $exitCode -lt 0 -or $panicText) {
        $status = 'crash'
        $digest = Limit-Digest ("tool crash (exit={0}): {1}" -f $exitCode, (Get-ToolDigest $stdout $stderr))
    } elseif ($exitCode -ne 0) {
        $status = 'fail'
        $digest = Limit-Digest ("tool error (exit={0}): {1}" -f $exitCode, (Get-ToolDigest $stdout $stderr))
    } else {
        $vfail = Test-PackedImage -Path $packedPath
        if ($vfail.Count -eq 0) {
            $status = 'pass'
        } else {
            $status = 'fail'
            $digest = Limit-Digest ('PE static validation failed: ' + ($vfail -join '; '))
        }
    }
}

$result = [pscustomobject]@{
    name         = $name
    file         = $FileLabel
    status       = $status
    toolExitCode = [int]$exitCode
    seconds      = $seconds
    errorDigest  = $digest
}

$jsonPath = Join-Path $outDirAbs ($name + '.json')
try {
    [System.IO.File]::WriteAllText($jsonPath, ($result | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
} catch {
    Write-Diag "cannot write result JSON ${jsonPath}: $($_.Exception.Message)"
    exit 2
}

# single machine-readable line on stdout for run_corpus.ps1
$result | ConvertTo-Json -Compress -Depth 6

if ($status -eq 'pass') { exit 0 } else { exit 1 }
