param(
    [Parameter(Mandatory = $true)]
    [string]$PackedA,
    [Parameter(Mandatory = $true)]
    [string]$PackedB,
    [Parameter(Mandatory = $true)]
    [string]$InspectJsonPath,
    [string]$Cli = "",
    [string]$InputDll = ""
)

$ErrorActionPreference = "Stop"

function Fail([string]$msg) {
    Write-Error $msg
    exit 1
}

if (-not (Test-Path -LiteralPath $PackedA)) { Fail "missing packed file: $PackedA" }
if (-not (Test-Path -LiteralPath $PackedB)) { Fail "missing packed file: $PackedB" }
if (-not (Test-Path -LiteralPath $InspectJsonPath)) { Fail "missing inspect json: $InspectJsonPath" }

$bytesA = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PackedA))
$bytesB = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PackedB))

$ascii = [System.Text.Encoding]::ASCII.GetString($bytesA)
foreach ($needle in @("UPX0", "UPX1", "UPX!", ".packed")) {
    if ($ascii.Contains($needle)) {
        Fail "packed bytes contain forbidden marker '$needle' (G-SIG)"
    }
}

$inspect = Get-Content -LiteralPath $InspectJsonPath -Raw | ConvertFrom-Json
if ($null -eq $inspect.import_rva) {
    Fail "inspect JSON missing import_rva"
}
# G-IAT: the disk import directory must be gone on standard/max, except the
# documented product keeps (docs/SUPPORT.md): TLS-callback images keep it
# because LoadLibraryA is unsafe under the loader lock, and JNI/qp_r1_*
# exports keep it because the JVM resolves them by exact name. Any non-zero
# import_rva outside those keeps is a silent downgrade and fails here.
$iatJustified = $false
if ([int]$inspect.import_rva -ne 0) {
    if ($inspect.iat_mode -ne "disk-import-directory") {
        Fail "G-IAT disk: import_rva is $($inspect.import_rva) but iat_mode is '$($inspect.iat_mode)'"
    }
    $tlsKeep = ($null -ne $inspect.tls_directory_rva) -and ([int]$inspect.tls_directory_rva -ne 0)
    $jniKeep = $false
    if ($null -ne $inspect.exports) {
        foreach ($e in $inspect.exports) {
            if ($e.name -eq "JNI_OnLoad" -or $e.name -eq "JNI_OnUnload" -or
                $e.name.StartsWith("Java_") -or $e.name.StartsWith("qp_r1_")) {
                $jniKeep = $true
            }
        }
    }
    $iatJustified = $tlsKeep -or $jniKeep
    if (-not $iatJustified) {
        Fail "G-IAT disk: import_rva must be 0, got $($inspect.import_rva) (no TLS/JNI keep reason)"
    }
    Write-Host "G-IAT disk: import_rva kept at $($inspect.import_rva) per documented TLS/JNI keep"
}

if ($bytesA.Length -eq $bytesB.Length) {
    $same = $true
    for ($i = 0; $i -lt $bytesA.Length; $i++) {
        if ($bytesA[$i] -ne $bytesB[$i]) { $same = $false; break }
    }
    if ($same) { Fail "G-POLY: two packed outputs are identical" }
} else {
    # different length already implies polymorphism
}

$flipPath = Join-Path ([System.IO.Path]::GetDirectoryName((Resolve-Path -LiteralPath $PackedA))) "hello_dll.xl.flip.dll"
[System.IO.File]::Copy((Resolve-Path -LiteralPath $PackedA), $flipPath, $true)
$flip = [System.IO.File]::ReadAllBytes($flipPath)
$off = 0x600
if ($flip.Length -le $off) { Fail "packed file shorter than 0x600; cannot flip executable page" }
$flip[$off] = $flip[$off] -bxor 0x01
[System.IO.File]::WriteAllBytes($flipPath, $flip)
$shaA = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytesA))
$shaFlip = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($flip))
if ($shaA -eq $shaFlip) { Fail "tamper flip at 0x600 did not change SHA256" }
# LoadLibrary fail-closed is covered by cargo test packed_dll_tamper_flip_fails_closed.

$upx = Get-Command upx -ErrorAction SilentlyContinue
if ($null -eq $upx) {
    Write-Host "G-UPX skipped: upx not installed"
} else {
    if (-not $Cli -or -not $InputDll) {
        Write-Host "G-UPX skipped: packer CLI or input DLL not provided"
    } else {
        $upxOut = Join-Path ([System.IO.Path]::GetDirectoryName((Resolve-Path -LiteralPath $PackedA))) "hello_dll.xl.upxtry.dll"
        & $upx.Source -d -o $upxOut (Resolve-Path -LiteralPath $PackedA)
        if ($LASTEXITCODE -eq 0) {
            Fail "G-UPX: upx -d succeeded on packed image"
        }
        Write-Host "G-UPX: upx -d failed as expected (exit $LASTEXITCODE)"
    }
}

Write-Host "ci-gates: G-SIG markers, G-IAT disk (0 or documented TLS/JNI keep), G-POLY, tamper SHA256 ok"
exit 0
