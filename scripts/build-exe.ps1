[CmdletBinding()]
param(
    [string]$OutputDir = "dist",
    [string]$Label = "",
    [switch]$RunTests,
    [switch]$ReleaseBundle,
    [switch]$AllowBudgetFail,
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    Write-Host "> $FilePath $($Arguments -join ' ')"
    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
        }
    }
    finally {
        Pop-Location
    }
}

if ($env:OS -ne "Windows_NT") {
    throw "build-exe.ps1 builds the Windows x86_64 Xenolith executable. Run it on Windows."
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([System.IO.Path]::IsPathRooted($OutputDir)) {
    $outputPath = [System.IO.Path]::GetFullPath($OutputDir)
}
else {
    $outputPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDir))
}

Push-Location -LiteralPath $repoRoot
try {
    if ($Clean) {
        Invoke-Checked -FilePath "cargo" -Arguments @("clean") -WorkingDirectory $repoRoot
    }

    Invoke-Checked -FilePath "cargo" -Arguments @(
        "build",
        "--locked",
        "--release",
        "-p",
        "xenolith-cli"
    ) -WorkingDirectory $repoRoot

    if ($RunTests) {
        Invoke-Checked -FilePath "cargo" -Arguments @(
            "build",
            "--locked",
            "--release",
            "-p",
            "hello-dll",
            "-p",
            "license-toy",
            "-p",
            "hello-exe"
        ) -WorkingDirectory $repoRoot

        $previousSkipWsl = $env:XL_SKIP_WSL_TESTS
        $env:XL_SKIP_WSL_TESTS = "1"
        try {
            Invoke-Checked -FilePath "cargo" -Arguments @(
                "test",
                "--locked",
                "--workspace",
                "--exclude",
                "xenolith-runtime"
            ) -WorkingDirectory $repoRoot
        }
        finally {
            $env:XL_SKIP_WSL_TESTS = $previousSkipWsl
        }
    }

    $builtExe = Join-Path $repoRoot "target\release\xenolith.exe"
    if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) {
        throw "Build finished but executable was not found: $builtExe"
    }

    New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
    $packagedExe = Join-Path $outputPath "xenolith.exe"
    Copy-Item -LiteralPath $builtExe -Destination $packagedExe -Force

    $exeHash = (Get-FileHash -LiteralPath $packagedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashFile = Join-Path $outputPath "xenolith.exe.sha256"
    "$exeHash *xenolith.exe" | Set-Content -LiteralPath $hashFile -Encoding ascii

    if ($ReleaseBundle) {
        if ([string]::IsNullOrWhiteSpace($Label)) {
            $Label = "v$(Get-Date -Format 'yyyyMMdd-HHmmss')-windows-x86_64"
        }

        $releaseArgs = @(
            "release",
            "--out",
            $outputPath,
            "--label",
            $Label
        )
        if ($AllowBudgetFail) {
            $releaseArgs += "--allow-budget-fail"
        }

        Invoke-Checked -FilePath $packagedExe -Arguments $releaseArgs -WorkingDirectory $repoRoot
    }

    $version = (& $packagedExe --version).Trim()
    Write-Host ""
    Write-Host "Built:   $packagedExe"
    Write-Host "Version: $version"
    Write-Host "SHA256:  $exeHash"
    Write-Host "Hash:    $hashFile"
    if ($ReleaseBundle) {
        $manifestPath = Join-Path $outputPath "manifest.json"
        $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host "Bundle:   $manifestPath"
        Write-Host "Manifest SHA256: $manifestHash"
    }
}
finally {
    Pop-Location
}
