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

function Assert-EmptyOutput {
    param([Parameter(Mandatory = $true)][string]$Path)

    $ancestor = $Path
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor) {
            $item = Get-Item -LiteralPath $ancestor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Output path contains a reparse point: $ancestor"
            }
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
    if (Test-Path -LiteralPath $Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            throw "Output must be a plain directory: $Path"
        }
        if (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
            throw "Output directory is not empty: $Path. Choose a new directory."
        }
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
if ($outputPath.TrimEnd([char[]]"\/") -eq [IO.Path]::GetPathRoot($outputPath).TrimEnd([char[]]"\/")) {
    throw "Output must name a directory below a filesystem root: $outputPath"
}
$outputPath = $outputPath.TrimEnd([char[]]"\/")
Assert-EmptyOutput -Path $outputPath

$stagePath = $null
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
        # Keep the release fixtures in sync with the CI and release prebuilds.
        Invoke-Checked -FilePath "cargo" -Arguments @(
            "build",
            "--locked",
            "--release",
            "-p",
            "hello-dll",
            "-p",
            "license-toy",
            "-p",
            "hello-exe",
            "-p",
            "eh-dll",
            "-p",
            "jni-host",
            "-p",
            "jni-rust"
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

    $metadataText = & cargo metadata --format-version 1 --no-deps --locked
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo metadata failed with exit code $LASTEXITCODE"
    }
    $metadata = ($metadataText | Out-String) | ConvertFrom-Json
    $builtExe = Join-Path $metadata.target_directory "release\xenolith.exe"
    if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) {
        throw "Build finished but executable was not found: $builtExe"
    }

    $outputParent = [IO.Path]::GetDirectoryName($outputPath)
    [IO.Directory]::CreateDirectory($outputParent) | Out-Null
    $stagePath = Join-Path $outputParent (".xenolith-build-" + [guid]::NewGuid().ToString("N"))

    if ($ReleaseBundle) {
        if ([string]::IsNullOrWhiteSpace($Label)) {
            $Label = "v$(Get-Date -Format 'yyyyMMdd-HHmmss')-windows-x86_64"
        }

        $releaseArgs = @(
            "release",
            "--out",
            $stagePath,
            "--label",
            $Label
        )
        if ($AllowBudgetFail) {
            $releaseArgs += "--allow-budget-fail"
        }

        Invoke-Checked -FilePath $builtExe -Arguments $releaseArgs -WorkingDirectory $repoRoot
        $manifestPath = Join-Path $stagePath "manifest.json"
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if (@($manifest.artifacts).Count -eq 0) {
            throw "Release manifest has no artifacts"
        }
        $artifactNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($artifact in $manifest.artifacts) {
            $name = $artifact.name
            if ([string]::IsNullOrWhiteSpace($name) -or $name -match '[/\\:]' -or $name -in @(".", "..") -or -not $artifactNames.Add($name)) {
                throw "Invalid or repeated release artifact name: $name"
            }
            $artifactPath = Join-Path $stagePath $name
            $item = Get-Item -LiteralPath $artifactPath -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $artifact.bytes) {
                throw "Release artifact structure or length mismatch: $name"
            }
            $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -cne $artifact.sha256) {
                throw "Release artifact digest mismatch: $name"
            }
        }
        if (-not $artifactNames.Contains("xenolith.exe")) {
            throw "Release manifest does not include xenolith.exe"
        }
    }
    else {
        [IO.Directory]::CreateDirectory($stagePath) | Out-Null
        Copy-Item -LiteralPath $builtExe -Destination (Join-Path $stagePath "xenolith.exe")
    }

    $stagedExe = Join-Path $stagePath "xenolith.exe"
    $versionOutput = & $stagedExe --version
    if ($LASTEXITCODE -ne 0) {
        throw "Packaged executable version probe failed with exit code $LASTEXITCODE"
    }
    $version = ($versionOutput | Out-String).Trim()
    if ($version -notmatch '^xenolith \S+$') {
        throw "Unexpected packaged executable version: $version"
    }
    $exeHash = (Get-FileHash -LiteralPath $stagedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    "$exeHash *xenolith.exe" | Set-Content -LiteralPath (Join-Path $stagePath "xenolith.exe.sha256") -Encoding ascii
    $manifestHash = if ($ReleaseBundle) { (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { "" }

    # Directory.Move refuses a concurrent destination. Delete only an empty
    # existing directory at commit time, after every staged artifact is verified.
    Assert-EmptyOutput -Path $outputPath
    if (Test-Path -LiteralPath $outputPath) {
        [IO.Directory]::Delete($outputPath, $false)
    }
    [IO.Directory]::Move($stagePath, $outputPath)
    $stagePath = $null
    $packagedExe = Join-Path $outputPath "xenolith.exe"
    $hashFile = Join-Path $outputPath "xenolith.exe.sha256"
    Write-Host ""
    Write-Host "Built:   $packagedExe"
    Write-Host "Version: $version"
    Write-Host "SHA256:  $exeHash"
    Write-Host "Hash:    $hashFile"
    if ($ReleaseBundle) {
        $manifestPath = Join-Path $outputPath "manifest.json"
        Write-Host "Bundle:   $manifestPath"
        Write-Host "Manifest SHA256: $manifestHash"
    }
}
finally {
    if ($stagePath -and [IO.Directory]::Exists($stagePath)) {
        [IO.Directory]::Delete($stagePath, $true)
    }
    Pop-Location
}
