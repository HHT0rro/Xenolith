[CmdletBinding()]
param(
    [string]$ScriptPath = "",
    [string]$TestRoot = (Join-Path ([IO.Path]::GetTempPath()) ("xenolith-build-exe-" + [guid]::NewGuid().ToString("N")))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $ScriptPath = Join-Path $PSScriptRoot "../scripts/build-exe.ps1"
}
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path
if (Test-Path -LiteralPath $TestRoot) {
    throw "Test directory already exists: $TestRoot"
}
New-Item -ItemType Directory -Path $TestRoot | Out-Null
$fixtureSource = Join-Path $TestRoot "Fixture.cs"
@'
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

class Fixture {
    static string Record(string path) {
        byte[] bytes = File.ReadAllBytes(path);
        string hash;
        using (var sha = SHA256.Create()) {
            hash = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }
        return "{\"name\":\"" + Path.GetFileName(path) + "\",\"bytes\":" + bytes.Length + ",\"sha256\":\"" + hash + "\"}";
    }

    static int Main(string[] args) {
        if (args.Length == 1 && args[0] == "--version") {
            if (Environment.GetEnvironmentVariable("XL_SCRIPT_FIXTURE_FAIL") == "version") return 9;
            if (Environment.GetEnvironmentVariable("XL_SCRIPT_FIXTURE_FAIL") == "race") {
                string destination = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)), "dist");
                Directory.CreateDirectory(destination);
                File.WriteAllText(Path.Combine(destination, "concurrent.txt"), "concurrent output");
            }
            Console.WriteLine("xenolith 0.1.0");
            return 0;
        }
        if (args.Length == 0 || args[0] != "release") return 2;
        string output = args[Array.IndexOf(args, "--out") + 1];
        if (Directory.Exists(output) && Directory.GetFileSystemEntries(output).Length != 0) {
            Console.Error.WriteLine("release output directory is not empty");
            return 3;
        }
        Directory.CreateDirectory(output);
        string payload = Path.Combine(output, "payload.txt");
        File.WriteAllText(payload, "owned harmless release fixture");
        if (Environment.GetEnvironmentVariable("XL_SCRIPT_FIXTURE_FAIL") == "release") return 7;
        string executable = Path.Combine(output, "xenolith.exe");
        File.Copy(Assembly.GetExecutingAssembly().Location, executable);
        string digest = Environment.GetEnvironmentVariable("XL_SCRIPT_FIXTURE_FAIL") == "manifest"
            ? "{\"name\":\"payload.txt\",\"bytes\":0,\"sha256\":\"invalid\"}"
            : Record(payload);
        File.WriteAllText(Path.Combine(output, "manifest.json"), "{\"artifacts\":[" + Record(executable) + "," + digest + "]}");
        return 0;
    }
}
'@ | Set-Content -LiteralPath $fixtureSource -Encoding utf8
$fixtureExe = Join-Path $TestRoot "Fixture.exe"
$compiler = Join-Path $env:WINDIR "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
& $compiler /nologo /target:exe ("/out:" + $fixtureExe) $fixtureSource
if ($LASTEXITCODE -ne 0) { throw "Fixture compilation failed" }

# The build wrapper runs normally. Cargo is replaced by a successful build of
# the owned executable so publication failures can be tested without compiling Rust.
function cargo {
    if ($args[0] -eq "metadata") {
        @{ target_directory = $fixtureTarget } | ConvertTo-Json -Compress
    }
    $global:LASTEXITCODE = 0
}

$cases = @(
    @{ name = "existing-output"; old = $true; bundle = $false; failure = ""; external = $false },
    @{ name = "existing-bundle"; old = $true; bundle = $true; failure = ""; external = $false },
    @{ name = "normal-success"; old = $false; bundle = $false; failure = ""; external = $false },
    @{ name = "bundle-success"; old = $false; bundle = $true; failure = ""; external = $false },
    @{ name = "bundle-failure"; old = $false; bundle = $true; failure = "release"; external = $false },
    @{ name = "version-failure"; old = $false; bundle = $false; failure = "version"; external = $false },
    @{ name = "invalid-manifest"; old = $false; bundle = $true; failure = "manifest"; external = $false },
    @{ name = "external-target"; old = $false; bundle = $false; failure = ""; external = $true },
    @{ name = "empty-output-trailing-separator"; old = $false; bundle = $true; failure = ""; external = $false },
    @{ name = "concurrent-output"; old = $false; bundle = $false; failure = "race"; external = $false },
    @{ name = "junction-parent"; old = $false; bundle = $false; failure = "junction"; external = $false }
)
$previousFailure = $env:XL_SCRIPT_FIXTURE_FAIL
$results = @()
try {
    foreach ($case in $cases) {
        $caseRoot = Join-Path $TestRoot $case.name
        $scripts = Join-Path $caseRoot "scripts"
        New-Item -ItemType Directory -Path $scripts -Force | Out-Null
        $buildScript = Join-Path $scripts "build-exe.ps1"
        Copy-Item -LiteralPath $ScriptPath -Destination $buildScript
        $fixtureTarget = if ($case.external) { Join-Path $TestRoot "external-target-output" } else { Join-Path $caseRoot "target" }
        $releaseDirectory = Join-Path $fixtureTarget "release"
        New-Item -ItemType Directory -Path $releaseDirectory -Force | Out-Null
        Copy-Item -LiteralPath $fixtureExe -Destination (Join-Path $releaseDirectory "xenolith.exe")
        $destination = Join-Path $caseRoot "dist"
        if ($case.name -eq "empty-output-trailing-separator") {
            New-Item -ItemType Directory -Path $destination | Out-Null
            $destination += [IO.Path]::DirectorySeparatorChar
        }
        if ($case.failure -eq "junction") {
            $realParent = Join-Path $caseRoot "real-parent"
            New-Item -ItemType Directory -Path $realParent | Out-Null
            $linkedParent = Join-Path $caseRoot "linked-parent"
            New-Item -ItemType Junction -Path $linkedParent -Target $realParent | Out-Null
            $destination = Join-Path $linkedParent "dist"
        }
        $oldHashes = @{}
        if ($case.old) {
            New-Item -ItemType Directory -Path $destination | Out-Null
            foreach ($name in @("xenolith.exe", "xenolith.exe.sha256", "manifest.json", "user.txt")) {
                $oldPath = Join-Path $destination $name
                [IO.File]::WriteAllText($oldPath, "old artifact " + $name)
                $oldHashes[$name] = (Get-FileHash -LiteralPath $oldPath -Algorithm SHA256).Hash
            }
        }
        $env:XL_SCRIPT_FIXTURE_FAIL = $case.failure
        $invocationError = $null
        try {
            & $buildScript -OutputDir $destination -ReleaseBundle:$case.bundle *>&1 |
                Out-File -LiteralPath (Join-Path $caseRoot "invocation.log") -Encoding utf8
        }
        catch { $invocationError = $_.Exception.Message }
        $expectedFailure = $case.old -or $case.failure -ne ""
        $passed = ($null -ne $invocationError) -eq $expectedFailure
        if ($case.failure -eq "release") { $passed = $passed -and $invocationError -match 'exit code 7' }
        if ($case.failure -eq "version") { $passed = $passed -and $invocationError -match 'exit code 9' }
        if ($case.failure -eq "manifest") { $passed = $passed -and $invocationError -match 'mismatch' }
        if ($case.failure -eq "race") { $passed = $passed -and $invocationError -match 'not empty' }
        if ($case.failure -eq "junction") { $passed = $passed -and $invocationError -match 'reparse point' }
        if ($case.old) {
            foreach ($name in $oldHashes.Keys) {
                $path = Join-Path $destination $name
                $passed = $passed -and (Test-Path -LiteralPath $path -PathType Leaf)
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    $passed = $passed -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $oldHashes[$name]
                }
            }
            $passed = $passed -and @(Get-ChildItem -LiteralPath $destination -Force).Count -eq $oldHashes.Count
        }
        elseif ($case.failure -eq "race") {
            $concurrentFile = Join-Path $destination "concurrent.txt"
            $passed = $passed -and (Test-Path -LiteralPath $concurrentFile)
            if (Test-Path -LiteralPath $concurrentFile) {
                $passed = $passed -and (Get-Content -LiteralPath $concurrentFile -Raw) -ceq "concurrent output"
            }
            $passed = $passed -and @(Get-ChildItem -LiteralPath $destination -Force).Count -eq 1
        }
        elseif ($expectedFailure) {
            $passed = $passed -and (-not (Test-Path -LiteralPath $destination))
        }
        else {
            $packaged = Join-Path $destination "xenolith.exe"
            $passed = $passed -and (Test-Path -LiteralPath $packaged -PathType Leaf)
            if (Test-Path -LiteralPath $packaged -PathType Leaf) {
                $hash = (Get-FileHash -LiteralPath $packaged -Algorithm SHA256).Hash.ToLowerInvariant()
                $passed = $passed -and (Get-Content -LiteralPath (Join-Path $destination "xenolith.exe.sha256") -Raw).Trim() -ceq "$hash *xenolith.exe"
            }
            if ($case.bundle) {
                $passed = $passed -and (Test-Path -LiteralPath (Join-Path $destination "manifest.json") -PathType Leaf)
            }
        }
        $passed = $passed -and @(Get-ChildItem -LiteralPath $caseRoot -Directory -Filter ".xenolith-build-*" -Force).Count -eq 0
        $results += [pscustomobject]@{ case = $case.name; passed = $passed; expected_failure = $expectedFailure; error = $invocationError }
    }
}
finally { $env:XL_SCRIPT_FIXTURE_FAIL = $previousFailure }
$results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $TestRoot "results.json") -Encoding utf8
$results | Format-Table -AutoSize
Write-Host "Evidence directory $TestRoot"
if (@($results | Where-Object { -not $_.passed }).Count -gt 0) { exit 1 }
