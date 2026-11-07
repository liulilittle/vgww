<#
.SYNOPSIS
    Runs the VGWW unit tests under Application Verifier (Heaps, Handles,
    Locks) and exports one XML log per test executable.

.DESCRIPTION
    Prerequisites:
      * Application Verifier installed (standalone download; the default
        location is %windir%\System32\appverif.exe).
      * An ELEVATED PowerShell: AppVerifier persists per-image settings in
        HKLM and needs to write them.
    The script enables the three verifier layers for every test_*.exe in the
    build output, runs ctest, exports the verifier log as XML and (unless
    -KeepSettings) removes the settings again.

.PARAMETER DryRun
    Prints every appverif/ctest command line without executing anything.
    Use it to validate the script in environments without AppVerifier.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\appverifier.ps1
    powershell -ExecutionPolicy Bypass -File scripts\appverifier.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string]$BuildDir = "",
    [string]$Config = "Release",
    [string]$LogDir = "",
    [string]$AppVerif = "$env:windir\System32\appverif.exe",
    [string]$Ctest = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe",
    [switch]$KeepSettings,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# $PSScriptRoot is not yet populated while [CmdletBinding()] param defaults
# are evaluated on Windows PowerShell 5.1, so the default is resolved here.
if ([string]::IsNullOrEmpty($BuildDir)) {
    $BuildDir = Join-Path $PSScriptRoot "..\build_v2"
}

$BuildDir = (Resolve-Path -LiteralPath $BuildDir).Path
$testDir = Join-Path $BuildDir $Config
if ([string]::IsNullOrEmpty($LogDir)) {
    $LogDir = Join-Path $BuildDir "appverifier-logs"
}

$exes = @(Get-ChildItem -LiteralPath $testDir -Filter "test_*.exe" -File)
if ($exes.Count -eq 0) {
    throw "No test executables under '$testDir' (build first)."
}
if (-not $DryRun) {
    if (-not (Test-Path -LiteralPath $AppVerif)) {
        throw ("appverif.exe not found at '$AppVerif'. Install Application " +
               "Verifier and pass -AppVerif <path>.")
    }
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}

function Invoke-Tool([string]$exe, [string[]]$arguments) {
    Write-Host ">> $exe $($arguments -join ' ')"
    if ($DryRun) { return 0 }
    & $exe @arguments
    return $LASTEXITCODE
}

foreach ($exe in $exes) {
    [void](Invoke-Tool $AppVerif @("-enable", "Heaps", "Handles", "Locks",
                                   "-for", $exe.Name))
}
[void](Invoke-Tool $AppVerif @("-logtofile", "enable"))

$ctestExit = 0
try {
    $ctestExit = Invoke-Tool $Ctest @("--test-dir", $BuildDir, "-C", $Config,
                                      "--output-on-failure")
}
finally {
    foreach ($exe in $exes) {
        $xml = Join-Path $LogDir ($exe.BaseName + ".xml")
        [void](Invoke-Tool $AppVerif @("-export", "log", "-for", $exe.Name,
                                       "-with", "to=$xml"))
        if (-not $KeepSettings) {
            [void](Invoke-Tool $AppVerif @("-disable", "*", "-for", $exe.Name))
        }
    }
    [void](Invoke-Tool $AppVerif @("-logtofile", "disable"))
}
exit $ctestExit
