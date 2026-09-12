# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [Parameter()]
    [Alias('Test')]
    [switch] $RunTests,

    [Parameter()]
    [switch] $RunAllTests,

    [Parameter()]
    [switch] $RunElevatedTests,

    [Parameter()]
    [string] $ElevatedTestOutputPath,

    [Parameter()]
    [switch] $RunAcceptanceTest,

    [Parameter()]
    [string] $TargetUser = "LaunchAsUser"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$buildDirectory = Join-Path $projectRoot 'out\build'
$launcherPath = Join-Path `
    $buildDirectory `
    "$Configuration\launch-as.exe"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-CtestTests {
    param(
        [Parameter(Mandatory)]
        [string] $Description,

        [Parameter(Mandatory)]
        [string] $LabelOption,

        [Parameter(Mandatory)]
        [string] $LabelValue
    )

    Write-Host "Running $Description CTest tests ($Configuration)"
    & ctest `
        --test-dir $buildDirectory `
        -C $Configuration `
        $LabelOption $LabelValue `
        --output-on-failure
    if ($LASTEXITCODE -ne 0) {
        throw "CTest failed with exit code $LASTEXITCODE."
    }
}

function Invoke-ElevatedCtestTests {
    if (Test-IsAdministrator) {
        Invoke-CtestTests -Description 'all elevated' -LabelOption '--label-regex' -LabelValue 'elevated'
        return
    }

    Write-Host ""
    Write-Host 'Requesting UAC approval to run elevated CTest tests'
    $hostExecutable = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($hostExecutable)) {
        throw 'Could not determine the current PowerShell executable for the elevated test run.'
    }
    $elevatedTestOutputPath = Join-Path $buildDirectory "elevated-ctest-$Configuration.log"
    if (Test-Path -LiteralPath $elevatedTestOutputPath) {
        Remove-Item -LiteralPath $elevatedTestOutputPath -Force
    }
    $elevatedArguments = "-NoProfile -File `"$PSCommandPath`" -Configuration $Configuration -RunElevatedTests -ElevatedTestOutputPath `"$elevatedTestOutputPath`""
    try {
        $process = Start-Process -FilePath $hostExecutable -ArgumentList $elevatedArguments -Verb RunAs -Wait -PassThru -WorkingDirectory $projectRoot
    }
    catch {
        throw "Could not start elevated CTest tests: $($_.Exception.Message)"
    }
    if (Test-Path -LiteralPath $elevatedTestOutputPath) {
        Get-Content -LiteralPath $elevatedTestOutputPath
    }
    else {
        Write-Warning "Elevated CTest output was not captured: $elevatedTestOutputPath"
    }
    if ($process.ExitCode -ne 0) {
        throw "Elevated CTest tests failed with exit code $($process.ExitCode)."
    }
}

if ($RunElevatedTests) {
    if (-not (Test-IsAdministrator)) {
        throw '-RunElevatedTests must be run from an elevated PowerShell process.'
    }
    if (-not [string]::IsNullOrWhiteSpace($ElevatedTestOutputPath)) {
        $outputDirectory = Split-Path -Parent $ElevatedTestOutputPath
        if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
            $null = New-Item -ItemType Directory -Force -Path $outputDirectory
        }
    }
    $elevatedTestExitCode = 0
    try {
        if ([string]::IsNullOrWhiteSpace($ElevatedTestOutputPath)) {
            Invoke-CtestTests -Description 'all elevated' -LabelOption '--label-regex' -LabelValue 'elevated'
        }
        else {
            & {
                Invoke-CtestTests -Description 'all elevated' -LabelOption '--label-regex' -LabelValue 'elevated'
            } *>&1 | Out-File -LiteralPath $ElevatedTestOutputPath -Encoding utf8
        }
    }
    catch {
        if ([string]::IsNullOrWhiteSpace($ElevatedTestOutputPath)) {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        else {
            $_ | Out-File -LiteralPath $ElevatedTestOutputPath -Append -Encoding utf8
        }
        $elevatedTestExitCode = 1
    }
    if ($elevatedTestExitCode -ne 0) {
        exit $elevatedTestExitCode
    }
    return
}

$ninjaGenerator = 'Ninja Multi-Config'
if ($null -eq (Get-Command ninja -ErrorAction SilentlyContinue)) {
    throw 'Ninja was not found on PATH. Install Ninja and rerun build.ps1.'
}

if ([string]::IsNullOrWhiteSpace($env:INCLUDE)) {
    $vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vsWhere -PathType Leaf)) {
        throw 'Could not find Visual Studio. Install the MSVC C++ build tools and rerun build.ps1.'
    }

    $installationPath = & $vsWhere -latest -products '*' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $developerCommand = Join-Path $installationPath.Trim() 'Common7\Tools\VsDevCmd.bat'
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $developerCommand -PathType Leaf)) {
        throw 'Could not find Visual Studio MSVC x64 build tools.'
    }

    $environment = & cmd.exe /c "call `"$developerCommand`" -no_logo -arch=x64 -host_arch=x64 >nul && set"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not initialize the MSVC build environment (exit code $LASTEXITCODE)."
    }
    foreach ($entry in $environment) {
        $separator = $entry.IndexOf('=')
        if ($separator -gt 0) {
            Set-Item -LiteralPath "Env:$($entry.Substring(0, $separator))" `
                -Value $entry.Substring($separator + 1)
        }
    }
}

$nativeSourceRoots = @(
    (Join-Path $projectRoot 'src')
    (Join-Path $projectRoot 'tests')
)
$nativeSourceFiles = @(
    Get-ChildItem `
        -LiteralPath $nativeSourceRoots `
        -Recurse `
        -File |
    Where-Object { $_.Extension -in '.cpp', '.h', '.hpp' } |
    Sort-Object -Property FullName |
    ForEach-Object -MemberName FullName
)
$clangFormat = Get-Command -Name 'clang-format' -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $clangFormat) {
    Write-Warning 'clang-format was not found on PATH; continuing without formatting native C++ sources.'
}
else {
    Write-Host 'Formatting native C++ sources'
    & $clangFormat.Source -i -- @nativeSourceFiles
    if ($LASTEXITCODE -ne 0) {
        throw "clang-format failed with exit code $LASTEXITCODE."
    }
}

Write-Host "Configuring Ninja Multi-Config build in $buildDirectory"
& cmake -S $projectRoot -B $buildDirectory -G $ninjaGenerator
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed with exit code $LASTEXITCODE."
}

$buildDescription = 'all configured targets'
Write-Host "Building $buildDescription ($Configuration)"
$buildArguments = @(
    '--build'
    $buildDirectory
    '--config'
    $Configuration
)
& cmake @buildArguments
if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed with exit code $LASTEXITCODE."
}

if ($RunTests -or $RunAllTests) {
    Invoke-CtestTests -Description 'all non-elevated' -LabelOption '--label-exclude' -LabelValue 'elevated|interactive'
    $RunAcceptanceTest = $true;
}

if ($RunAllTests) {
    Invoke-ElevatedCtestTests
}

if ($RunAcceptanceTest) {
    if ([string]::IsNullOrWhiteSpace($TargetUser)) {
        throw '-TargetUser is required with -RunAcceptanceTest.'
    }

    Write-Host "Running interactive launcher acceptance test as .\$TargetUser"
    & (Join-Path `
            $projectRoot `
            'tests\Invoke-LauncherAcceptanceTest.ps1') `
        -TargetUser $TargetUser `
        -LauncherPath $launcherPath
}

Write-Host "Launcher ready: $launcherPath"
