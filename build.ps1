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

Write-Host 'Formatting native C++ sources'
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
& clang-format -i -- @nativeSourceFiles
if ($LASTEXITCODE -ne 0) {
    throw "clang-format failed with exit code $LASTEXITCODE."
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

if ($RunTests) {
    Write-Host "Running all non-elevated CTest tests ($Configuration)"
    & ctest `
        --test-dir $buildDirectory `
        -C $Configuration `
        --label-exclude 'elevated|interactive' `
        --output-on-failure
    if ($LASTEXITCODE -ne 0) {
        throw "CTest failed with exit code $LASTEXITCODE."
    }
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
