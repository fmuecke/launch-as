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
    [string] $TargetUser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$buildDirectory = Join-Path $projectRoot 'out\build'
$launcherPath = Join-Path `
    $buildDirectory `
    "$Configuration\launch-as.exe"

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

Write-Host "Configuring x64 build in $buildDirectory"
& cmake -S $projectRoot -B $buildDirectory -A x64
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed with exit code $LASTEXITCODE."
}

$buildDescription = if ($RunTests) {
    'launch-as and test targets'
}
else {
    'launch-as'
}
Write-Host "Building $buildDescription ($Configuration)"
$buildArguments = @(
    '--build'
    $buildDirectory
    '--config'
    $Configuration
)
if (-not $RunTests) {
    $buildArguments += @('--target', 'launch_as')
}
& cmake @buildArguments
if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed with exit code $LASTEXITCODE."
}

if ($RunTests) {
    Write-Host "Running unattended launcher tests ($Configuration)"
    & ctest `
        --test-dir $buildDirectory `
        -C $Configuration `
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
