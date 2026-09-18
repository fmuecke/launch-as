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
    [switch] $RunSandboxTests,

    [Parameter()]
    [switch] $RunElevatedTests,

    [Parameter()]
    [string] $ElevatedTestOutputPath,

    [Parameter()]
    [switch] $RunAcceptanceTest,

    [Parameter()]
    [switch] $PackageRelease,

    [Parameter()]
    [string] $TargetUser = "LaunchAsUser"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$outputDirectory = Join-Path $projectRoot 'out'
$buildDirectory = Join-Path $outputDirectory 'build'
$releaseVersion = $null
$releaseDirectory = $null
$releaseStagingDirectory = $null
$releaseArchivePath = $null

function Remove-ManagedOutputDirectory {
    param([Parameter(Mandatory)][string] $Path)

    $resolvedOutputDirectory = [IO.Path]::GetFullPath($outputDirectory)
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    if (-not $resolvedPath.StartsWith($resolvedOutputDirectory + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a directory outside ${resolvedOutputDirectory}: $resolvedPath"
    }
    if (Test-Path -LiteralPath $resolvedPath) {
        Remove-Item -LiteralPath $resolvedPath -Recurse -Force
    }
}

function Get-ReleaseVersion {
    $cmakePath = Join-Path $projectRoot 'CMakeLists.txt'
    $cmakeText = Get-Content -LiteralPath $cmakePath -Raw
    $versionMatch = [regex]::Match($cmakeText, '(?ms)project\(.*?VERSION\s+(?<version>\d+\.\d+\.\d+)')
    if (-not $versionMatch.Success) {
        throw "Could not determine the project version from $cmakePath."
    }
    return "$($versionMatch.Groups['version'].Value)" # add "-preview" for preview releases
}

if ($PackageRelease) {
    $releaseVersion = Get-ReleaseVersion
    $buildDirectory = Join-Path $outputDirectory 'release-build'
    $releaseDirectory = Join-Path $outputDirectory 'release'
    $packageName = "launch-as-v$releaseVersion-win64"
    $releaseStagingDirectory = Join-Path $releaseDirectory $packageName
    $releaseArchivePath = Join-Path $outputDirectory "$packageName.zip"
    Remove-ManagedOutputDirectory $buildDirectory
    Remove-ManagedOutputDirectory $releaseStagingDirectory
    if (Test-Path -LiteralPath $releaseArchivePath) {
        Remove-Item -LiteralPath $releaseArchivePath -Force
    }
}

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

function Invoke-WindowsSandboxIntegrationTests {
    & (Join-Path $projectRoot 'tests\Invoke-BrokerIntegrationInWindowsSandbox.ps1') `
        -BuildDirectory $buildDirectory `
        -Configuration $Configuration
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
}

if ($RunAllTests) {
    Invoke-WindowsSandboxIntegrationTests
}
elseif ($RunSandboxTests) {
    Invoke-WindowsSandboxIntegrationTests
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

if ($PackageRelease) {
    $null = New-Item -ItemType Directory -Force -Path $releaseStagingDirectory
    $releaseFiles = @(
        'launch-as.exe'
        'launch-as-admin.exe'
        'launch-as-broker.exe'
        'launch-as-conhost.exe'
    )
    foreach ($releaseFile in $releaseFiles) {
        $sourcePath = Join-Path $buildDirectory "$Configuration\$releaseFile"
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "Release build did not produce $sourcePath."
        }
        Copy-Item -LiteralPath $sourcePath -Destination $releaseStagingDirectory
    }
    foreach ($documentationFile in @('Setup-LaunchAs.ps1', 'README.md', 'CHANGELOG.md', 'LICENSE')) {
        Copy-Item -LiteralPath (Join-Path $projectRoot $documentationFile) `
            -Destination $releaseStagingDirectory
    }
    $archiveInputs = Get-ChildItem -LiteralPath $releaseStagingDirectory -File |
    Sort-Object -Property Name |
    ForEach-Object -MemberName FullName
    Compress-Archive -Path $archiveInputs -DestinationPath $releaseArchivePath -CompressionLevel Optimal -Force
    Remove-ManagedOutputDirectory $releaseStagingDirectory
    Write-Host "Release package ready: $releaseArchivePath"
}

Write-Host "Launcher ready: $launcherPath"
