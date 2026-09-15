# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Interactive', 'Install', 'Update', 'Uninstall')]
    [string] $Command = 'Interactive',

    [Parameter()]
    # This value is embedded in the elevated relaunch command line; reject quoting/control
    # characters and keep it aligned with the broker's local-account-name grammar.
    [ValidatePattern('^[^\\/\[\]:;|=,+*?<>"\x00-\x1F]{1,20}$')]
    [string] $DefaultAccount = 'LaunchAsUser',

    [Parameter()]
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$exitCancelled = 1223 # ERROR_CANCELLED

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Action {
    param([Parameter(Mandatory)][string] $Prompt)

    if ($Force) {
        return $true
    }
    return (Read-Host "$Prompt [y/N]") -match '^(?i)y(?:es)?$'
}

function Get-LaunchAsExecutable {
    $packageLauncher = Join-Path $PSScriptRoot 'launch-as.exe'
    $buildLauncher = Join-Path $PSScriptRoot 'out\build\Release\launch-as.exe'
    if (Test-Path -LiteralPath $packageLauncher -PathType Leaf) {
        return $packageLauncher
    }
    if (Test-Path -LiteralPath $buildLauncher -PathType Leaf) {
        return $buildLauncher
    }
    throw "launch-as.exe was not found beside the script or at $buildLauncher. Extract the binary package or run .\build.ps1 first."
}

function Get-InstalledLaunchAsExecutable {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    return Join-Path $programFiles 'launch-as\launch-as.exe'
}

function Get-SemanticVersion {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "Could not read a product version from $Path."
    }
    try {
        return [System.Management.Automation.SemanticVersion]::Parse($version)
    }
    catch {
        throw "Product version '$version' in $Path is not valid SemVer."
    }
}

function Assert-NotDowngrade {
    $installedLauncher = Get-InstalledLaunchAsExecutable
    if (-not (Test-Path -LiteralPath $installedLauncher -PathType Leaf)) {
        return
    }

    $candidateLauncher = Get-LaunchAsExecutable
    $installedVersion = Get-SemanticVersion -Path $installedLauncher
    $candidateVersion = Get-SemanticVersion -Path $candidateLauncher
    if ($candidateVersion.CompareTo($installedVersion) -lt 0) {
        throw "Refusing to downgrade launch-as from $installedVersion to $candidateVersion."
    }
    if ($candidateVersion.CompareTo($installedVersion) -eq 0) {
        Write-Host "Reinstalling launch-as $candidateVersion."
    }
    else {
        Write-Host "Updating launch-as from $installedVersion to $candidateVersion."
    }
}

if (-not (Test-Administrator)) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" " +
    "-Command `"$Command`" -DefaultAccount `"$DefaultAccount`""
    if ($Force) {
        $arguments += ' -Force'
    }
    $powerShell = Join-Path $PSHOME 'pwsh.exe'
    if (-not (Test-Path -LiteralPath $powerShell -PathType Leaf)) {
        throw "PowerShell 7 executable not found at $powerShell."
    }
    $process = Start-Process -FilePath $powerShell `
        -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    $exitCode = $process.ExitCode
    if ($exitCode -eq 0) {
        Write-Host 'Elevated setup completed successfully (exit code 0).' -ForegroundColor Green
    }
    elseif ($exitCode -eq $exitCancelled) {
        Write-Host "Elevated setup was cancelled (exit code $exitCancelled)." -ForegroundColor Yellow
    }
    else {
        Write-Host "Elevated setup failed (exit code $exitCode)." -ForegroundColor Red
    }
    exit $exitCode
}

$packageAdmin = Join-Path $PSScriptRoot 'launch-as-admin.exe'
$buildAdmin = Join-Path $PSScriptRoot 'out\build\Release\launch-as-admin.exe'
$admin = if (Test-Path -LiteralPath $packageAdmin -PathType Leaf) {
    $packageAdmin
}
elseif (Test-Path -LiteralPath $buildAdmin -PathType Leaf) {
    $buildAdmin
}
else {
    throw "Administrator executable not found beside the script or at $buildAdmin. Extract the binary package or run .\build.ps1 first."
}

$service = Get-Service -Name 'launch-as-broker' -ErrorAction SilentlyContinue
if ($Command -eq 'Interactive') {
    if ($null -eq $service) {
        $Command = 'Install'
    }
    else {
        Write-Host "Existing launch-as-broker service detected ($($service.Status))."
        $Command = if ($Force) { 'Update' } else { Read-Host 'Choose update, uninstall, or cancel' }
    }
}

switch ($Command.ToLowerInvariant()) {
    'install' {
        if ($null -ne $service) {
            throw 'launch-as-broker is already installed. Use -Command Update or -Command Uninstall.'
        }
        Assert-NotDowngrade
        if (-not (Confirm-Action 'Install launch-as-broker and the launch-as command-line tools; authorize the current user to launch managed accounts')) {
            exit $exitCancelled
        }
        & $admin install
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
        if (Confirm-Action "Create default launch-as account '$DefaultAccount'") {
            & $admin create $DefaultAccount
            exit $LASTEXITCODE
        }
        Write-Host 'Broker installation completed, but account creation was cancelled.' -ForegroundColor Yellow
        exit $exitCancelled
    }
    'update' {
        if ($null -eq $service) {
            throw 'launch-as-broker is not installed. Use -Command Install.'
        }
        Assert-NotDowngrade
        $updatePrompt = "Update the broker and command-line tools, stop any active broker sessions, and take over default account '$DefaultAccount' (replacing its broker-owned password)"
        if (-not (Confirm-Action $updatePrompt)) {
            exit $exitCancelled
        }
        & $admin install
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
        & $admin create $DefaultAccount --takeover --force
        exit $LASTEXITCODE
    }
    'uninstall' {
        if ($null -eq $service) {
            Write-Host 'launch-as-broker is not installed; removing any residual launch-as artifacts.' `
                -ForegroundColor Yellow
        }
        if (-not (Confirm-Action 'Uninstall the broker service and all installed launch-as executables')) {
            exit $exitCancelled
        }
        & $admin uninstall --force
        exit $LASTEXITCODE
    }
    default {
        exit $exitCancelled
    }
}
