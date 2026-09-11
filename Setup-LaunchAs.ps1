# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
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

if (-not (Test-Administrator)) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
        '-DefaultAccount', $DefaultAccount)
    if ($Force) {
        $arguments += '-Force'
    }
    $process = Start-Process -FilePath (Get-Command pwsh -ErrorAction Stop).Source `
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
if ($null -eq $service) {
    if (-not (Confirm-Action 'Install launch-as-broker')) {
        exit $exitCancelled
    }
    & $admin install
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    if (Confirm-Action "Enroll default account '$DefaultAccount'") {
        & $admin enroll $DefaultAccount --force
        exit $LASTEXITCODE
    }
    Write-Host 'Broker installation completed, but account enrollment was cancelled.' -ForegroundColor Yellow
    exit $exitCancelled
}

Write-Host "Existing launch-as-broker service detected ($($service.Status))."
$choice = if ($Force) { 'update' } else { Read-Host 'Choose update, uninstall, or cancel' }
switch ($choice.ToLowerInvariant()) {
    'update' {
        $updatePrompt = "Update the broker, stop any active broker sessions, and re-enroll default account '$DefaultAccount' (replacing its broker-owned password)"
        if (-not (Confirm-Action $updatePrompt)) {
            exit $exitCancelled
        }
        & $admin install
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
        & $admin enroll $DefaultAccount --force
        exit $LASTEXITCODE
    }
    'uninstall' {
        if (-not (Confirm-Action 'Uninstall the broker service and its installed binaries')) {
            exit $exitCancelled
        }
        & $admin uninstall --force
        exit $LASTEXITCODE
    }
    default {
        exit $exitCancelled
    }
}
