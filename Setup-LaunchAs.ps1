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
    exit $process.ExitCode
}

$admin = Join-Path $PSScriptRoot 'out\build\Release\launch-as-admin.exe'
if (-not (Test-Path -LiteralPath $admin -PathType Leaf)) {
    throw "Administrator executable not found: $admin. Run .\build.ps1 first."
}

$service = Get-Service -Name 'launch-as-broker' -ErrorAction SilentlyContinue
if ($null -eq $service) {
    if (-not (Confirm-Action 'Install launch-as-broker')) {
        return
    }
    & $admin install
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    if (Confirm-Action "Enroll default account '$DefaultAccount'") {
        & $admin enroll $DefaultAccount --force
        exit $LASTEXITCODE
    }
    return
}

Write-Host "Existing launch-as-broker service detected ($($service.Status))."
$choice = if ($Force) { 'update' } else { Read-Host 'Choose update, uninstall, or cancel' }
switch ($choice.ToLowerInvariant()) {
    'update' {
        if (-not (Confirm-Action 'Update the broker and stop any active broker sessions')) {
            return
        }
        & $admin install
        exit $LASTEXITCODE
    }
    'uninstall' {
        if (-not (Confirm-Action 'Uninstall the broker service and its installed binaries')) {
            return
        }
        & $admin uninstall --force
        exit $LASTEXITCODE
    }
    default {
        return
    }
}
