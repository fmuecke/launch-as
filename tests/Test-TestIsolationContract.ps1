# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $CMakePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $AcceptanceScriptDirectory,
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cmakeText = Get-Content -LiteralPath $CMakePath -Raw
foreach ($target in @(
        'LauncherBrokerAuditTests',
        'LauncherBrokerAccountProvisioningTests',
        'LauncherBrokerServiceInstallerTests')) {
    if ($cmakeText -notmatch "add_executable\(\s*$target") {
        throw "The Sandbox runner still needs build target $target."
    }
}
foreach ($testName in @(
        'launcher.broker_audit',
        'launcher.broker_account_provisioning',
        'launcher.broker_service_installer')) {
    if ($cmakeText -match "add_test\(\s*NAME\s+$([regex]::Escape($testName))") {
        throw "$testName must not be registered for ordinary host CTest runs."
    }
}

foreach ($name in @(
        'Invoke-BrokerConsoleAcceptanceTest.ps1',
        'Invoke-BrokerProbeAcceptanceTest.ps1',
        'Invoke-BrokerSameAccountConcurrencyTest.ps1')) {
    $path = Join-Path $AcceptanceScriptDirectory $name
    $scriptText = Get-Content -LiteralPath $path -Raw
    if ($scriptText -match '\$Account\s*=\s*[''\"]LaunchAsUser[''\"]') {
        throw "$path must require an explicit acceptance account."
    }
}