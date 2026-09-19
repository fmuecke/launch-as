# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "The Windows Sandbox integration runner does not exist: $Path"
}

$scriptText = Get-Content -LiteralPath $Path -Raw
$immutableRevision = '7b4d862ab00465b06028b11ee4981c48c398602a'
$expectedHash = 'B23495DFF238F65FDD69869BFD58481032BD3F9BA0A7E9D001EDF4444FB4C78C'

if ($scriptText -notmatch [regex]::Escape("/raw/$immutableRevision/WindowsSandboxTest.psm1")) {
    throw 'The Windows Sandbox helper must be downloaded from the pinned immutable revision.'
}
if ($scriptText -notmatch [regex]::Escape($expectedHash)) {
    throw 'The Windows Sandbox helper must be verified against its pinned SHA-256.'
}
if ($scriptText -notmatch 'Get-FileHash.*-Algorithm\s+SHA256') {
    throw 'The Windows Sandbox helper download must be SHA-256 verified before import.'
}
if ($scriptText -notmatch 'Invoke-WindowsSandboxTest') {
    throw 'The integration runner must execute through Invoke-WindowsSandboxTest.'
}
if ($scriptText -notmatch 'cmd\.exe /d /s /c') {
    throw 'The integration runner must execute each test through cmd.exe for file redirection.'
}
if ($scriptText -notmatch '>.+2>&1') {
    throw 'The integration runner must redirect guest stdout and stderr to the shared folder.'
}
if ($scriptText -notmatch 'Get-Content[^\r\n]+-Raw') {
    throw 'The integration runner must replay guest stdout and stderr from its shared result file.'
}
if ($scriptText -notmatch '\$execution\.ExitCode\s*-ne\s*0') {
    throw 'The integration runner must check the guest test command exit code.'
}
foreach ($successMarker in @(
        'Broker audit integration tests passed',
        'Broker account-provisioning integration tests passed',
        'Broker service-installer integration tests passed')) {
    if ($scriptText -notmatch [regex]::Escape($successMarker)) {
        throw "The integration runner must require the success marker: $successMarker"
    }
}
foreach ($artifact in @(
        'LauncherBrokerAuditTests.exe',
        'LauncherBrokerAccountProvisioningTests.exe',
        'LauncherBrokerServiceInstallerTests.exe',
        'launch-as-broker.exe')) {
    if ($scriptText -notmatch [regex]::Escape($artifact)) {
        throw "The integration runner must stage $artifact."
    }
}
