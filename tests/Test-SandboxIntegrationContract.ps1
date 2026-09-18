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
foreach ($artifact in @(
        'LauncherBrokerAuditTests.exe',
        'LauncherBrokerAccountProvisioningTests.exe',
        'LauncherBrokerServiceInstallerTests.exe',
        'launch-as-broker.exe')) {
    if ($scriptText -notmatch [regex]::Escape($artifact)) {
        throw "The integration runner must stage $artifact."
    }
}
