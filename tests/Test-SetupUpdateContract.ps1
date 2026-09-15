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

$scriptText = Get-Content -LiteralPath $Path -Raw
$updateClause = [regex]::Match(
    $scriptText,
    "(?ms)^\s*'update'\s*\{(?<body>.*?)^\s*\}\s*^\s*'uninstall'\s*\{")
if (-not $updateClause.Success) {
    throw 'Could not find the setup update branch.'
}

$body = $updateClause.Groups['body'].Value
$versionCheckIndex = $body.IndexOf('Assert-NotDowngrade', [StringComparison]::Ordinal)
$installIndex = $body.IndexOf('& $admin install', [StringComparison]::Ordinal)
$installFailureIndex = $body.IndexOf('if ($LASTEXITCODE -ne 0)', [StringComparison]::Ordinal)
$takeoverIndex = $body.IndexOf(
    '& $admin create $DefaultAccount --takeover', [StringComparison]::Ordinal)

if ($installIndex -lt 0) {
    throw 'The setup update branch does not install the broker.'
}
if ($versionCheckIndex -lt 0 -or $versionCheckIndex -gt $installIndex) {
    throw 'The setup update branch must reject a downgrade before installation.'
}
if ($installFailureIndex -lt $installIndex -or $installFailureIndex -gt $takeoverIndex) {
    throw 'The setup update branch does not stop before takeover when installation fails.'
}
if ($takeoverIndex -lt $installIndex) {
    throw 'The setup update branch does not retake over the default account after installation.'
}
if ($body -notmatch '& \$admin create \$DefaultAccount --takeover --force') {
    throw 'The setup update branch must force-enable a disabled default account.'
}
if ($body -notmatch 'take over default account ''\$DefaultAccount''') {
    throw 'The setup update confirmation does not disclose takeover.'
}
if ($body -notmatch 'replacing its broker-owned password') {
    throw 'The setup update confirmation does not disclose password replacement.'
}
if ($scriptText -notmatch "\[ValidateSet\('Interactive', 'Install', 'Update', 'Uninstall'\)\]") {
    throw 'The setup script must expose explicit command-line actions.'
}
if ($scriptText -notmatch '\[System\.Management\.Automation\.SemanticVersion\]::Parse') {
    throw 'The setup script must compare file versions with a SemVer parser.'
}
if ($scriptText -notmatch 'Refusing to downgrade launch-as') {
    throw 'The setup script must reject downgrade attempts.'
}
