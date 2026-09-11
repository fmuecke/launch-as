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
$installIndex = $body.IndexOf('& $admin install', [StringComparison]::Ordinal)
$installFailureIndex = $body.IndexOf('if ($LASTEXITCODE -ne 0)', [StringComparison]::Ordinal)
$enrollIndex = $body.IndexOf(
    '& $admin enroll $DefaultAccount --force', [StringComparison]::Ordinal)

if ($installIndex -lt 0) {
    throw 'The setup update branch does not install the broker.'
}
if ($installFailureIndex -lt $installIndex -or $installFailureIndex -gt $enrollIndex) {
    throw 'The setup update branch does not stop before enrollment when installation fails.'
}
if ($enrollIndex -lt $installIndex) {
    throw 'The setup update branch does not re-enroll the default account after installation.'
}
if ($body -notmatch 're-enroll default account ''\$DefaultAccount''') {
    throw 'The setup update confirmation does not disclose re-enrollment.'
}
if ($body -notmatch 'replacing its broker-owned password') {
    throw 'The setup update confirmation does not disclose password replacement.'
}
