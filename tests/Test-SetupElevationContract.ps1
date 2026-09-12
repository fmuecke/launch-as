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
if ($scriptText -notmatch "\[ValidatePattern\('" -or
    $scriptText -notmatch 'Join-Path \$PSHOME ''pwsh\.exe''') {
    throw 'The setup relaunch must validate the account name and use pwsh.exe from $PSHOME.'
}
if ($scriptText -match '\$arguments\s*=\s*@\(' -or
    $scriptText -match 'Get-Command pwsh') {
    throw 'The setup relaunch must not use an unquoted argument array or resolve pwsh through PATH.'
}
if ($scriptText -notmatch '-File `"\$PSCommandPath`"' -or
    $scriptText -notmatch '-DefaultAccount `"\$DefaultAccount`"') {
    throw 'The setup relaunch must quote both the script path and default account.'
}

& (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $Path -DefaultAccount 'invalid/account'
if ($LASTEXITCODE -eq 0) {
    throw 'The setup script accepted an invalid default account name.'
}
