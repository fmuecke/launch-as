# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [string]$Account = 'AgentSandbox'
)

$caller = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent())
if ($caller.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this acceptance test from the authorised non-elevated user session.'
}

$launcher = Resolve-Path (Join-Path $PSScriptRoot '..\out\build\Release\launch-as.exe')
$cmd = (Get-Command cmd.exe -CommandType Application).Source
$workingDirectory = Join-Path $env:PUBLIC 'Documents'
if (-not (Test-Path -LiteralPath $workingDirectory -PathType Container)) {
    $workingDirectory = $env:PUBLIC
}

Write-Host "Launching cmd.exe as enrolled account $Account. The output must identify $Account and show a logon SID."
& $launcher.Path --user $Account --working-directory $workingDirectory --terminal -- `
    $cmd /d /c 'whoami & whoami /logonid'
if ($LASTEXITCODE -ne 0) {
    throw "Broker console launch failed with exit code $LASTEXITCODE."
}
