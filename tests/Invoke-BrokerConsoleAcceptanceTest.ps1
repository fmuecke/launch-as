# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [string]$Account = 'AgentSandbox',
    [ValidateRange(0, [int]::MaxValue)]
    [int]$ExpectedExitCode = 0
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
$output = & $launcher.Path --user $Account --working-directory $workingDirectory --terminal -- `
    $cmd /d /c "whoami & whoami /logonid & exit $ExpectedExitCode"
$exitCode = $LASTEXITCODE
$output | Write-Host

$accountPattern = '(?im)^.+\\' + [regex]::Escape($Account) + '\s*$'
if (-not ($output -match $accountPattern)) {
    throw "Broker console output did not identify the enrolled account $Account."
}
if (-not ($output -match '(?m)^S-1-5-5-\d+-\d+\s*$')) {
    throw 'Broker console output did not include a logon SID.'
}
if ($exitCode -ne $ExpectedExitCode) {
    throw "Broker console launch returned exit code $exitCode; expected $ExpectedExitCode."
}
