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
$probe = Resolve-Path (Join-Path $PSScriptRoot '..\out\build\Release\LauncherBrokerChildIdentityProbe.exe')
$workingDirectory = Join-Path $env:PUBLIC 'Documents'
if (-not (Test-Path -LiteralPath $workingDirectory -PathType Container)) {
    $workingDirectory = $env:PUBLIC
}

${interactiveWindow} = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 } |
    Select-Object -First 1
if ($null -eq $interactiveWindow) {
    throw 'Open a normal desktop window, then run this test from the authorised non-elevated session.'
}
$interactiveLogonSid = (& whoami /logonid | Select-Object -Last 1).Trim()
if ($interactiveLogonSid -notmatch '^S-1-5-5-\d+-\d+$') {
    throw "Could not determine the interactive user's logon SID: $interactiveLogonSid"
}
$windowHandle = [uint64]$interactiveWindow.MainWindowHandle.ToInt64()

Write-Host "Launching the identity probe as enrolled account $Account. It must report a different logon SID and not access this interactive process or enumerate its window."
$output = & $launcher.Path --user $Account --working-directory $workingDirectory --terminal -- `
    $probe.Path --window $windowHandle --process $PID --exit-code $ExpectedExitCode
$exitCode = $LASTEXITCODE
$output | Write-Host
$outputText = $output -join [Environment]::NewLine

$childLogonSid = [regex]::Match($outputText, '(?i)logonSid\s*=\s*(S-1-5-5-\d+-\d+)').Groups[1].Value
if ($outputText -notmatch ('(?i)account\s*=\s*' + [regex]::Escape($Account))) {
    throw "Broker console output did not identify the enrolled account $Account."
}
if ([string]::IsNullOrWhiteSpace($childLogonSid)) {
    throw 'Broker console output did not include the child logon SID.'
}
if ($childLogonSid -eq $interactiveLogonSid) {
    throw 'The broker child reused the interactive user logon SID.'
}
if ($outputText -notmatch '(?i)interactiveWindowVisible\s*=\s*false') {
    throw "The broker child enumerated interactive window $($interactiveWindow.Id)."
}
if ($outputText -notmatch '(?i)interactiveProcessVmReadDenied\s*=\s*true') {
    throw 'The broker child could read the interactive PowerShell process.'
}
if ($outputText -notmatch '(?i)interactiveProcessTerminateDenied\s*=\s*true') {
    throw 'The broker child could terminate the interactive PowerShell process.'
}
if ($exitCode -ne $ExpectedExitCode) {
    throw "Broker console launch returned exit code $exitCode; expected $ExpectedExitCode."
}
