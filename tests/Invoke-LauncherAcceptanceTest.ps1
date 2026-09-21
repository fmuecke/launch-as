# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as
# Runs the broker acceptance suite from its authorised non-elevated interactive session.
# The Windows Sandbox acceptance runner installs the broker and creates the explicit target account.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $TargetUser,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $LauncherPath = (
        Join-Path $PSScriptRoot '..\out\build\Release\launch-as.exe'
    ),

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int] $CallerWindowProcessId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ProgressPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$caller = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($caller.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this acceptance test from the authorised non-elevated user session.'
}

$localUser = Get-LocalUser -Name $TargetUser -ErrorAction Stop
if (-not $localUser.Enabled) {
    throw "Local user '$TargetUser' is disabled. Take it over with --force before running acceptance tests."
}

$administrators = Get-LocalGroup -SID 'S-1-5-32-544'
$isAdministrator = Get-LocalGroupMember -Group $administrators |
Where-Object { $_.SID -eq $localUser.SID }
if ($null -ne $isAdministrator) {
    throw "Local user '$TargetUser' is an administrator; use a managed standard user."
}

$resolvedLauncher = Resolve-Path -LiteralPath $LauncherPath
$binaryDirectory = Split-Path -Parent $resolvedLauncher.Path
$identityProbe = Join-Path $binaryDirectory 'LauncherBrokerChildIdentityProbe.exe'
$accessProbe = Join-Path $binaryDirectory 'LauncherBrokerProcessAccessProbe.exe'
$consoleAcceptance = Join-Path $PSScriptRoot 'Invoke-BrokerConsoleAcceptanceTest.ps1'
$brokerProbeAcceptance = Join-Path $PSScriptRoot 'Invoke-BrokerProbeAcceptanceTest.ps1'
$sameAccountConcurrency = Join-Path $PSScriptRoot 'Invoke-BrokerSameAccountConcurrencyTest.ps1'

function Write-AcceptancePhase([string] $Name) {
    @(
        'RUNNING'
        "acceptance-phase=$Name"
    ) | Out-File -LiteralPath $ProgressPath -Encoding utf8
}

Write-Host "Acceptance account: .\$TargetUser"
Write-AcceptancePhase 'console-identity-isolation'
Write-Host 'Running the installed broker console identity and isolation checks.'
& $consoleAcceptance `
    -Account $TargetUser `
    -ExpectedExitCode 37 `
    -LauncherPath $resolvedLauncher.Path `
    -ProbePath $identityProbe `
    -ReportRoot (Split-Path -Parent $ProgressPath) `
    -CallerWindowProcessId $CallerWindowProcessId

Write-AcceptancePhase 'process-access-disconnect'
Write-Host 'Running the installed broker process-access and disconnect checks.'
& $brokerProbeAcceptance `
    -Account $TargetUser `
    -AccessProbePath $accessProbe

Write-AcceptancePhase 'same-account-concurrency'
Write-Host 'Running two overlapping sessions for the same managed account.'
& $sameAccountConcurrency -Account $TargetUser

Write-Host "`nAcceptance tests passed:"
Write-Host '  - The broker launched the managed standard account through an independent logon session.'
Write-Host '  - The child token did not contain the interactive user logon SID.'
Write-Host '  - The child could not enumerate the interactive window or open the caller for VM_READ or TERMINATE.'
Write-Host '  - The target exit code propagated through the console path.'
Write-Host '  - Disconnecting the broker control pipe terminated the child process tree.'
Write-Host '  - Two same-account sessions overlapped and retained independent disconnect lifetimes.'
