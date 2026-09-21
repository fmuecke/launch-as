# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $RunnerPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $DriverPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $FixturePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $DemandStartPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LogonHelperPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $SupportModulePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $StandardCallerPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $AcceptancePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ConcurrencyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $RunnerPath -PathType Leaf)) {
    throw "The Windows Sandbox acceptance runner does not exist: $RunnerPath"
}
if (-not (Test-Path -LiteralPath $DriverPath -PathType Leaf)) {
    throw "The guest acceptance driver does not exist: $DriverPath"
}
if (-not (Test-Path -LiteralPath $FixturePath -PathType Leaf)) {
    throw "The Sandbox acceptance fixture does not exist: $FixturePath"
}
if (-not (Test-Path -LiteralPath $DemandStartPath -PathType Leaf)) {
    throw "The broker demand-start test does not exist: $DemandStartPath"
}
if (-not (Test-Path -LiteralPath $LogonHelperPath -PathType Leaf)) {
    throw "The C# acceptance logon helper does not exist: $LogonHelperPath"
}
if (-not (Test-Path -LiteralPath $SupportModulePath -PathType Leaf)) {
    throw "The Sandbox acceptance support module does not exist: $SupportModulePath"
}
if (-not (Test-Path -LiteralPath $StandardCallerPath -PathType Leaf)) {
    throw "The standard-caller acceptance driver does not exist: $StandardCallerPath"
}
if (-not (Test-Path -LiteralPath $AcceptancePath -PathType Leaf)) {
    throw "The acceptance suite does not exist: $AcceptancePath"
}
if (-not (Test-Path -LiteralPath $ConcurrencyPath -PathType Leaf)) {
    throw "The concurrency acceptance test does not exist: $ConcurrencyPath"
}

Import-Module $SupportModulePath -Force
$singleSandboxList = @'
{
  "WindowsSandboxEnvironments": [
    { "Id": "sandbox-regression-id", "State": "Running" }
  ]
}
'@ | ConvertFrom-Json
$resolvedSandboxId = Get-SingleWindowsSandboxId -ListResult $singleSandboxList
if ($resolvedSandboxId -ne 'sandbox-regression-id') {
    throw "The Sandbox list parser returned an unexpected id: $resolvedSandboxId"
}

$runnerText = Get-Content -LiteralPath $RunnerPath -Raw
$driverText = Get-Content -LiteralPath $DriverPath -Raw
$fixtureText = Get-Content -LiteralPath $FixturePath -Raw
$demandStartText = Get-Content -LiteralPath $DemandStartPath -Raw
$logonHelperText = Get-Content -LiteralPath $LogonHelperPath -Raw
$standardCallerText = Get-Content -LiteralPath $StandardCallerPath -Raw
$acceptanceText = Get-Content -LiteralPath $AcceptancePath -Raw
$scriptText = @(
    $runnerText,
    $driverText,
    $fixtureText,
    $demandStartText,
    $logonHelperText,
    $standardCallerText,
    $acceptanceText
) -join `
    [Environment]::NewLine
$immutableRevision = '7b4d862ab00465b06028b11ee4981c48c398602a'
$expectedHash = 'B23495DFF238F65FDD69869BFD58481032BD3F9BA0A7E9D001EDF4444FB4C78C'
if ($runnerText -notmatch [regex]::Escape("/raw/$immutableRevision/WindowsSandboxTest.psm1")) {
    throw 'The acceptance runner must use the pinned immutable Windows Sandbox helper.'
}
if ($runnerText -notmatch [regex]::Escape($expectedHash) -or
    $runnerText -notmatch 'Get-FileHash.*-Algorithm\s+SHA256') {
    throw 'The acceptance runner must SHA-256 verify the pinned Windows Sandbox helper.'
}
if ($runnerText -notmatch [regex]::Escape("Join-Path `$PSScriptRoot 'LauncherAcceptanceLogon.cs'")) {
    throw 'The acceptance runner must copy the C# logon helper into the Sandbox.'
}
foreach ($requiredText in @(
        'Invoke-WindowsSandboxTest',
        'WindowsSandboxAcceptanceSupport.psm1',
        'Get-SingleWindowsSandboxId',
        'LaunchAsDevCaller',
        'LaunchAsDevTestUser',
        'wsb.exe',
        'connect',
        'ExistingLogin',
        '0x80070520',
        'fixture-result.txt',
        'LogonUser',
        'CreateProcessWithTokenW',
        'S-1-5-5-',
        'SeGroupLogonId',
        '0x000F037F',
        '0x000F01FF',
        'SetUserObjectSecurity',
        'RUNNING',
        'acceptance-phase=',
        'interactive-acceptance-result.txt',
        'Invoke-BrokerDemandStartTest.ps1',
        'Run-LauncherAcceptanceInSandbox.ps1',
        'Invoke-LauncherAcceptanceTest.ps1',
        'LauncherBrokerChildIdentityProbe.exe',
        'LauncherBrokerProcessAccessProbe.exe',
        'launch-as-admin.exe',
        'launch-as-broker.exe',
        'launch-as-conhost.exe',
        'launch-as.exe')) {
    if ($scriptText -notmatch [regex]::Escape($requiredText)) {
        throw "The interactive Sandbox runner must contain: $requiredText"
    }
}
if ($scriptText -match '[''\"]LaunchAsUser[''\"]') {
    throw 'Interactive Sandbox acceptance must not use LaunchAsUser.'
}
if ($scriptText -match 'Read-Host') {
    throw 'Interactive Sandbox acceptance must not require manual command entry.'
}
if ($scriptText -match "-Verb\s+RunAs") {
    throw 'Interactive Sandbox acceptance must not depend on UAC inside the guest.'
}
if ($scriptText -notmatch '-Credential\s+\$callerCredential') {
    throw 'The guest bootstrap must launch the reserved caller with explicit credentials.'
}
if ($scriptText -notmatch '-TargetUser' -or
    $scriptText -notmatch '\$targetAccount') {
    throw 'The acceptance suite must receive the reserved guest test account explicitly.'
}

foreach ($logFile in @(
        'fixture.log',
        'demand-start.log',
        'interactive-acceptance.log')) {
    if ($scriptText -notmatch [regex]::Escape($logFile)) {
        throw "The Sandbox acceptance workflow must retain $logFile in its run directory."
    }
}
if ($driverText -notmatch 'Copy-GuestLogs') {
    throw 'The guest acceptance driver must copy every phase log into the shared run directory.'
}
foreach ($phaseScript in @($FixturePath, $DemandStartPath, $StandardCallerPath)) {
    $phaseText = Get-Content -LiteralPath $phaseScript -Raw
    if ($phaseText -notmatch 'Start-Transcript') {
        throw "The acceptance phase must capture its complete console log: $phaseScript"
    }
}

$stopBrokerMatch = [regex]::Match(
    $driverText,
    'Stop-Service\s+-Name\s+[''"]launch-as-broker[''"]')
$removeAdministratorIndex = $driverText.IndexOf('Remove-LocalGroupMember')
$demandStartMatch = [regex]::Match(
    $driverText,
    '\$demandStart\s*=\s*Start-Process')
$interactiveStartIndex = $driverText.IndexOf('[LaunchAs.AcceptanceLogonV2]::Start')
if (-not $stopBrokerMatch.Success -or
    $removeAdministratorIndex -lt 0 -or
    $stopBrokerMatch.Index -gt $removeAdministratorIndex) {
    throw (
        'The elevated guest bootstrap must stop launch-as-broker before demoting ' +
        'the standard caller so its first launch verifies demand-start access.'
    )
}
if ($demandStartText -notmatch '&\s+\$AdminPath\s+list' -or
    $demandStartText -notmatch '\$LASTEXITCODE' -or
    $demandStartText -notmatch '(?m)^\s*''PASS''\s*$') {
    throw 'The standard-caller demand-start test must validate the broker list operation.'
}
if (-not $demandStartMatch.Success -or
    $demandStartMatch.Index -lt $removeAdministratorIndex -or
    $interactiveStartIndex -lt 0 -or
    $demandStartMatch.Index -gt $interactiveStartIndex) {
    throw (
        'A noninteractive standard-caller operation must demand-start the stopped broker ' +
        'before interactive acceptance begins.'
    )
}

$concurrencyText = Get-Content -LiteralPath $ConcurrencyPath -Raw
if ($concurrencyText -match '::EnsureBrokerStarted\(\)') {
    throw 'The concurrency phase must use the broker already started by the acceptance suite.'
}
