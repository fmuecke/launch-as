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
    [string] $DriverPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $RunnerPath -PathType Leaf)) {
    throw "The interactive-session probe runner does not exist: $RunnerPath"
}
if (-not (Test-Path -LiteralPath $DriverPath -PathType Leaf)) {
    throw "The interactive-session guest driver does not exist: $DriverPath"
}

$runnerText = Get-Content -LiteralPath $RunnerPath -Raw
$driverText = Get-Content -LiteralPath $DriverPath -Raw
$combinedText = $runnerText + [Environment]::NewLine + $driverText

foreach ($requiredText in @(
        'Invoke-WindowsSandboxTest',
        'LauncherInteractiveSessionProbe.exe',
        'LauncherInteractiveAclLeaseProbe.exe',
        'Show-LauncherAcceptanceWindow.ps1',
        'Run-InteractiveSessionProbeInSandbox.ps1',
        'ExistingLogin',
        'cmd.exe /d /s /c',
        'powershell.exe',
        'interactive-session-probe-result.txt',
        'interactive-session-probe-command.log',
        'New-ScheduledTaskPrincipal',
        "-UserId 'SYSTEM'",
        'Get-ScheduledTaskInfo',
        'LaunchAsDevCaller',
        '-Credential $callerCredential',
        'acl-probe-exit-code.txt',
        'probeExitCode',
        'canaryDeadline',
        'processSessionId',
        'activeConsoleSessionId',
        'callerIsAdministrator',
        'callerElevated',
        'callerSid',
        'windowStationLeaseAdded',
        'windowStationLeaseRemoved',
        'desktopLeaseAdded',
        'desktopLeaseRemoved',
        'daclSemanticallyRestored',
        'independentDaclSemanticallyRestored',
        'probeSucceeded',
        'canaryVisible')) {
    if ($combinedText -notmatch [regex]::Escape($requiredText)) {
        throw "The interactive-session probe workflow must contain: $requiredText"
    }
}
if ($runnerText -notmatch '>.+2>&1') {
    throw 'The probe runner must redirect guest stdout and stderr to the shared folder.'
}
if ($runnerText -notmatch '\$guestRun\.ExitCode\s*-ne\s*0') {
    throw 'The probe runner must check the guest command exit code.'
}
if ($runnerText -match 'Join-Path\s+\$PSHOME\s+[''"]powershell\.exe[''"]') {
    throw "The host runner must invoke the guest's inbox powershell.exe by name."
}
if ($driverText -match '\$callerSessionId\s+-ne\s+\$activeConsoleSessionId' -or
    $driverText -match '\$systemResult\[''activeConsoleSessionId''\].*-ne\s+\$callerSessionId') {
    throw 'The probe must not use WTSGetActiveConsoleSessionId to select the caller session.'
}
if ($driverText -notmatch "\['canaryVisible'\]\s*-ne\s*'true'" -or
    $driverText -notmatch "\['canaryVisible'\]\s*-ne\s*'false'") {
    throw 'The guest driver must prove that only the caller-session probe sees the canary.'
}
if ($driverText -match 'SetUserObjectSecurity|WRITE_DAC|WriteDac') {
    throw 'The feasibility probe must not modify window-station or desktop ACLs.'
}
