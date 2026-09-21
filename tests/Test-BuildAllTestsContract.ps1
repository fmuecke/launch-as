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
if ($scriptText -notmatch '\[switch\]\s*\$RunAllTests') {
    throw 'build.ps1 must expose the -RunAllTests switch.'
}
if ($scriptText -notmatch '\[switch\]\s*\$RunSandboxTests') {
    throw 'build.ps1 must expose the -RunSandboxTests switch.'
}
if ($scriptText -notmatch '\[switch\]\s*\$RunAcceptanceTest') {
    throw 'build.ps1 must expose the -RunAcceptanceTest switch.'
}
if ($scriptText -notmatch "-LabelOption '--label-exclude' -LabelValue 'elevated\|interactive'") {
    throw 'The regular test run must continue to exclude elevated and interactive tests.'
}
if ($scriptText -notmatch "'tests\\Invoke-BrokerIntegrationInWindowsSandbox.ps1'") {
    throw 'The sandbox test run must use the project integration-test entry point.'
}
if ($scriptText -notmatch '(?s)if\s*\(\$RunAllTests\).*?Invoke-WindowsSandboxIntegrationTests') {
    throw '-RunAllTests must run the elevated integration tests in Windows Sandbox.'
}
if ($scriptText -notmatch '(?s)if\s*\(\$RunSandboxTests\).*?Invoke-WindowsSandboxIntegrationTests') {
    throw '-RunSandboxTests must run the elevated integration tests in Windows Sandbox.'
}
if ($scriptText -match 'Start-Process.*-Verb RunAs') {
    throw 'The test runner must not request host elevation.'
}
if ($scriptText -match '\$RunElevatedTests|\$ElevatedTestOutputPath') {
    throw 'build.ps1 must not expose a host-elevated test route.'
}
if ($scriptText -match '\$TargetUser\s*=\s*["'']LaunchAsUser["'']') {
    throw 'build.ps1 must not default tests to the production-style LaunchAsUser account.'
}
if ($scriptText -notmatch "'tests\\Invoke-LauncherAcceptanceInWindowsSandbox.ps1'") {
    throw 'Interactive acceptance must use the Windows Sandbox entry point.'
}
if ($scriptText -notmatch '(?s)if\s*\(\$RunAcceptanceTest\).*?Invoke-WindowsSandboxAcceptanceTest') {
    throw '-RunAcceptanceTest must run interactive acceptance inside Windows Sandbox.'
}
if ($scriptText -notmatch '(?s)if\s*\(\$RunAllTests\).*?Confirm-InteractiveAcceptance.*?Invoke-WindowsSandboxAcceptanceTest') {
    throw '-RunAllTests must offer the interactive Windows Sandbox acceptance test.'
}
