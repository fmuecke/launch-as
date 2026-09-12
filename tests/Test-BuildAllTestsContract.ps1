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
if ($scriptText -notmatch "-LabelOption '--label-exclude' -LabelValue 'elevated\|interactive'") {
    throw 'The regular test run must continue to exclude elevated and interactive tests.'
}
if ($scriptText -notmatch "-LabelOption '--label-regex' -LabelValue 'elevated'") {
    throw 'The elevated child run must select only elevated CTest tests.'
}
if ($scriptText -notmatch 'Start-Process.*-Verb RunAs.*-Wait.*-PassThru') {
    throw 'The elevated test run must use Start-Process -Verb RunAs and wait for its result.'
}
if ($scriptText -notmatch '-RunElevatedTests') {
    throw 'The elevated child process must use the internal elevated-test switch.'
}
if ($scriptText -notmatch '-WaitForElevatedTestResults') {
    throw 'The elevated child process must wait for the user to inspect its test results.'
}
if ($scriptText -notmatch "Read-Host 'Elevated tests are complete\. Press Enter to close this window\.'") {
    throw 'The elevated test window must remain open until the user has inspected the results.'
}
