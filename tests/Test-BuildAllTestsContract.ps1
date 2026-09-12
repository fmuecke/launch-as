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
if ($scriptText -notmatch '\[string\]\s*\$ElevatedTestOutputPath') {
    throw 'build.ps1 must accept the elevated-test output path.'
}
if ($scriptText -notmatch '-ElevatedTestOutputPath') {
    throw 'The elevated child process must receive the elevated-test output path.'
}
if ($scriptText -notmatch 'Out-File -LiteralPath \$ElevatedTestOutputPath') {
    throw 'The elevated child process must capture CTest output in the requested file.'
}
if ($scriptText -notmatch 'Get-Content -LiteralPath \$elevatedTestOutputPath') {
    throw 'The parent process must print the captured elevated-test output.'
}
if ($scriptText -match 'Read-Host') {
    throw 'The elevated test run must not wait for interactive input.'
}
