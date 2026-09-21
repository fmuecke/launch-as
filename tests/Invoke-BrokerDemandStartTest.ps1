# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $AdminPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedAccount,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ResultPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$transcriptStarted = $false
try {
    Start-Transcript -Path $LogPath -Force | Out-Null
    $transcriptStarted = $true
    $output = & $AdminPath list 2>&1
    $exitCode = $LASTEXITCODE
    $outputLines = @($output | ForEach-Object { $_.ToString() })
    $outputLines | Write-Output
    if ($exitCode -ne 0) {
        throw "Broker list failed with exit code $exitCode.`n$($outputLines -join [Environment]::NewLine)"
    }
    if ($outputLines -notcontains $ExpectedAccount) {
        throw "Broker list did not return the expected account '$ExpectedAccount'."
    }

    @(
        'PASS'
        "The standard caller demand-started the broker and listed $ExpectedAccount."
    ) | Out-File -LiteralPath $ResultPath -Encoding utf8
}
catch {
    Write-Host "Sandbox broker demand-start failed: $($_.Exception.Message)" -ForegroundColor Red
    @(
        'FAIL'
        $_.Exception.Message
        $_.ScriptStackTrace
    ) | Out-File -LiteralPath $ResultPath -Encoding utf8
    exit 1
}
finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
}
