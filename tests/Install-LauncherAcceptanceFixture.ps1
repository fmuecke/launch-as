# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $BinaryDirectory,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Account,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ResultPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$caller = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $caller.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The Windows Sandbox acceptance fixture must run elevated.'
}

$admin = Join-Path $BinaryDirectory 'launch-as-admin.exe'
if (-not (Test-Path -LiteralPath $admin -PathType Leaf)) {
    throw "The Sandbox acceptance administrator executable does not exist: $admin"
}

$transcriptStarted = $false
try {
    Start-Transcript -Path $LogPath -Force | Out-Null
    $transcriptStarted = $true
    & $admin install
    if ($LASTEXITCODE -ne 0) {
        throw "Installing the Sandbox broker failed with exit code $LASTEXITCODE."
    }

    & $admin create $Account
    if ($LASTEXITCODE -ne 0) {
        throw "Creating Sandbox account '$Account' failed with exit code $LASTEXITCODE."
    }

    @(
        'PASS'
        "Installed the Sandbox broker and created .\$Account."
    ) | Out-File -LiteralPath $ResultPath -Encoding utf8
}
catch {
    Write-Host "Sandbox fixture failed: $($_.Exception.Message)" -ForegroundColor Red
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
