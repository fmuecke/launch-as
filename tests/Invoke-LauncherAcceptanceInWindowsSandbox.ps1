# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $BuildDirectory,

    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$runRoot = Join-Path $repositoryRoot 'out\windows-sandbox-acceptance'
$supportModulePath = Join-Path $PSScriptRoot 'WindowsSandboxAcceptanceSupport.psm1'
$windowsSandboxTestModuleUri = 'https://gist.githubusercontent.com/fmuecke/2a53528dba05cd208c2cfbef2c547e2a/raw/7b4d862ab00465b06028b11ee4981c48c398602a/WindowsSandboxTest.psm1'
$windowsSandboxTestModuleSha256 = 'B23495DFF238F65FDD69869BFD58481032BD3F9BA0A7E9D001EDF4444FB4C78C'
$windowsSandboxTestModulePath = Join-Path $runRoot 'WindowsSandboxTest-1.0.0.psm1'
$windowsSandboxTestDownloadPath = "$windowsSandboxTestModulePath.download"

$null = New-Item -ItemType Directory -Path $runRoot -Force
if (Test-Path -LiteralPath $windowsSandboxTestModulePath -PathType Leaf) {
    $moduleHash = (Get-FileHash -LiteralPath $windowsSandboxTestModulePath -Algorithm SHA256).Hash
    if ($moduleHash -ne $windowsSandboxTestModuleSha256) {
        throw "Cached WindowsSandboxTest module hash mismatch. Expected $windowsSandboxTestModuleSha256, got $moduleHash."
    }
}
else {
    try {
        Invoke-WebRequest -Uri $windowsSandboxTestModuleUri -OutFile $windowsSandboxTestDownloadPath
        $downloadedHash = (
            Get-FileHash -LiteralPath $windowsSandboxTestDownloadPath -Algorithm SHA256
        ).Hash
        if ($downloadedHash -ne $windowsSandboxTestModuleSha256) {
            throw "WindowsSandboxTest module hash mismatch. Expected $windowsSandboxTestModuleSha256, got $downloadedHash."
        }
        Move-Item -LiteralPath $windowsSandboxTestDownloadPath `
            -Destination $windowsSandboxTestModulePath -Force
    }
    finally {
        if (Test-Path -LiteralPath $windowsSandboxTestDownloadPath) {
            Remove-Item -LiteralPath $windowsSandboxTestDownloadPath -Force
        }
    }
}
Import-Module $windowsSandboxTestModulePath -Force
Import-Module $supportModulePath -Force

$configurationDirectory = Join-Path $BuildDirectory $Configuration
$artifactPaths = @(
    (Join-Path $configurationDirectory 'launch-as.exe')
    (Join-Path $configurationDirectory 'launch-as-admin.exe')
    (Join-Path $configurationDirectory 'launch-as-broker.exe')
    (Join-Path $configurationDirectory 'launch-as-conhost.exe')
    (Join-Path $configurationDirectory 'LauncherBrokerChildIdentityProbe.exe')
    (Join-Path $configurationDirectory 'LauncherBrokerProcessAccessProbe.exe')
    (Join-Path $configurationDirectory 'LauncherInteractiveTargetProbe.exe')
    (Join-Path $PSScriptRoot 'Invoke-BrokerDemandStartTest.ps1')
    (Join-Path $PSScriptRoot 'Install-LauncherAcceptanceFixture.ps1')
    (Join-Path $PSScriptRoot 'LauncherAcceptanceLogon.cs')
    (Join-Path $PSScriptRoot 'Run-LauncherAcceptanceInSandbox.ps1')
    (Join-Path $PSScriptRoot 'Invoke-LauncherAcceptanceAsStandardUser.ps1')
    (Join-Path $PSScriptRoot 'Show-LauncherAcceptanceWindow.ps1')
    (Join-Path $PSScriptRoot 'Invoke-LauncherAcceptanceTest.ps1')
    (Join-Path $PSScriptRoot 'Invoke-BrokerConsoleAcceptanceTest.ps1')
    (Join-Path $PSScriptRoot 'Invoke-BrokerProbeAcceptanceTest.ps1')
    (Join-Path $PSScriptRoot 'Invoke-BrokerSameAccountConcurrencyTest.ps1')
    (Join-Path $PSScriptRoot 'Invoke-BrokerInteractiveAcceptanceTest.ps1')
)
foreach ($artifactPath in $artifactPaths) {
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        throw "The Sandbox acceptance artifact does not exist: $artifactPath"
    }
}

$resultFileName = 'interactive-acceptance-result.txt'
$driverFileName = 'Run-LauncherAcceptanceInSandbox.ps1'
$callerPassword = 'LaunchAsDevTest!' + [guid]::NewGuid().ToString('N')
$sandboxResult = Invoke-WindowsSandboxTest `
    -RunRoot $runRoot `
    -ArtifactPath $artifactPaths `
    -PassThru `
    -TestScript {
        param($sandbox)

        $running = & wsb.exe --raw list | Out-String | ConvertFrom-Json
        $sandboxId = Get-SingleWindowsSandboxId -ListResult $running

        $null = Start-Process -FilePath 'wsb.exe' -ArgumentList @(
            'connect'
            '--id'
            $sandboxId
        )
        $guestDriverPath = Join-Path $sandbox.GuestMountPath $driverFileName
        $guestCommand = (
            'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" ' +
            '-SourceDirectory "{1}" -CallerPassword "{2}"'
        ) -f $guestDriverPath, $sandbox.GuestMountPath, $callerPassword
        $loginDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $guestRun = & $sandbox.InvokeCommand `
                -Command $guestCommand `
                -Phase 'Interactive acceptance' `
                -RunAs 'ExistingLogin' `
                -CaptureFailure
            $loginSessionPending = $guestRun.ExitCode -ne 0 -and
                $guestRun.Output -match '0x80070520'
            if ($loginSessionPending -and [DateTime]::UtcNow -lt $loginDeadline) {
                Start-Sleep -Seconds 1
            }
        } while ($loginSessionPending -and [DateTime]::UtcNow -lt $loginDeadline)

        $resultPath = Join-Path $sandbox.HostDirectory $resultFileName
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            throw "The guest acceptance script did not create $resultPath.`n$($guestRun.Output)"
        }
        $result = Get-Content -LiteralPath $resultPath -Raw
        if ($guestRun.ExitCode -ne 0 -or $result -notmatch '(?m)^PASS\s*$') {
            throw "Interactive Windows Sandbox acceptance failed.`n$result`n$($guestRun.Output)"
        }
        Write-Output $result.TrimEnd()
    }

$sandboxOutput = $sandboxResult.Output | Out-String
if ($sandboxOutput -notmatch '(?m)^PASS\s*$') {
    throw "Interactive Windows Sandbox acceptance did not report success.`n$sandboxOutput"
}
Write-Output $sandboxOutput.TrimEnd()
Write-Host "Windows Sandbox artifacts retained at $($sandboxResult.HostDirectory)"
