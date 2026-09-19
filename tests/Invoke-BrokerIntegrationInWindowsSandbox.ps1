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
$runRoot = Join-Path $repositoryRoot 'out\windows-sandbox-integration'
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
        $downloadedHash = (Get-FileHash -LiteralPath $windowsSandboxTestDownloadPath -Algorithm SHA256).Hash
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

$configurationDirectory = Join-Path $BuildDirectory $Configuration
$artifactPaths = @(
    (Join-Path $configurationDirectory 'LauncherBrokerAuditTests.exe')
    (Join-Path $configurationDirectory 'LauncherBrokerAccountProvisioningTests.exe')
    (Join-Path $configurationDirectory 'LauncherBrokerServiceInstallerTests.exe')
    (Join-Path $configurationDirectory 'launch-as-broker.exe')
)
foreach ($artifactPath in $artifactPaths) {
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        throw "The sandbox integration-test artifact does not exist: $artifactPath"
    }
}

$successMarker = 'launch-as Windows Sandbox integration tests passed'
$sandboxResult = Invoke-WindowsSandboxTest `
    -RunRoot $runRoot `
    -ArtifactPath $artifactPaths `
    -PassThru `
    -TestScript {
        param($sandbox)

        $auditTestPath = Join-Path $sandbox.GuestMountPath 'LauncherBrokerAuditTests.exe'
        $accountTestPath = Join-Path `
            $sandbox.GuestMountPath `
            'LauncherBrokerAccountProvisioningTests.exe'
        $installerTestPath = Join-Path `
            $sandbox.GuestMountPath `
            'LauncherBrokerServiceInstallerTests.exe'
        $brokerPath = Join-Path $sandbox.GuestMountPath 'launch-as-broker.exe'
        $testCases = @(
            [PSCustomObject]@{
                Name       = 'Broker audit integration test'
                Executable = $auditTestPath
                Arguments  = @()
                ResultFile = 'audit-result.txt'
                Marker     = 'Broker audit integration tests passed'
            }
            [PSCustomObject]@{
                Name       = 'Broker account-provisioning integration test'
                Executable = $accountTestPath
                Arguments  = @()
                ResultFile = 'account-provisioning-result.txt'
                Marker     = 'Broker account-provisioning integration tests passed'
            }
            [PSCustomObject]@{
                Name       = 'Broker service-installer integration test'
                Executable = $installerTestPath
                Arguments  = @($brokerPath)
                ResultFile = 'service-installer-result.txt'
                Marker     = 'Broker service-installer integration tests passed'
            }
        )
        foreach ($testCase in $testCases) {
            $resultPath = Join-Path $sandbox.HostDirectory $testCase.ResultFile
            $guestResultPath = Join-Path $sandbox.GuestMountPath $testCase.ResultFile
            $argumentText = @(
                foreach ($argument in $testCase.Arguments) {
                    '"' + $argument.Replace('"', '""') + '"'
                }
            )
            $argumentSuffix = if ($argumentText.Count -eq 0) {
                ''
            }
            else {
                ' ' + ($argumentText -join ' ')
            }
            $testCommand = 'cmd.exe /d /s /c ""{0}"{1} > "{2}" 2>&1"' -f `
                $testCase.Executable, $argumentSuffix, $guestResultPath
            $execution = & $sandbox.InvokeCommand `
                -Command $testCommand `
                -Phase $testCase.Name `
                -CaptureFailure
            if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
                throw "$($testCase.Name) did not create $resultPath.`n$($execution.Output)"
            }
            $result = Get-Content -LiteralPath $resultPath -Raw
            if ($execution.ExitCode -ne 0) {
                throw "$($testCase.Name) failed with exit code $($execution.ExitCode).`n$result"
            }
            $markerPattern = '(?m)^{0}\s*$' -f [regex]::Escape($testCase.Marker)
            if ($result -notmatch $markerPattern) {
                throw "$($testCase.Name) did not report success.`n$result"
            }
            Write-Output $result.TrimEnd()
        }
        Write-Output $successMarker
    }

$sandboxOutput = $sandboxResult.Output | Out-String
if ($sandboxOutput -notmatch [regex]::Escape($successMarker)) {
    throw "Windows Sandbox integration tests did not report their success marker. Output:`n$sandboxOutput"
}
Write-Output $sandboxOutput.TrimEnd()
Write-Host "Windows Sandbox artifacts retained at $($sandboxResult.HostDirectory)"
