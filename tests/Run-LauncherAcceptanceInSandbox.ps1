# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $SourceDirectory,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $CallerPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$callerAccount = 'LaunchAsDevCaller'
$targetAccount = 'LaunchAsDevTestUser'
$workDirectory = 'C:\LaunchAsAcceptance'
$resultDirectory = 'C:\Users\Public\Documents\LaunchAsAcceptance'
$localResultPath = Join-Path $resultDirectory 'interactive-acceptance-result.txt'
$sharedResultPath = Join-Path $SourceDirectory 'interactive-acceptance-result.txt'
$phaseLogs = @(
    [PSCustomObject]@{
        LocalPath  = Join-Path $resultDirectory 'fixture.log'
        SharedPath = Join-Path $SourceDirectory 'fixture.log'
    }
    [PSCustomObject]@{
        LocalPath  = Join-Path $resultDirectory 'demand-start.log'
        SharedPath = Join-Path $SourceDirectory 'demand-start.log'
    }
    [PSCustomObject]@{
        LocalPath  = Join-Path $resultDirectory 'interactive-acceptance.log'
        SharedPath = Join-Path $SourceDirectory 'interactive-acceptance.log'
    }
)
$callerCredential = $null
$callerWasAddedToAdministrators = $false
$interactiveLaunch = $null

function Wait-GuestProcess {
    param(
        [Parameter(Mandatory)]
        [Diagnostics.Process] $Process,

        [Parameter(Mandatory)]
        [ValidateRange(1, 600)]
        [int] $TimeoutSeconds,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Description,

        [string] $ProgressPath,

        [string] $SharedProgressPath
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not $Process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        if (-not [string]::IsNullOrWhiteSpace($ProgressPath) -and
            -not [string]::IsNullOrWhiteSpace($SharedProgressPath) -and
            (Test-Path -LiteralPath $ProgressPath -PathType Leaf)) {
            Copy-Item -LiteralPath $ProgressPath -Destination $SharedProgressPath -Force
        }
        Start-Sleep -Milliseconds 250
        $Process.Refresh()
    }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        throw "$Description timed out after $TimeoutSeconds seconds."
    }
    if (-not [string]::IsNullOrWhiteSpace($ProgressPath) -and
        -not [string]::IsNullOrWhiteSpace($SharedProgressPath) -and
        (Test-Path -LiteralPath $ProgressPath -PathType Leaf)) {
        Copy-Item -LiteralPath $ProgressPath -Destination $SharedProgressPath -Force
    }
}

function Copy-GuestLogs {
    param(
        [Parameter(Mandatory)]
        [object[]] $Logs
    )

    foreach ($log in $Logs) {
        if (Test-Path -LiteralPath $log.LocalPath -PathType Leaf) {
            Copy-Item -LiteralPath $log.LocalPath -Destination $log.SharedPath -Force
        }
    }
}

if ($null -eq ('LaunchAs.AcceptanceLogonV2' -as [type])) {
    $acceptanceLogonSource = Join-Path $SourceDirectory 'LauncherAcceptanceLogon.cs'
    Add-Type -Path $acceptanceLogonSource -ErrorAction Stop
}

Remove-Item -LiteralPath $sharedResultPath -Force -ErrorAction SilentlyContinue
try {
    $caller = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $caller.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The Sandbox bootstrap must run as the existing elevated guest user.'
    }

    if (Test-Path -LiteralPath $workDirectory) {
        throw "The disposable Sandbox work directory already exists: $workDirectory"
    }
    $null = New-Item -ItemType Directory -Path $workDirectory
    $null = New-Item -ItemType Directory -Path $resultDirectory -Force
    foreach ($log in $phaseLogs) {
        Remove-Item -LiteralPath $log.LocalPath -Force -ErrorAction SilentlyContinue
    }
    Copy-Item -Path (Join-Path $SourceDirectory '*') -Destination $workDirectory -Force

    if (Get-LocalUser -Name $callerAccount -ErrorAction SilentlyContinue) {
        throw "The reserved Sandbox caller already exists: $callerAccount"
    }
    $securePassword = ConvertTo-SecureString $CallerPassword -AsPlainText -Force
    $callerUser = New-LocalUser `
        -Name $callerAccount `
        -Password $securePassword `
        -PasswordNeverExpires `
        -UserMayNotChangePassword
    $callerCredential = [PSCredential]::new(
        "$env:COMPUTERNAME\$callerAccount", $securePassword)
    $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
    Add-LocalGroupMember -Group $administrators -Member $callerUser
    $callerWasAddedToAdministrators = $true

    & icacls.exe $workDirectory /grant "*$($callerUser.SID):(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Granting the Sandbox caller access to $workDirectory failed."
    }
    & icacls.exe $resultDirectory /grant "*$($callerUser.SID):(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Granting the Sandbox caller access to $resultDirectory failed."
    }

    $fixturePath = Join-Path $workDirectory 'Install-LauncherAcceptanceFixture.ps1'
    $fixtureResultPath = Join-Path $resultDirectory 'fixture-result.txt'
    Remove-Item -LiteralPath $fixtureResultPath -Force -ErrorAction SilentlyContinue
    $fixtureArguments = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        ('"{0}"' -f $fixturePath)
        '-BinaryDirectory'
        ('"{0}"' -f $workDirectory)
        '-Account'
        $targetAccount
        '-ResultPath'
        ('"{0}"' -f $fixtureResultPath)
        '-LogPath'
        ('"{0}"' -f $phaseLogs[0].LocalPath)
    )
    $fixture = Start-Process `
        -FilePath (Join-Path $PSHOME 'powershell.exe') `
        -ArgumentList $fixtureArguments `
        -Credential $callerCredential `
        -LoadUserProfile `
        -WorkingDirectory $workDirectory `
        -PassThru
    Wait-GuestProcess `
        -Process $fixture -TimeoutSeconds 120 -Description 'Sandbox fixture installation'
    Copy-GuestLogs -Logs $phaseLogs[0]
    if (-not (Test-Path -LiteralPath $fixtureResultPath -PathType Leaf)) {
        throw "The Sandbox fixture did not write its result: $fixtureResultPath"
    }
    $fixtureResult = Get-Content -LiteralPath $fixtureResultPath -Raw
    if ($fixtureResult -notmatch '(?m)^PASS\s*$') {
        throw "The Sandbox fixture failed.`n$fixtureResult"
    }

    $targetUser = Get-LocalUser -Name $targetAccount -ErrorAction Stop
    & icacls.exe $workDirectory /grant "*$($targetUser.SID):(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Granting the Sandbox target access to $workDirectory failed."
    }

    Stop-Service -Name 'launch-as-broker' -ErrorAction Stop

    Remove-LocalGroupMember -Group $administrators -Member $callerUser
    $callerWasAddedToAdministrators = $false
    $remainingMembership = Get-LocalGroupMember -Group $administrators |
    Where-Object { $_.SID -eq $callerUser.SID }
    if ($null -ne $remainingMembership) {
        throw "The Sandbox caller is still a member of $($administrators.Name)."
    }

    $windowsPowerShell = Join-Path $PSHOME 'powershell.exe'
    $demandStartScriptPath = Join-Path $workDirectory 'Invoke-BrokerDemandStartTest.ps1'
    $demandStartAdminPath = Join-Path $workDirectory 'launch-as-admin.exe'
    $demandStartResultPath = Join-Path $resultDirectory 'demand-start-result.txt'
    Remove-Item -LiteralPath $demandStartResultPath -Force -ErrorAction SilentlyContinue
    $demandStartArguments = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        ('"{0}"' -f $demandStartScriptPath)
        '-AdminPath'
        ('"{0}"' -f $demandStartAdminPath)
        '-ExpectedAccount'
        $targetAccount
        '-ResultPath'
        ('"{0}"' -f $demandStartResultPath)
        '-LogPath'
        ('"{0}"' -f $phaseLogs[1].LocalPath)
    )
    $demandStart = Start-Process `
        -FilePath $windowsPowerShell `
        -ArgumentList $demandStartArguments `
        -Credential $callerCredential `
        -LoadUserProfile `
        -WorkingDirectory $workDirectory `
        -WindowStyle Hidden `
        -PassThru
    Wait-GuestProcess `
        -Process $demandStart -TimeoutSeconds 30 -Description 'Sandbox broker demand-start'
    Copy-GuestLogs -Logs $phaseLogs[1]
    if (-not (Test-Path -LiteralPath $demandStartResultPath -PathType Leaf)) {
        throw "The standard Sandbox caller did not write its demand-start result."
    }
    $demandStartResult = Get-Content -LiteralPath $demandStartResultPath -Raw
    if ($demandStartResult -notmatch '(?m)^PASS\s*$') {
        throw "The standard Sandbox caller could not demand-start the broker.`n$demandStartResult"
    }

    $acceptancePath = Join-Path $workDirectory 'Invoke-LauncherAcceptanceAsStandardUser.ps1'
    $acceptanceCommandLine = (
        '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}" ' +
        '-TargetUser {2} -ExpectedCaller {3} -ResultPath "{4}" -LogPath "{5}"'
    ) -f $windowsPowerShell, $acceptancePath, $targetAccount, $callerAccount, $localResultPath, `
        $phaseLogs[2].LocalPath
    $interactiveLaunch = [LaunchAs.AcceptanceLogonV2]::Start(
        $callerAccount,
        $env:COMPUTERNAME,
        $CallerPassword,
        $windowsPowerShell,
        $acceptanceCommandLine,
        $workDirectory)
    $acceptance = Get-Process -Id $interactiveLaunch.ProcessId -ErrorAction Stop
    Wait-GuestProcess `
        -Process $acceptance `
        -TimeoutSeconds 300 `
        -Description 'Interactive Sandbox acceptance' `
        -ProgressPath $localResultPath `
        -SharedProgressPath $sharedResultPath
    Copy-GuestLogs -Logs $phaseLogs[2]
    if (-not (Test-Path -LiteralPath $localResultPath -PathType Leaf)) {
        throw "The standard caller did not write its acceptance result: $localResultPath"
    }
    Copy-Item -LiteralPath $localResultPath -Destination $sharedResultPath -Force
    $acceptanceResult = Get-Content -LiteralPath $localResultPath -Raw
    if ($acceptanceResult -notmatch '(?m)^PASS\s*$') {
        throw "Interactive Sandbox acceptance failed.`n$acceptanceResult"
    }
}
catch {
    $failureResult = @('FAIL')
    $brokerService = Get-Service -Name 'launch-as-broker' -ErrorAction SilentlyContinue
    if ($null -ne $brokerService) {
        $failureResult += "broker-service-status=$($brokerService.Status)"
    }
    if (Test-Path -LiteralPath $localResultPath -PathType Leaf) {
        $failureResult += (Get-Content -LiteralPath $localResultPath)
    }
    $failureResult += $_.Exception.Message
    $failureResult += $_.ScriptStackTrace
    $failureResult | Out-File -LiteralPath $sharedResultPath -Encoding utf8
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 1
}
finally {
    Copy-GuestLogs -Logs $phaseLogs
    if ($null -ne $interactiveLaunch) {
        $interactiveLaunch.Dispose()
    }
    if ($callerWasAddedToAdministrators) {
        Remove-LocalGroupMember `
            -Group (Get-LocalGroup -SID 'S-1-5-32-544') `
            -Member $callerAccount `
            -ErrorAction SilentlyContinue
    }
}
