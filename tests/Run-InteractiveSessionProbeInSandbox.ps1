# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $SourceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$workDirectory = 'C:\LaunchAsInteractiveSessionProbe'
$sharedResultPath = Join-Path $SourceDirectory 'interactive-session-probe-result.txt'
$callerResultPath = Join-Path $workDirectory 'caller-session.txt'
$systemResultPath = Join-Path $workDirectory 'system-session.txt'
$probePath = Join-Path $workDirectory 'LauncherInteractiveSessionProbe.exe'
$aclProbePath = Join-Path $workDirectory 'LauncherInteractiveAclLeaseProbe.exe'
$windowScriptPath = Join-Path $workDirectory 'Show-LauncherAcceptanceWindow.ps1'
$canaryTitle = 'launch-as Sandbox acceptance caller'
$taskName = 'launch-as-interactive-session-probe-' + [guid]::NewGuid().ToString('N')
$windowProcess = $null
$taskRegistered = $false
$callerAccount = 'LaunchAsDevCaller'
$callerCreated = $false
$aclResultPath = $null
$aclExitCodePath = $null

function Read-ProbeResult {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    $result = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
            $result[$parts[0]] = $parts[1]
        }
    }
    return $result
}

Remove-Item -LiteralPath $sharedResultPath -Force -ErrorAction SilentlyContinue
try {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The interactive-session probe driver must run as the elevated existing login.'
    }
    if (Test-Path -LiteralPath $workDirectory) {
        throw "The disposable probe work directory already exists: $workDirectory"
    }
    $null = New-Item -ItemType Directory -Path $workDirectory
    Copy-Item -LiteralPath (Join-Path $SourceDirectory 'LauncherInteractiveSessionProbe.exe') `
        -Destination $probePath
    Copy-Item -LiteralPath (Join-Path $SourceDirectory 'LauncherInteractiveAclLeaseProbe.exe') `
        -Destination $aclProbePath
    Copy-Item -LiteralPath (Join-Path $SourceDirectory 'Show-LauncherAcceptanceWindow.ps1') `
        -Destination $windowScriptPath

    $windowProcess = Start-Process `
        -FilePath (Join-Path $PSHOME 'powershell.exe') `
        -ArgumentList @(
            '-NoProfile'
            '-Sta'
            '-ExecutionPolicy'
            'Bypass'
            '-File'
            ('"{0}"' -f $windowScriptPath)
        ) `
        -PassThru
    $windowDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 100
        $windowProcess.Refresh()
    } while ($windowProcess.MainWindowHandle -eq 0 -and
        -not $windowProcess.HasExited -and
        [DateTime]::UtcNow -lt $windowDeadline)
    if ($windowProcess.HasExited -or $windowProcess.MainWindowHandle -eq 0) {
        throw 'The interactive-session probe could not create its controlled window.'
    }

    $canaryDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        & $probePath $canaryTitle $callerResultPath
        if ($LASTEXITCODE -ne 0) {
            throw "The caller-session probe failed with exit code $LASTEXITCODE."
        }
        $callerResult = Read-ProbeResult -Path $callerResultPath
        if ($callerResult['canaryVisible'] -ne 'true') {
            Start-Sleep -Milliseconds 100
            $windowProcess.Refresh()
        }
    } while ($callerResult['canaryVisible'] -ne 'true' -and
        -not $windowProcess.HasExited -and
        [DateTime]::UtcNow -lt $canaryDeadline)

    $action = New-ScheduledTaskAction `
        -Execute $probePath `
        -Argument ('"{0}" "{1}"' -f $canaryTitle, $systemResultPath)
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $null = Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Principal $taskPrincipal
    $taskRegistered = $true
    Start-ScheduledTask -TaskName $taskName

    $taskDeadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 100
        $task = Get-ScheduledTask -TaskName $taskName
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
    } while (($task.State -eq 'Running' -or
            -not (Test-Path -LiteralPath $systemResultPath -PathType Leaf)) -and
        [DateTime]::UtcNow -lt $taskDeadline)
    if (-not (Test-Path -LiteralPath $systemResultPath -PathType Leaf)) {
        throw 'The SYSTEM probe did not create its result before the timeout.'
    }
    if ($taskInfo.LastTaskResult -ne 0) {
        throw "The SYSTEM probe failed with exit code $($taskInfo.LastTaskResult)."
    }

    $systemResult = Read-ProbeResult -Path $systemResultPath
    foreach ($key in @(
            'processSessionId',
            'activeConsoleSessionId',
            'processWindowStation',
            'openWinSta0Error',
            'setWinSta0Error',
            'openDefaultDesktopError',
            'enumerateWindowsError',
            'restoreWindowStationError',
            'canaryVisible')) {
        if (-not $callerResult.ContainsKey($key) -or -not $systemResult.ContainsKey($key)) {
            throw "A probe result omitted the required field '$key'."
        }
    }
    foreach ($key in @(
            'openWinSta0Error',
            'setWinSta0Error',
            'openDefaultDesktopError',
            'enumerateWindowsError',
            'restoreWindowStationError')) {
        if ($callerResult[$key] -ne '0') {
            throw "The caller-session probe reported ${key}=$($callerResult[$key])."
        }
    }
    foreach ($key in @(
            'openWinSta0Error',
            'setWinSta0Error',
            'openDefaultDesktopError',
            'enumerateWindowsError',
            'restoreWindowStationError')) {
        if ($systemResult[$key] -ne '0') {
            throw "The Session-0 probe reported ${key}=$($systemResult[$key])."
        }
    }
    if ($callerResult['canaryVisible'] -ne 'true') {
        throw 'The caller-session probe could not see its controlled window.'
    }
    if ($systemResult['canaryVisible'] -ne 'false') {
        throw 'The Session-0 SYSTEM probe unexpectedly saw the caller-session window.'
    }
    $callerSessionId = [uint32] $callerResult['processSessionId']
    $systemSessionId = [uint32] $systemResult['processSessionId']
    if ($callerSessionId -eq 0) {
        throw 'The visible probe unexpectedly ran in Session 0.'
    }
    if ($systemSessionId -ne 0) {
        throw "The scheduled SYSTEM probe ran in session $systemSessionId instead of Session 0."
    }
    if ([string]::Equals(
            $systemResult['processWindowStation'],
            'WinSta0',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The Session-0 SYSTEM probe unexpectedly started on the interactive window station.'
    }

    if (Get-LocalUser -Name $callerAccount -ErrorAction SilentlyContinue) {
        throw "The reserved Sandbox caller already exists: $callerAccount"
    }
    $callerPassword = 'LaunchAsAclProbe!' + [guid]::NewGuid().ToString('N')
    $securePassword = ConvertTo-SecureString $callerPassword -AsPlainText -Force
    $callerUser = New-LocalUser `
        -Name $callerAccount `
        -Password $securePassword `
        -PasswordNeverExpires `
        -UserMayNotChangePassword
    $callerCreated = $true
    $callerCredential = [PSCredential]::new(
        "$env:COMPUTERNAME\$callerAccount", $securePassword)
    $aclResultDirectory = 'C:\Users\Public\Documents\LaunchAsInteractiveAclProbe'
    $null = New-Item -ItemType Directory -Path $aclResultDirectory -Force
    $aclResultPath = Join-Path $aclResultDirectory 'acl-lease-result.txt'
    $aclExitCodePath = Join-Path $aclResultDirectory 'acl-probe-exit-code.txt'
    $aclWrapperPath = Join-Path $workDirectory 'Run-InteractiveAclLeaseProbe.cmd'
    & icacls.exe $workDirectory /grant "*$($callerUser.SID):(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Granting the standard probe caller access to $workDirectory failed."
    }
    & icacls.exe $aclResultDirectory /grant "*$($callerUser.SID):(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Granting the standard probe caller access to $aclResultDirectory failed."
    }
    @(
        '@echo off'
        ('"{0}" "{1}"' -f $aclProbePath, $aclResultPath)
        'set "probeExitCode=%ERRORLEVEL%"'
        ('> "{0}" echo %probeExitCode%' -f $aclExitCodePath)
        'exit /b %probeExitCode%'
    ) | Set-Content -LiteralPath $aclWrapperPath -Encoding Ascii
    $aclProbe = Start-Process `
        -FilePath $env:ComSpec `
        -ArgumentList @('/d', '/s', '/c', ('"{0}"' -f $aclWrapperPath)) `
        -Credential $callerCredential `
        -LoadUserProfile `
        -WorkingDirectory $workDirectory `
        -WindowStyle Hidden `
        -PassThru
    if (-not $aclProbe.WaitForExit(30000)) {
        Stop-Process -Id $aclProbe.Id -Force -ErrorAction SilentlyContinue
        throw 'The standard-caller ACL lease probe timed out.'
    }
    $aclProbe.Refresh()
    if (-not (Test-Path -LiteralPath $aclResultPath -PathType Leaf)) {
        throw 'The standard-caller ACL lease probe did not create its result.'
    }
    if (-not (Test-Path -LiteralPath $aclExitCodePath -PathType Leaf)) {
        throw 'The standard-caller ACL lease probe did not create its exit-code result.'
    }
    $probeExitCode = [int] (Get-Content -LiteralPath $aclExitCodePath -Raw).Trim()
    $aclResult = Read-ProbeResult -Path $aclResultPath
    foreach ($key in @(
            'callerIsAdministrator',
            'callerElevated',
            'callerSid',
            'windowStationLeaseAdded',
            'windowStationLeaseRemoved',
            'desktopLeaseAdded',
            'desktopLeaseRemoved',
            'daclSemanticallyRestored',
            'independentDaclSemanticallyRestored',
            'probeSucceeded')) {
        if (-not $aclResult.ContainsKey($key)) {
            throw "The ACL lease probe omitted the required field '$key'."
        }
    }
    if ($probeExitCode -ne 0 -or
        $aclResult['callerIsAdministrator'] -ne 'false' -or
        $aclResult['callerElevated'] -ne 'false' -or
        $aclResult['windowStationLeaseAdded'] -ne 'true' -or
        $aclResult['windowStationLeaseRemoved'] -ne 'true' -or
        $aclResult['desktopLeaseAdded'] -ne 'true' -or
        $aclResult['desktopLeaseRemoved'] -ne 'true' -or
        $aclResult['daclSemanticallyRestored'] -ne 'true' -or
        $aclResult['independentDaclSemanticallyRestored'] -ne 'true' -or
        $aclResult['probeSucceeded'] -ne 'true') {
        throw "The standard-caller ACL lease probe failed with exit code '$probeExitCode'.`n$((Get-Content -LiteralPath $aclResultPath) -join [Environment]::NewLine)"
    }

    @(
        'PASS'
        "caller.processSessionId=$callerSessionId"
        "caller.activeConsoleSessionId=$($callerResult['activeConsoleSessionId'])"
        "caller.processWindowStation=$($callerResult['processWindowStation'])"
        "caller.canaryVisible=$($callerResult['canaryVisible'])"
        "system.processSessionId=$systemSessionId"
        "system.activeConsoleSessionId=$($systemResult['activeConsoleSessionId'])"
        "system.processWindowStation=$($systemResult['processWindowStation'])"
        "system.openWinSta0Error=$($systemResult['openWinSta0Error'])"
        "system.setWinSta0Error=$($systemResult['setWinSta0Error'])"
        "system.openDefaultDesktopError=$($systemResult['openDefaultDesktopError'])"
        "system.canaryVisible=$($systemResult['canaryVisible'])"
        "acl.callerIsAdministrator=$($aclResult['callerIsAdministrator'])"
        "acl.callerElevated=$($aclResult['callerElevated'])"
        "acl.callerSid=$($aclResult['callerSid'])"
        "acl.exitCode=$probeExitCode"
        "acl.windowStationLeaseAdded=$($aclResult['windowStationLeaseAdded'])"
        "acl.windowStationLeaseRemoved=$($aclResult['windowStationLeaseRemoved'])"
        "acl.desktopLeaseAdded=$($aclResult['desktopLeaseAdded'])"
        "acl.desktopLeaseRemoved=$($aclResult['desktopLeaseRemoved'])"
        "acl.daclSemanticallyRestored=$($aclResult['daclSemanticallyRestored'])"
        "acl.independentDaclSemanticallyRestored=$($aclResult['independentDaclSemanticallyRestored'])"
        "acl.probeSucceeded=$($aclResult['probeSucceeded'])"
    ) | Out-File -LiteralPath $sharedResultPath -Encoding utf8
}
catch {
    $failure = @(
        'FAIL'
        $_.Exception.Message
        $_.ScriptStackTrace
    )
    foreach ($probeResultPath in @(
            $callerResultPath,
            $systemResultPath,
            $aclResultPath,
            $aclExitCodePath)) {
        if (-not [string]::IsNullOrEmpty($probeResultPath) -and
            (Test-Path -LiteralPath $probeResultPath -PathType Leaf)) {
            $failure += "--- $(Split-Path -Leaf $probeResultPath) ---"
            $failure += Get-Content -LiteralPath $probeResultPath
        }
    }
    $failure | Out-File -LiteralPath $sharedResultPath -Encoding utf8
    throw
}
finally {
    if ($taskRegistered) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($callerCreated) {
        Remove-LocalUser -Name $callerAccount -ErrorAction SilentlyContinue
    }
    if ($null -ne $windowProcess -and -not $windowProcess.HasExited) {
        Stop-Process -Id $windowProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
