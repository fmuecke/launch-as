# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Account,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LauncherPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ProbePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ReportRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$caller = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($caller.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this acceptance test from the authorised non-elevated user session.'
}

$launcher = Resolve-Path -LiteralPath $LauncherPath
$probe = Resolve-Path -LiteralPath $ProbePath
$reportDirectory = Join-Path $ReportRoot (
    'launch-as-interactive-{0}' -f [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($reportDirectory) | Out-Null
$authenticatedUsersSid = [Security.Principal.SecurityIdentifier]::new(
    [Security.Principal.WellKnownSidType]::AuthenticatedUserSid, $null)
$reportAcl = Get-Acl -LiteralPath $reportDirectory
$reportAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $authenticatedUsersSid,
        [Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
Set-Acl -LiteralPath $reportDirectory -AclObject $reportAcl

$reportPath = Join-Path $reportDirectory 'target.txt'
$stdoutPath = Join-Path $reportDirectory 'launcher.stdout.txt'
$stderrPath = Join-Path $reportDirectory 'launcher.stderr.txt'
$exitCodePath = Join-Path $reportDirectory 'launcher.exit-code.txt'
$wrapperPath = Join-Path $reportDirectory 'launch-interactive.cmd'
$windowTitle = 'launch-as-interactive-acceptance-' + [guid]::NewGuid().ToString('N')
$callerLogonSid = (& whoami /logonid | Select-Object -Last 1).Trim()
$callerSessionId = (Get-Process -Id $PID).SessionId
$launcherProcess = $null

try {
    @(
        '@echo off'
        ('"{0}" --mode interactive --user "{1}" --working-directory "{2}" -- "{3}" "{4}" "{5}" 4000' -f `
                $launcher.Path, $Account, $reportDirectory, $probe.Path, $reportPath, $windowTitle)
        'set "launcherExitCode=%ERRORLEVEL%"'
        ('> "{0}" echo %launcherExitCode%' -f $exitCodePath)
        'exit /b %launcherExitCode%'
    ) | Set-Content -LiteralPath $wrapperPath -Encoding Ascii
    $launcherProcess = Start-Process `
        -FilePath $env:ComSpec `
        -ArgumentList @('/d', '/s', '/c', ('"{0}"' -f $wrapperPath)) `
        -NoNewWindow `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -PassThru

    $reportDeadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $reportPath -PathType Leaf) -and
        -not $launcherProcess.HasExited -and [DateTime]::UtcNow -lt $reportDeadline) {
        Start-Sleep -Milliseconds 100
        $launcherProcess.Refresh()
    }
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw 'The installed interactive target did not write its report.'
    }
    $targetReport = Get-Content -LiteralPath $reportPath -Raw
    function Get-TargetValue([string] $Name) {
        $match = [regex]::Match(
            $targetReport, '(?im)^' + [regex]::Escape($Name) + '\s*=\s*(.+)$')
        if ($match.Success) {
            return $match.Groups[1].Value.Trim()
        }
        return ''
    }

    if ((Get-TargetValue 'probeSucceeded') -ne 'true') {
        throw "The installed interactive target reported failure.`n$targetReport"
    }
    if ([int](Get-TargetValue 'processSessionId') -ne $callerSessionId -or
        (Get-TargetValue 'processWindowStation') -ne 'WinSta0' -or
        (Get-TargetValue 'threadDesktop') -ne 'Default') {
        throw "The installed interactive target was not placed on the caller desktop.`n$targetReport"
    }
    $targetLogonSid = Get-TargetValue 'tokenLogonSid'
    if ($targetLogonSid -notmatch '^S-1-5-5-\d+-\d+$' -or
        $targetLogonSid -eq $callerLogonSid) {
        throw "The installed interactive target did not use an independent logon SID.`n$targetReport"
    }
    $visibleWindow = Get-Process | Where-Object { $_.MainWindowTitle -eq $windowTitle }
    if ($null -eq $visibleWindow) {
        throw 'The installed interactive target did not expose its expected shared-desktop window.'
    }

    if (-not $launcherProcess.WaitForExit(15000)) {
        throw 'The interactive launcher did not finish after the target process tree exited.'
    }
    if (-not (Test-Path -LiteralPath $exitCodePath -PathType Leaf)) {
        throw 'The interactive launcher did not write its exit-code result.'
    }
    $launcherExitCode = [int](Get-Content -LiteralPath $exitCodePath -Raw).Trim()
    if ($launcherExitCode -ne 0) {
        throw "The interactive launcher returned exit code $launcherExitCode."
    }
    Write-Host 'Installed interactive launch passed: caller session, WinSta0\\Default, independent logon SID, visible window, and lease release.'
}
finally {
    if ($null -ne $launcherProcess -and -not $launcherProcess.HasExited) {
        Stop-Process -Id $launcherProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
        Get-Content -LiteralPath $stdoutPath | Write-Host
    }
    if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
        Get-Content -LiteralPath $stderrPath | Write-Host
    }
    Remove-Item -LiteralPath $reportDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
