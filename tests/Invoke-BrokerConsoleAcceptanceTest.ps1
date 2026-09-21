# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Account,
    [ValidateRange(0, [int]::MaxValue)]
    [int]$ExpectedExitCode = 0,
    [string]$LauncherPath = (
        Join-Path $PSScriptRoot '..\out\build\Release\launch-as.exe'
    ),
    [string]$ProbePath = (
        Join-Path $PSScriptRoot '..\out\build\Release\LauncherBrokerChildIdentityProbe.exe'
    ),
    [string]$ReportRoot = (Join-Path $env:PUBLIC 'Documents'),
    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$CallerWindowProcessId
)

$caller = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent())
if ($caller.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this acceptance test from the authorised non-elevated user session.'
}

$launcher = Resolve-Path -LiteralPath $LauncherPath
$probe = Resolve-Path -LiteralPath $ProbePath
$workingDirectory = Join-Path $env:PUBLIC 'Documents'
if (-not (Test-Path -LiteralPath $workingDirectory -PathType Container)) {
    $workingDirectory = $env:PUBLIC
}

${interactiveWindow} = Get-Process -Id $CallerWindowProcessId -ErrorAction Stop
if ($interactiveWindow.MainWindowHandle -eq 0) {
    throw "Caller process $CallerWindowProcessId does not own a visible window."
}
$interactiveLogonSid = (& whoami /logonid | Select-Object -Last 1).Trim()
if ($interactiveLogonSid -notmatch '^S-1-5-5-\d+-\d+$') {
    throw "Could not determine the interactive user's logon SID: $interactiveLogonSid"
}
$windowHandle = [uint64]$interactiveWindow.MainWindowHandle.ToInt64()
$resolvedReportRoot = Resolve-Path -LiteralPath $ReportRoot
$reportDirectory = Join-Path $resolvedReportRoot.Path `
    ("launch-as-probe-{0}" -f [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($reportDirectory) | Out-Null
$authenticatedUsersSid = [System.Security.Principal.SecurityIdentifier]::new(
    [System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid, $null)
$reportDirectoryAcl = Get-Acl -LiteralPath $reportDirectory
$reportDirectoryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $authenticatedUsersSid,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow))
Set-Acl -LiteralPath $reportDirectory -AclObject $reportDirectoryAcl
$reportPath = Join-Path $reportDirectory 'probe.txt'

try {
    Write-Host "Launching the identity probe as managed account $Account. It must report a different logon SID and not access this interactive process or enumerate its window."
    $output = & $launcher.Path --user $Account --working-directory $workingDirectory -- `
        $probe.Path --window $windowHandle --process $PID --exit-code $ExpectedExitCode `
        --interactive-logon-sid $interactiveLogonSid --output $reportPath 2>&1
    $exitCode = $LASTEXITCODE
    $output | Write-Host
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        $launcherOutput = ($output | Out-String).TrimEnd()
        throw (
            "Broker child did not write its probe report: $reportPath " +
            "(broker exit code $exitCode). Output:`n$launcherOutput"
        )
    }
    $outputText = Get-Content -LiteralPath $reportPath -Raw

    function Get-ProbeValue([string]$Name) {
        $match = [regex]::Match($outputText, '(?im)^' + [regex]::Escape($Name) + '\s*=\s*(.+)$')
        if ($match.Success) {
            return $match.Groups[1].Value.Trim()
        }
        return ''
    }

    $childLogonSid = [regex]::Match($outputText, '(?i)logonSid\s*=\s*(S-1-5-5-\d+-\d+)').Groups[1].Value
    $reportedAccount = Get-ProbeValue 'account'
    if (-not [string]::Equals($reportedAccount, $Account, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Broker console reported account '$reportedAccount'; expected '$Account'."
    }
    $reportedUsername = Get-ProbeValue 'USERNAME'
    if (-not [string]::Equals($reportedUsername, $Account, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Broker child USERNAME was '$reportedUsername'; expected '$Account'. Output:`n$outputText"
    }
    if ($outputText -match '(?i)(appdata|localappdata|userprofile)\s*=.*systemprofile') {
        throw "Broker child inherited the service profile environment. Output:`n$outputText"
    }
    if ([string]::IsNullOrWhiteSpace($childLogonSid)) {
        throw 'Broker console output did not include the child logon SID.'
    }
    if ($childLogonSid -eq $interactiveLogonSid) {
        throw 'The broker child reused the interactive user logon SID.'
    }
    if ($outputText -notmatch '(?i)interactiveLogonSidPresentInTokenGroups\s*=\s*false') {
        throw "The broker child's TokenGroups contain the interactive user logon SID."
    }
    if ($outputText -notmatch '(?i)interactiveWindowVisible\s*=\s*false') {
        throw "The broker child enumerated interactive window $($interactiveWindow.Id)."
    }
    if ($outputText -notmatch '(?i)interactiveProcessVmReadDenied\s*=\s*true') {
        throw 'The broker child could read the interactive PowerShell process.'
    }
    if ($outputText -notmatch '(?i)interactiveProcessTerminateDenied\s*=\s*true') {
        throw 'The broker child could terminate the interactive PowerShell process.'
    }
    if ($exitCode -ne $ExpectedExitCode) {
        throw "Broker console launch returned exit code $exitCode; expected $ExpectedExitCode."
    }
}
finally {
    Remove-Item -LiteralPath $reportDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
