# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Account,
    [Parameter(Mandatory)][string] $LauncherPath,
    [Parameter(Mandatory)][string] $ReportRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scopeRoot = Join-Path $ReportRoot ('read-scope-' + [guid]::NewGuid().ToString('N'))
$outside = Join-Path $scopeRoot 'outside'
$works = @((Join-Path $scopeRoot 'work-one'), (Join-Path $scopeRoot 'work-two'))
$consoleWorks = @((Join-Path $scopeRoot 'console-medium'), (Join-Path $scopeRoot 'console-low'))
$probeSource = Join-Path (Split-Path -Parent $LauncherPath) 'LauncherBrokerWriteScopeProbe.exe'
$interactiveProbeSource = Join-Path (Split-Path -Parent $LauncherPath) 'LauncherBrokerReadScopeInteractiveProbe.exe'
$sid = [Security.Principal.NTAccount]::new($Account).Translate([Security.Principal.SecurityIdentifier])
$clients = @()
$logPath = Join-Path $env:LOCALAPPDATA 'launch-as\launch-as.log'

function Wait-ReadScopeCondition {
    param([scriptblock] $Condition, [string] $Description)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (& $Condition)) {
        if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out: $Description" }
        Start-Sleep -Milliseconds 100
    }
}

function Has-ReadScopeDeny {
    param([string] $Path = $outside)
    return @((Get-Acl -LiteralPath $Path).Access | Where-Object {
        $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value -eq $sid.Value
    }).Count -gt 0
}

function Invoke-FailedReadScopeLaunch {
    param([string] $InvalidImage, [switch] $Log)
    $flags = @('--restrict-access')
    if ($Log) { $flags += '--log' }
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $LauncherPath --user $Account --mode interactive @flags `
            --working-directory $works[0] -- $InvalidImage 2>&1
    } finally { $ErrorActionPreference = 'Stop' }
    if ($LASTEXITCODE -eq 0) { throw 'An invalid executable unexpectedly launched.' }
    $output | Write-Host
    $rejected = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'launch-as-broker' } `
        -MaxEvents 5 | Where-Object {
            $fields = @($_.Properties | ForEach-Object Value)
            # CreateProcess and CreateProcessAsUser can report different image-loading errors.
            ($fields -contains 'win32Error=2' -or $fields -contains 'win32Error=193' -or
                $fields -contains 'win32Error=216') -and $fields -contains 'restrictAccess=true' -and
                $fields -contains 'readScopePath='
        })
    if ($rejected.Count -eq 0) { throw 'The broker did not audit the invalid-image rejection.' }
}

try {
    $null = New-Item -ItemType Directory -Path $outside
    Set-Content -LiteralPath (Join-Path $outside 'outside.txt') -Value 'outside'
    foreach ($work in ($works + $consoleWorks)) {
        $null = New-Item -ItemType Directory -Path (Join-Path $work 'existing')
        Set-Content -LiteralPath (Join-Path $work 'existing\old.txt') -Value 'existing'
        Copy-Item -LiteralPath $probeSource -Destination $work
        Copy-Item -LiteralPath $interactiveProbeSource -Destination $work
        & cmd.exe /d /c mklink /J (Join-Path $work 'junction') $outside
        if ($LASTEXITCODE -ne 0) { throw 'Could not create read-scope junction fixture.' }
    }
    & icacls.exe $scopeRoot /grant "${Account}:(OI)(CI)F" /T /Q
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant target access to read-scope fixtures.' }
    # Protected child access must still fail through the denied base folder.
    $file = Join-Path $outside 'outside.txt'
    $acl = Get-Acl -LiteralPath $file
    $acl.SetAccessRuleProtection($true, $true)
    Set-Acl -LiteralPath $file -AclObject $acl
    $original = (Get-Acl -LiteralPath $outside).Sddl
    $rootOriginal = (Get-Acl -LiteralPath 'C:\').Sddl

    foreach ($low in @($false, $true)) {
        # Persistent Low labels include the copied executable. Keep each variant separate
        # so the later Medium interactive probe uses a Medium-labelled executable.
        $work = $consoleWorks[[int]$low]
        $flags = @('--restrict-access')
        if ($low) { $flags += '--low-integrity' }
        $integrity = if ($low) { 'low' } else { 'medium' }
        $probe = Join-Path $work 'LauncherBrokerWriteScopeProbe.exe'
        $output = & $LauncherPath --user $Account --log @flags --working-directory $work -- `
            $probe $work $outside $integrity 'access' 2>&1
        $code = $LASTEXITCODE
        $output | Write-Host
        if ($code -ne 0 -or ($output | Out-String) -notmatch
                'Read-scope installed launch and descendant probes passed') {
            throw "Read-restricted console launch failed (exit $code)."
        }
        Wait-ReadScopeCondition { -not (Has-ReadScopeDeny) } 'console ACL restoration'
        if ((Get-Acl -LiteralPath $outside).Sddl -ne $original -or
            (Get-Acl -LiteralPath 'C:\').Sddl -ne $rootOriginal) {
            throw 'Console exit changed the original ACLs.'
        }
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application';
            ProviderName = 'launch-as-broker'; Id = 7 } -MaxEvents 2000)
        $logged = @($events | Where-Object {
            @($_.Properties | ForEach-Object Value) -contains "path=$work"
        } | Select-Object -First 1)
        if ($logged.Count -eq 0) { throw 'The --log launch did not record its working directory.' }
        $requestField = @($logged[0].Properties | ForEach-Object Value |
            Where-Object { $_ -like 'requestId=*' })[0]
        $diagnostics = @($events | Where-Object {
            @($_.Properties | ForEach-Object Value) -contains $requestField
        })
        foreach ($action in @('launch.begin', 'launch.account_logged_on', 'launch.started',
                'read.deny_selected', 'read.excluded_from_deny', 'read.ancestor_traverse', 'read.restore')) {
            if (@($diagnostics | Where-Object {
                    @($_.Properties | ForEach-Object Value) -contains "action=$action"
                }).Count -eq 0) { throw "The --log launch omitted $action." }
        }
        $deny = @($diagnostics | Where-Object {
            $fields = @($_.Properties | ForEach-Object Value)
            $fields -contains 'action=read.deny_selected' -and
                @($fields | Where-Object { $_ -like 'path=*\outside' }).Count -gt 0
        })
        $exclusion = @($diagnostics | Where-Object {
            $fields = @($_.Properties | ForEach-Object Value)
            $fields -contains 'action=read.excluded_from_deny' -and
                @($fields | Where-Object { $_ -like ('path=*\' + (Split-Path -Leaf $work)) }).Count -gt 0
        })
        if ($deny.Count -eq 0 -or $exclusion.Count -eq 0) {
            throw 'The --log launch did not identify the denied and excluded fixture folders.'
        }
        $text = @(Get-Content -LiteralPath $logPath -Encoding UTF8 |
            Where-Object { $_.Contains($requestField) })
        $brokerLines = @($text | Where-Object { $_.Contains('component=launch-as-broker') })
        if ($brokerLines.Count -ne $diagnostics.Count -or
            @($text | Where-Object { $_ -match 'action=client\.log_' }).Count -gt 0) {
            throw 'The text log did not copy each broker diagnostic exactly once.'
        }
        foreach ($action in @('launch.begin', 'read.deny_selected', 'read.excluded_from_deny',
                'read.restore', 'session.closed')) {
            if (@($text | Where-Object { $_.Contains("action=$action") }).Count -eq 0) {
                throw "The text log omitted $action."
            }
        }
        $marker = Join-Path $work 'descendant-passed.txt'
        Remove-Item -LiteralPath $marker -Force
        $probe = Join-Path $work 'LauncherBrokerReadScopeInteractiveProbe.exe'
        $beforeGui = Get-Content -LiteralPath $logPath -Raw -Encoding UTF8
        $output = & $LauncherPath --user $Account --mode interactive --log @flags --working-directory $work -- `
            $probe $work $outside $integrity 'access' 'descendant' 2>&1
        $output | Write-Host
        if ($LASTEXITCODE -ne 0) { throw "Read-restricted GUI launch failed: $integrity." }
        Wait-ReadScopeCondition { Test-Path -LiteralPath $marker } "GUI probe completion: $integrity"
        Wait-ReadScopeCondition { -not (Has-ReadScopeDeny) } 'GUI ACL restoration'
        if ((Get-Acl -LiteralPath $outside).Sddl -ne $original -or
            (Get-Acl -LiteralPath 'C:\').Sddl -ne $rootOriginal) {
            throw 'GUI exit changed the original ACLs.'
        }
        $guiText = (Get-Content -LiteralPath $logPath -Raw -Encoding UTF8).Substring($beforeGui.Length)
        foreach ($action in @('launch.begin', 'read.deny_selected', 'read.restore', 'session.closed')) {
            if (-not $guiText.Contains("action=$action")) { throw "The GUI text log omitted $action." }
        }
        if ($guiText -match 'action=client\.log_') { throw 'The GUI text log reported a collection failure.' }
    }

    $loggedText = Get-Content -LiteralPath $logPath -Raw -Encoding UTF8

    # Two live sessions share a scope; the second launch adds its working directory.
    foreach ($work in $works) {
        $probe = Join-Path $work 'LauncherBrokerReadScopeInteractiveProbe.exe'
        $integrity = if ($clients.Count -eq 0) { 'medium' } else { 'low' }
        $flags = @('--restrict-access')
        if ($integrity -eq 'low') { $flags += '--low-integrity' }
        $arguments = @('--user', $Account, '--mode', 'interactive') + $flags + @(
            '--working-directory', $work, '--', $probe, $work, $outside, $integrity, 'access', 'hold')
        $client = Start-Process -FilePath $LauncherPath -ArgumentList (
            $arguments | ForEach-Object { '"{0}"' -f $_ }) -NoNewWindow -PassThru `
            -RedirectStandardOutput (Join-Path $work 'client.stdout.log') `
            -RedirectStandardError (Join-Path $work 'client.stderr.log')
        # Cache the native handle before PowerShell 5.1 reaps the redirected process.
        $null = $client.Handle
        $clients += $client
        Wait-ReadScopeCondition {
            if ($client.HasExited) {
                $details = foreach ($name in @('client.stdout.log', 'client.stderr.log',
                        'probe.stdout.log', 'probe.stderr.log')) {
                    $log = Join-Path $work $name
                    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Raw }
                }
                throw "Read-restricted interactive launch exited: $($details -join [Environment]::NewLine)"
            }
            Test-Path -LiteralPath (Join-Path $work 'ready.txt')
        } 'interactive read-scope readiness'
        if ($clients.Count -eq 1) {
            try {
                $ErrorActionPreference = 'Continue'
                $output = & $LauncherPath --user $Account --mode interactive --working-directory $work -- `
                    C:\Windows\System32\cmd.exe /d /c exit 0 2>&1
            } finally { $ErrorActionPreference = 'Stop' }
            if ($LASTEXITCODE -eq 0) { throw 'An unrestricted launch joined a read-restricted account scope.' }
            $output | Write-Host
            $newBase = Join-Path $scopeRoot 'created-during-session'
            $null = New-Item -ItemType Directory -Path $newBase
            if (Has-ReadScopeDeny $newBase) {
                throw 'A folder created between launches unexpectedly inherited a scope deny.'
            }
        } elseif (-not (Has-ReadScopeDeny $newBase)) {
            throw 'The second launch did not cover a newly created base folder.'
        }
    }
    Set-Content -LiteralPath (Join-Path $works[0] 'release.txt') -Value 'release'
    if (-not $clients[0].WaitForExit(30000) -or $clients[0].ExitCode -ne 0) {
        throw "The first read-restricted session did not close successfully (exit $($clients[0].ExitCode))."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $works[0] 'descendant-passed.txt'))) {
        throw 'The first interactive scope probe did not finish its assertions.'
    }
    if (-not (Has-ReadScopeDeny) -or $clients[1].HasExited) {
        throw 'Closing the first session released the shared read scope.'
    }
    # A failed launch must still assure the ACLs while another session retains the scope.
    $invalid = Join-Path $works[0] 'invalid.exe'
    $image = New-Object byte[] 128
    $image[0] = 0x4d; $image[1] = 0x5a
    $image[60] = 64
    $image[64] = 0x50; $image[65] = 0x45
    $image[68] = 0x64; $image[69] = 0x86
    [IO.File]::WriteAllBytes($invalid, $image)
    $failedBase = Join-Path $scopeRoot 'created-before-failed-launch'
    $null = New-Item -ItemType Directory -Path $failedBase
    if (Has-ReadScopeDeny $failedBase) { throw 'The new failure fixture inherited a scope deny.' }
    Invoke-FailedReadScopeLaunch $invalid
    if (-not (Has-ReadScopeDeny $failedBase) -or $clients[1].HasExited) {
        throw 'The failed launch did not assure and retain the active scope ACLs.'
    }
    Set-Content -LiteralPath (Join-Path $works[1] 'release.txt') -Value 'release'
    if (-not $clients[1].WaitForExit(30000) -or $clients[1].ExitCode -ne 0) {
        throw "The last read-restricted session did not close successfully (exit $($clients[1].ExitCode))."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $works[1] 'descendant-passed.txt'))) {
        throw 'The last interactive scope probe did not finish its assertions.'
    }
    Wait-ReadScopeCondition { -not (Has-ReadScopeDeny) } 'last-session ACL restoration'
    if ((Get-Acl -LiteralPath $outside).Sddl -ne $original -or
        (Get-Acl -LiteralPath 'C:\').Sddl -ne $rootOriginal) {
        throw 'The last session did not restore the original ACLs.'
    }
    # The same creation failure in a fresh scope must restore its temporary ACL changes.
    Invoke-FailedReadScopeLaunch $invalid
    Wait-ReadScopeCondition { -not (Has-ReadScopeDeny) } 'failed-launch ACL restoration'
    if ((Get-Acl -LiteralPath $outside).Sddl -ne $original -or
        (Get-Acl -LiteralPath 'C:\').Sddl -ne $rootOriginal) {
        throw 'The failed broker launch changed the original ACLs.'
    }
    if ((Get-Content -LiteralPath $logPath -Raw -Encoding UTF8) -ne $loggedText) {
        throw 'A launch without --log changed the caller text log.'
    }
    Invoke-FailedReadScopeLaunch $invalid -Log
    $failedText = (Get-Content -LiteralPath $logPath -Raw -Encoding UTF8).Substring($loggedText.Length)
    foreach ($action in @('launch.failed', 'client.launch_failed', 'read.deny_selected', 'read.restore')) {
        if (-not $failedText.Contains("action=$action")) { throw "The failed-launch log omitted $action." }
    }
    if ($failedText -match 'action=client\.log_') { throw 'The failed-launch log reported a collection failure.' }
    Write-Host 'Read-scope and text-log acceptance passed'
}
catch {
    Write-Host "Read-scope failure: $($_.Exception.Message)"
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'launch-as-broker' } `
        -MaxEvents 5 -ErrorAction Continue | ForEach-Object {
            $_.Properties | ForEach-Object Value | Where-Object {
                $_ -match '^(readScopePath|win32Error|operation)='
            } | Write-Host
        }
    throw
}
finally {
    if (Test-Path -LiteralPath $logPath) {
        Copy-Item -LiteralPath $logPath -Destination (Join-Path $ReportRoot 'launch-as.log') -Force
    }
    foreach ($work in $works) {
        if (Test-Path -LiteralPath $work) {
            Set-Content -LiteralPath (Join-Path $work 'release.txt') -Value 'release'
        }
    }
    foreach ($client in $clients) {
        if (-not $client.HasExited -and -not $client.WaitForExit(30000)) {
            Stop-Process -Id $client.Id -Force
            $client.WaitForExit()
        }
    }
    if ($clients.Count -gt 0) {
        Wait-ReadScopeCondition { -not (Has-ReadScopeDeny) } 'cleanup ACL restoration'
    }
    # Remove only this fixture, and remove junction objects without traversing their targets.
    foreach ($work in ($works + $consoleWorks)) {
        $junction = Join-Path $work 'junction'
        if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction) }
    }
    $resolvedRoot = [IO.Path]::GetFullPath($ReportRoot) + [IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($scopeRoot).StartsWith($resolvedRoot,
            [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid read-scope fixture cleanup path.' }
    Remove-Item -LiteralPath $scopeRoot -Recurse -Force
}
