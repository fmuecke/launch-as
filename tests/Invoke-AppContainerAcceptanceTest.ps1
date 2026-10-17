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
$probe = Join-Path (Split-Path -Parent $LauncherPath) 'LauncherAppContainerProbe.exe'
$unconfinedProbe = $probe
$scope = Join-Path $ReportRoot ('appcontainer-' + [guid]::NewGuid().ToString('N'))
$work = Join-Path $scope 'work'
$outside = Join-Path $scope 'outside'
New-Item -ItemType Directory -Path $work, $outside -Force | Out-Null
$probe = Join-Path $work 'probe.exe'
& icacls.exe $scope /grant "${Account}:(OI)(CI)M" /T /Q
if ($LASTEXITCODE -ne 0) { throw 'Could not grant target account fixture access.' }
& icacls.exe $scope /setintegritylevel 'M' /T /Q
if ($LASTEXITCODE -ne 0) { throw 'Could not set fixture baseline.' }
$output = & $LauncherPath --user $Account --working-directory $work -- $unconfinedProbe --check-modify $work 2>&1
$exitCode = $LASTEXITCODE
$output | Write-Host
if ($exitCode -ne 0) { throw 'The workspace is not a Modify-only fixture.' }
function Initialize-ManagedWorkspaceFiles([string] $Workspace) {
    # Existing contents belong to the managed account, while the root remains Modify-only.
    $command = ('mkdir existing & copy /Y "{0}" probe.exe >nul & ' +
        'echo existing>existing\old.txt & echo previous workspace>outside.txt & ' +
        'if not exist "%USERPROFILE%\appcontainer-existing" mkdir "%USERPROFILE%\appcontainer-existing"') -f $unconfinedProbe
    $output = & $LauncherPath --user $Account --working-directory $Workspace -- `
        C:\Windows\System32\cmd.exe /d /c $command 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Could not create managed-account-owned workspace fixtures.' }
    $output | Write-Host
    $output = & $LauncherPath --user $Account --working-directory $Workspace -- `
        C:\Windows\System32\cmd.exe /d /c 'echo history>"%USERPROFILE%\appcontainer-existing\history.txt"' 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the existing profile fixture.' }
    $output | Write-Host
}
Initialize-ManagedWorkspaceFiles $work
# The folder owner can prepare this label; the created file then inherits Low.
& icacls.exe $outside /setintegritylevel '(OI)(CI)L' /Q
if ($LASTEXITCODE -ne 0) { throw 'Could not establish the Low outside-directory baseline.' }
# A Low outside file owned by the managed account isolates the AppContainer ACL check from MIC.
$output = & $LauncherPath --user $Account --working-directory $outside -- `
    C:\Windows\System32\cmd.exe /d /c 'echo outside>outside.txt' 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Could not create the managed-account-owned outside file.' }
$output | Write-Host
$outsideFile = Join-Path $outside 'outside.txt'
$expectedOwner = ([Security.Principal.NTAccount]::new("$env:COMPUTERNAME\$Account")).Translate(
    [Security.Principal.SecurityIdentifier]).Value
if ((Get-Acl $outsideFile).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $expectedOwner) {
    throw 'Outside fixture is not owned by the managed account.'
}
$outsideAcl = (Get-Acl $outsideFile).Sddl
# Propagation must not use SYSTEM rights to update a caller-owned hard link.
Set-Content (Join-Path $outside 'shared.txt') 'caller-owned shared file'
$sharedAcl = (Get-Acl (Join-Path $outside 'shared.txt')).Sddl
New-Item -ItemType HardLink -Path (Join-Path $work 'hardlink.txt') -Value (Join-Path $outside 'shared.txt') | Out-Null
& cmd.exe /d /c mklink /J (Join-Path $work 'junction') $outside
if ($LASTEXITCODE -ne 0) { throw 'Could not create junction fixture.' }

$callerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function New-ProtectedCanary([string] $Path) {
    Set-Content $Path 'protected child'
    & icacls.exe $Path /inheritance:r /grant:r "*${callerSid}:F" '*S-1-5-18:F' /deny "${Account}:F" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the child canary.' }
    return (Get-Acl $Path).Sddl
}
$protectedPath = Join-Path $work 'protected.txt'
$protectedAcl = New-ProtectedCanary $protectedPath

$names = @()
foreach ($capability in @('', 'internetClient', 'S-1-15-3-1')) {
    $options = @('--appcontainer')
    $expected = 'minimal'
    if ($capability) { $options += @('--appcontainer-capability', $capability); $expected = 'capability' }
    $output = & $LauncherPath --user $Account @options --working-directory $work -- $probe $work $outside $expected 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String
    $output | Write-Host
    if ($exitCode -ne 0 -or $text -notmatch 'AppContainer token, file, process and descendant probes passed') {
        throw "AppContainer acceptance failed for '$capability' (exit $exitCode)."
    }
    if ($text -notmatch 'AppContainer: (launch-as-[0-9a-f]{48})') { throw 'Missing AppContainer identity.' }
    $names += $Matches[1]
}
if ($names[0] -eq $names[1] -or $names[1] -ne $names[2]) { throw 'Capability identities are not stable and distinct.' }

# Relaunch must prepare managed-account-owned files moved in after the root grant exists.
New-Item -ItemType Directory -Path (Join-Path $work 'late') | Out-Null
Set-Content (Join-Path $work 'late\inherited.txt') 'inherited'
$moved = Join-Path $scope 'moved-in.txt'
Set-Content $moved 'keep original permissions'
$movedAcl = (Get-Acl $moved).Sddl
Move-Item -LiteralPath $moved -Destination $work
$output = & $LauncherPath --user $Account --working-directory $scope -- `
    C:\Windows\System32\cmd.exe /d /c 'echo moved>managed-moved-in.txt' 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Could not create the managed moved-in fixture.' }
$output | Write-Host
Move-Item -LiteralPath (Join-Path $scope 'managed-moved-in.txt') -Destination $work
$output = & $LauncherPath --user $Account --appcontainer --working-directory $work -- `
    $probe --check-relaunch $work 2>&1
$exitCode = $LASTEXITCODE
$output | Write-Host
if ($exitCode -ne 0 -or ($output | Out-String) -notmatch 'AppContainer inheritance and relaunch propagation probes passed' -or
    (Get-Acl (Join-Path $work 'moved-in.txt')).Sddl -ne $movedAcl) {
    throw 'AppContainer relaunch failed propagation or changed a foreign-owned file.'
}

# The previous tree is now Low and explicitly grants other container identities.
# A new workspace must still be unable to read it, including through aliases.
$second = Join-Path $scope 'second-work'
New-Item -ItemType Directory -Path $second -Force | Out-Null
& icacls.exe $second /grant "${Account}:(OI)(CI)M" /T /Q
if ($LASTEXITCODE -ne 0) { throw 'Could not grant second workspace access.' }
Initialize-ManagedWorkspaceFiles $second
$secondProtectedPath = Join-Path $second 'protected.txt'
$secondProtectedAcl = New-ProtectedCanary $secondProtectedPath
Set-Content (Join-Path $work 'shared.txt') 'caller-owned shared file'
New-Item -ItemType HardLink -Path (Join-Path $second 'hardlink.txt') -Value (Join-Path $work 'shared.txt') | Out-Null
& cmd.exe /d /c mklink /J (Join-Path $second 'junction') $work
if ($LASTEXITCODE -ne 0) { throw 'Could not create second junction.' }
$output = & $LauncherPath --user $Account --appcontainer --working-directory $second -- `
    (Join-Path $second 'probe.exe') $second $work 'minimal' 2>&1
$exitCode = $LASTEXITCODE
$output | Write-Host
$text = $output | Out-String
if ($exitCode -ne 0 -or $text -notmatch 'AppContainer token, file, process and descendant probes passed' -or
    $text -notmatch 'AppContainer: (launch-as-[0-9a-f]{48})' -or $Matches[1] -eq $names[0]) {
    throw "Workspace identity isolation failed (exit $exitCode)."
}

# Check a system console executable independently of the native probe runtime.
$output = & $LauncherPath --user $Account --appcontainer --working-directory $work -- `
    C:\Windows\System32\cmd.exe /d /c echo appcontainer-cmd-passed 2>&1
$exitCode = $LASTEXITCODE
$output | Write-Host
if ($exitCode -ne 0 -or ($output | Out-String) -notmatch 'appcontainer-cmd-passed') {
    throw "AppContainer cmd.exe smoke test failed (exit $exitCode)."
}

# An explicit inheritable Medium label cannot be assigned to new files by a Low creator.
# Minimal AppContainer preparation must preserve that policy instead of lowering it.
$mediumInheritance = Join-Path $work 'medium-inheritance'
New-Item -ItemType Directory $mediumInheritance | Out-Null
& icacls.exe $mediumInheritance /setintegritylevel '(OI)(CI)M' /Q
if ($LASTEXITCODE -ne 0) { throw 'Could not create the explicit label fixture.' }
$output = & $LauncherPath --user $Account --appcontainer --working-directory $work -- `
    $probe --check-medium-create-denied $mediumInheritance 2>&1
$exitCode = $LASTEXITCODE
$output | Write-Host
if ($exitCode -ne 0 -or ($output | Out-String) -notmatch 'Explicit inheritable Medium label preserved') {
    throw 'AppContainer preparation did not preserve explicit integrity policy.'
}

# A broker metadata operation must not turn a read-only workspace into an allowed one.
$readOnly = Join-Path $scope 'readonly-work'
New-Item -ItemType Directory $readOnly -Force | Out-Null
& icacls.exe $readOnly /deny "${Account}:(WD,AD,WEA,WA,D)" /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create the unauthorized workspace fixture.' }
$readOnlyAcl = (Get-Acl $readOnly).Sddl
try {
    $ErrorActionPreference = 'Continue'
    $output = & $LauncherPath --user $Account --appcontainer --working-directory $readOnly -- `
        C:\Windows\System32\cmd.exe /d /c exit 0 2>&1
} finally { $ErrorActionPreference = 'Stop' }
if ($LASTEXITCODE -eq 0 -or (Get-Acl $readOnly).Sddl -ne $readOnlyAcl) {
    throw 'The broker prepared a workspace without account Modify access.'
}
$output | Write-Host

# Non-capability SIDs must fail without falling back to an unrestricted launch.
try {
    $ErrorActionPreference = 'Continue'
    $output = & $LauncherPath --user $Account --appcontainer --appcontainer-capability 'S-1-5-18' `
        --working-directory $work -- C:\Windows\System32\cmd.exe /d /c exit 0 2>&1
} finally { $ErrorActionPreference = 'Stop' }
if ($LASTEXITCODE -eq 0) { throw 'A non-capability SID was accepted.' }
$output | Write-Host
try {
    $ErrorActionPreference = 'Continue'
    $output = & $LauncherPath --user $Account --appcontainer --working-directory C:\Windows -- `
        C:\Windows\System32\cmd.exe /d /c exit 0 2>&1
} finally { $ErrorActionPreference = 'Stop' }
if ($LASTEXITCODE -eq 0) { throw 'A protected system workspace was prepared.' }
$output | Write-Host
if ((Get-Content (Join-Path $outside 'outside.txt') -Raw).Trim() -ne 'outside') { throw 'Outside file changed.' }
if ((Get-Acl $outsideFile).Sddl -ne $outsideAcl) { throw 'Outside ACL changed through an alias.' }
if ((Get-Acl (Join-Path $outside 'shared.txt')).Sddl -ne $sharedAcl) { throw 'A foreign-owned hard-link ACL changed.' }
if ((Get-Acl $protectedPath).Sddl -ne $protectedAcl -or
    (Get-Acl $secondProtectedPath).Sddl -ne $secondProtectedAcl) { throw 'The broker changed an unauthorized child ACL.' }
Write-Host 'AppContainer installed acceptance passed'
