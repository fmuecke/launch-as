# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $SandboxUser = 'ClaudeSandbox',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $LauncherPath = (
        Join-Path $PSScriptRoot `
            '..\..\out\build-native\native\Release\ClaudeSandboxLauncher.exe'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-LauncherStep {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string[]] $Arguments,

        [Parameter()]
        [int] $ExpectedExitCode = 0
    )

    Write-Host "`n[$Name]"
    & $script:ResolvedLauncher @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne $ExpectedExitCode) {
        throw (
            "$Name returned launcher exit code $exitCode; " +
            "expected $ExpectedExitCode."
        )
    }
}

$script:ResolvedLauncher = [System.IO.Path]::GetFullPath($LauncherPath)
if (-not (Test-Path -LiteralPath $script:ResolvedLauncher -PathType Leaf)) {
    throw "Launcher not found: $script:ResolvedLauncher"
}

$localUser = Get-LocalUser -Name $SandboxUser -ErrorAction Stop
if (-not $localUser.Enabled) {
    throw "Local user '$SandboxUser' is disabled."
}

$administrators = Get-LocalGroup -SID 'S-1-5-32-544'
$isAdministrator = Get-LocalGroupMember -Group $administrators |
    Where-Object { $_.SID -eq $localUser.SID }
if ($null -ne $isAdministrator) {
    throw "Local user '$SandboxUser' is an administrator; use a standard sandbox user."
}

$testCredentialTag =
    'acceptance-' + [Guid]::NewGuid().ToString('N')
try {
    Write-Host "Acceptance user: .\$SandboxUser"
    Write-Host 'The credential is stored for the Windows user running this test.'
    Write-Host "Temporary credential tag: $testCredentialTag"
    Write-Host 'Enter the sandbox account password at the native secure prompt.'

    Invoke-LauncherStep -Name 'Register and store credential' -Arguments @(
        'register',
        '--user',
        $SandboxUser,
        '--test-credential-tag',
        $testCredentialTag
    )

    Invoke-LauncherStep -Name 'Read credential-store status' -Arguments @(
        'status',
        '--user',
        $SandboxUser,
        '--test-credential-tag',
        $testCredentialTag
    )

    $commandPrompt = Join-Path $env:SystemRoot 'System32\cmd.exe'
    Invoke-LauncherStep -Name 'Retrieve credential and run user process' `
        -Arguments @(
            'run',
            '--user',
            $SandboxUser,
            '--test-credential-tag',
            $testCredentialTag,
            '--working-directory',
            $env:SystemRoot,
            '--',
            $commandPrompt,
            '/d',
            '/c',
            'exit 37'
        ) `
        -ExpectedExitCode 37

    Write-Host "`nAcceptance test passed:"
    Write-Host '  - Credential was written to Windows Credential Manager.'
    Write-Host '  - Credential was read back by the launcher.'
    Write-Host '  - Windows authenticated the sandbox user.'
    Write-Host '  - cmd.exe token SID matched that user.'
    Write-Host '  - cmd.exe returned the checked sentinel code.'
}
finally {
    Invoke-LauncherStep -Name 'Remove tagged test credential' -Arguments @(
        'forget',
        '--user',
        $SandboxUser,
        '--test-credential-tag',
        $testCredentialTag
    )
}
