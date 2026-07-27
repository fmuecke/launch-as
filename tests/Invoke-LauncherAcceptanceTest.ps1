# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $TargetUser,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $LauncherPath = (
        Join-Path $PSScriptRoot `
            '..\out\build\Release\launch-as.exe'
    ),

    [Parameter()]
    [securestring] $Password
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
        [int] $ExpectedExitCode = 0,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ExpectedOutput,

        [Parameter()]
        [AllowEmptyString()]
        [string] $StandardInput
    )

    Write-Host "`n[$Name]"
    $captureOutput = $PSBoundParameters.ContainsKey('ExpectedOutput')
    if ($PSBoundParameters.ContainsKey('StandardInput')) {
        $previousOutputEncoding = $OutputEncoding
        try {
            $OutputEncoding = [Text.UTF8Encoding]::new($false)
            if ($captureOutput) {
                $capturedOutput = @(
                    $StandardInput | & $script:ResolvedLauncher @Arguments
                )
            }
            else {
                $StandardInput | & $script:ResolvedLauncher @Arguments
            }
        }
        finally {
            $OutputEncoding = $previousOutputEncoding
        }
    }
    elseif ($captureOutput) {
        $capturedOutput = @(& $script:ResolvedLauncher @Arguments)
    }
    else {
        & $script:ResolvedLauncher @Arguments
    }
    $exitCode = $LASTEXITCODE
    if ($captureOutput) {
        $capturedOutput | ForEach-Object { Write-Host $_ }
        $outputText = $capturedOutput -join "`n"
        if (-not $outputText.Contains($ExpectedOutput)) {
            throw "$Name output did not contain '$ExpectedOutput'."
        }
    }
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

$localUser = Get-LocalUser -Name $TargetUser -ErrorAction Stop
if (-not $localUser.Enabled) {
    throw "Local user '$TargetUser' is disabled."
}

$administrators = Get-LocalGroup -SID 'S-1-5-32-544'
$isAdministrator = Get-LocalGroupMember -Group $administrators |
    Where-Object { $_.SID -eq $localUser.SID }
if ($null -ne $isAdministrator) {
    throw "Local user '$TargetUser' is an administrator; use a standard user."
}

$testCredentialTag =
    'acceptance-' + [Guid]::NewGuid().ToString('N')
try {
    Write-Host "Acceptance user: .\$TargetUser"
    Write-Host 'The credential is stored for the Windows user running this test.'
    Write-Host "Temporary credential tag: $testCredentialTag"

    $registrationArguments = @(
        'register',
        '--user',
        $TargetUser,
        '--test-credential-tag',
        $testCredentialTag
    )
    if ($null -eq $Password) {
        Write-Host 'Enter the target account password in Windows Credential UI.'
        Invoke-LauncherStep `
            -Name 'Register and store credential' `
            -Arguments $registrationArguments
    }
    else {
        Write-Host 'Registering with the supplied password through standard input.'
        $plainTextPassword = [pscredential]::new(
            'target',
            $Password
        ).GetNetworkCredential().Password
        try {
            $registrationArguments += '--password-stdin'
            Invoke-LauncherStep `
                -Name 'Register and store credential' `
                -Arguments $registrationArguments `
                -StandardInput $plainTextPassword
        }
        finally {
            $registrationArguments = $null
            $plainTextPassword = $null
        }
    }

    Invoke-LauncherStep -Name 'Read credential-store status' -Arguments @(
        'status',
        '--user',
        $TargetUser,
        '--test-credential-tag',
        $testCredentialTag
    )

    $commandPrompt = Join-Path $env:SystemRoot 'System32\cmd.exe'
    Invoke-LauncherStep -Name 'Retrieve credential and run user process' `
        -Arguments @(
            '--user',
            $TargetUser,
            '--credential-mode',
            'stored',
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

    Invoke-LauncherStep -Name 'Run target user through ConPTY' `
        -Arguments @(
            '--user',
            $TargetUser,
            '--credential-mode',
            'stored',
            '--test-credential-tag',
            $testCredentialTag,
            '--working-directory',
            $env:SystemRoot,
            '--terminal',
            '--',
            $commandPrompt,
            '/d',
            '/c',
            'echo conpty-user=%USERNAME% & exit 41'
        ) `
        -ExpectedExitCode 41 `
        -ExpectedOutput "conpty-user=$TargetUser"

    Write-Host "`nAcceptance test passed:"
    Write-Host '  - Credential was written to Windows Credential Manager.'
    Write-Host '  - Credential was read back by the launcher.'
    Write-Host '  - Windows authenticated the target user.'
    Write-Host '  - Direct cmd.exe and the ConPTY helper used the checked target token.'
    Write-Host '  - cmd.exe returned the checked sentinel code.'
    Write-Host '  - ConPTY returned target-user output through the current terminal.'
}
finally {
    Invoke-LauncherStep -Name 'Remove tagged test credential' -Arguments @(
        'forget',
        '--user',
        $TargetUser,
        '--test-credential-tag',
        $testCredentialTag
    )
}
