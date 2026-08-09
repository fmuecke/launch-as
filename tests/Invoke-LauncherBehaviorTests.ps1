# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LauncherPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedVersion = '0.3.2'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Launcher {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Arguments,

        [Parameter(Mandatory)]
        [int[]] $ExpectedExitCodes,

        [Parameter(Mandatory)]
        [string] $ExpectedOutput
    )

    $output = @(& $script:ResolvedLauncher @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object ToString) -join [Environment]::NewLine
    if ($exitCode -notin $ExpectedExitCodes) {
        throw "$Name returned $exitCode; expected $($ExpectedExitCodes -join ' or '). Output:`n$text"
    }
    if (-not $text.Contains($ExpectedOutput)) {
        throw "$Name did not produce '$ExpectedOutput'. Output:`n$text"
    }
    Write-Host "[PASS] $Name (exit $exitCode)"
}

function Assert-Equal {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [object] $Actual,

        [Parameter(Mandatory)]
        [object] $Expected
    )

    if ($Actual -ne $Expected) {
        throw "$Name was '$Actual'; expected '$Expected'."
    }
    Write-Host "[PASS] $Name"
}

$script:ResolvedLauncher = [IO.Path]::GetFullPath($LauncherPath)
if (-not (Test-Path -LiteralPath $script:ResolvedLauncher -PathType Leaf)) {
    throw "Launcher not found: $script:ResolvedLauncher"
}

$usage = Invoke-Launcher `
    -Name 'No arguments reports broker usage' `
    -Arguments @() `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'launch-as-broker'

foreach ($legacyCommand in 'register', 'status', 'forget') {
    Invoke-Launcher `
        -Name "Legacy $legacyCommand command is rejected" `
        -Arguments @($legacyCommand, '--user', 'AgentSandbox') `
        -ExpectedExitCodes 87 `
        -ExpectedOutput 'Usage:'
}

Invoke-Launcher `
    -Name 'Credential mode is rejected' `
    -Arguments @('--user', 'AgentSandbox', '--credential-mode', 'stored', '--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Password stdin is rejected' `
    -Arguments @('--user', 'AgentSandbox', '--password-stdin', '--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Legacy terminal switch is rejected' `
    -Arguments @('--user', 'AgentSandbox', '--terminal', '--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Missing account is rejected' `
    -Arguments @('--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Account domain syntax is rejected' `
    -Arguments @('--user', '.\AgentSandbox', '--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Missing process separator is rejected' `
    -Arguments @('--user', 'AgentSandbox', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Relative executable is rejected before broker access' `
    -Arguments @('--user', 'AgentSandbox', '--', 'cmd.exe') `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Executable is not an existing absolute file'
Invoke-Launcher `
    -Name 'Explicit run command remains supported' `
    -Arguments @('run', '--user', 'AgentSandbox', '--', 'cmd.exe') `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Executable is not an existing absolute file'

$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($script:ResolvedLauncher)
Assert-Equal -Name 'File version metadata' -Actual $version.FileVersion -Expected $ExpectedVersion
Assert-Equal -Name 'Product version metadata' -Actual $version.ProductVersion -Expected $ExpectedVersion
Assert-Equal `
    -Name 'File description metadata' `
    -Actual $version.FileDescription `
    -Expected 'Launcher for repeatable least-privilege execution on Windows'
Assert-Equal -Name 'Product name metadata' -Actual $version.ProductName -Expected 'launch-as'
Assert-Equal -Name 'Original filename metadata' -Actual $version.OriginalFilename -Expected 'launch-as.exe'
Assert-Equal `
    -Name 'Copyright metadata' `
    -Actual $version.LegalCopyright `
    -Expected 'Copyright (c) 2026 Florian Mücke'

Write-Host "`nAll unattended launcher behavior tests passed."
