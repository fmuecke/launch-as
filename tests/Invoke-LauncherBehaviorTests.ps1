# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LauncherPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $BrokerPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $AdminPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ConhostPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedVersion = '1.1.0'
    #[string] $ExpectedVersion = '1.0.0-preview'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$copyrightHolder = 'Florian M' + [char]0x00FC + 'cke'

function Invoke-NativeAndCapture {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Arguments,

        [Parameter(Mandatory)]
        [ref] $Output,

        [Parameter(Mandatory)]
        [ref] $ExitCode
    )

    $previousOutputEncoding = [Console]::OutputEncoding
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $ErrorActionPreference = 'Continue'
        $Output.Value = @(& $Path @Arguments 2>&1)
        $ExitCode.Value = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
        [Console]::OutputEncoding = $previousOutputEncoding
    }
}

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

    $output = $null
    $exitCode = 0
    Invoke-NativeAndCapture `
        -Path $script:ResolvedLauncher `
        -Arguments $Arguments `
        -Output ([ref] $output) `
        -ExitCode ([ref] $exitCode)
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

function Assert-VersionMetadata {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Description,

        [Parameter(Mandatory)]
        [string] $OriginalFilename
    )

    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    Assert-Equal -Name "$OriginalFilename file version metadata" -Actual $version.FileVersion -Expected $ExpectedVersion
    Assert-Equal -Name "$OriginalFilename product version metadata" -Actual $version.ProductVersion -Expected $ExpectedVersion
    Assert-Equal -Name "$OriginalFilename file description metadata" -Actual $version.FileDescription -Expected $Description
    Assert-Equal -Name "$OriginalFilename product name metadata" -Actual $version.ProductName -Expected 'launch-as'
    Assert-Equal -Name "$OriginalFilename original filename metadata" -Actual $version.OriginalFilename -Expected $OriginalFilename
    Assert-Equal -Name "$OriginalFilename copyright metadata" -Actual $version.LegalCopyright -Expected "Copyright (c) 2026 $copyrightHolder"
}

function Assert-LicenseHeader {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $output = $null
    $exitCode = 0
    Invoke-NativeAndCapture `
        -Path $Path `
        -Arguments @('--license') `
        -Output ([ref] $output) `
        -ExitCode ([ref] $exitCode)
    $text = ($output | ForEach-Object ToString) -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        throw "$Name --license returned $exitCode. Output:`n$text"
    }
    foreach ($line in @(
            "launch-as v$ExpectedVersion - Least-privilege Launcher",
            "Copyright (C) 2026 $copyrightHolder - This program comes with ABSOLUTELY NO WARRANTY.")) {
        if (-not $text.Contains($line)) {
            throw "$Name --license did not produce '$line'. Output:`n$text"
        }
    }
    Write-Host "[PASS] $Name --license"
}

$script:ResolvedLauncher = [IO.Path]::GetFullPath($LauncherPath)
if (-not (Test-Path -LiteralPath $script:ResolvedLauncher -PathType Leaf)) {
    throw "Launcher not found: $script:ResolvedLauncher"
}

foreach ($executable in @(
        @{ Path = $script:ResolvedLauncher; Name = 'launch-as' },
        @{ Path = [IO.Path]::GetFullPath($BrokerPath); Name = 'launch-as-broker' },
        @{ Path = [IO.Path]::GetFullPath($AdminPath); Name = 'launch-as-admin' },
        @{ Path = [IO.Path]::GetFullPath($ConhostPath); Name = 'launch-as-conhost' })) {
    if (-not (Test-Path -LiteralPath $executable.Path -PathType Leaf)) {
        throw "$($executable.Name) not found: $($executable.Path)"
    }
    Assert-LicenseHeader -Path $executable.Path -Name $executable.Name
}

$usage = Invoke-Launcher `
    -Name 'No arguments reports broker usage' `
    -Arguments @() `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'launch-as-broker'

foreach ($legacyCommand in 'register', 'status', 'forget') {
    Invoke-Launcher `
        -Name "Legacy $legacyCommand command is rejected" `
        -Arguments @($legacyCommand, '--user', 'LaunchAsUser') `
        -ExpectedExitCodes 87 `
        -ExpectedOutput 'Usage:'
}

Invoke-Launcher `
    -Name 'Credential mode is rejected' `
    -Arguments @('--user', 'LaunchAsUser', '--credential-mode', 'stored', '--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Password stdin is rejected' `
    -Arguments @('--user', 'LaunchAsUser', '--password-stdin', '--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Legacy terminal switch is rejected' `
    -Arguments @('--user', 'LaunchAsUser', '--terminal', '--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Internal pseudoconsole host switch is rejected' `
    -Arguments @('--internal-pseudoconsole-host', '--size', '120', '30') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Missing account is rejected' `
    -Arguments @('--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Account domain syntax is rejected' `
    -Arguments @('--user', '.\LaunchAsUser', '--', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Missing process separator is rejected' `
    -Arguments @('--user', 'LaunchAsUser', 'C:\Windows\System32\cmd.exe') `
    -ExpectedExitCodes 87 `
    -ExpectedOutput 'Usage:'
Invoke-Launcher `
    -Name 'Relative executable is rejected before broker access' `
    -Arguments @('--user', 'LaunchAsUser', '--', 'cmd.exe') `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Executable is not an existing absolute file'
Invoke-Launcher `
    -Name 'Explicit run command remains supported' `
    -Arguments @('run', '--user', 'LaunchAsUser', '--', 'cmd.exe') `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Executable is not an existing absolute file'

Assert-VersionMetadata `
    -Path $script:ResolvedLauncher `
    -Description 'Least-privilege launcher' `
    -OriginalFilename 'launch-as.exe'
Assert-VersionMetadata `
    -Path ([IO.Path]::GetFullPath($BrokerPath)) `
    -Description 'launch-as broker service' `
    -OriginalFilename 'launch-as-broker.exe'
Assert-VersionMetadata `
    -Path ([IO.Path]::GetFullPath($AdminPath)) `
    -Description 'launch-as broker administration' `
    -OriginalFilename 'launch-as-admin.exe'
Assert-VersionMetadata `
    -Path ([IO.Path]::GetFullPath($ConhostPath)) `
    -Description 'launch-as console host' `
    -OriginalFilename 'launch-as-conhost.exe'

Write-Host "`nAll unattended launcher behavior tests passed."
