# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LauncherPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedVersion = '0.5.0',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $SandboxUser = 'ClaudeSandbox',

    [Parameter(Mandatory)]
    [ValidateSet('Visible', 'Hidden')]
    [string] $ExpectedTestCredentialTagVisibility
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Launcher {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $Arguments,

        [Parameter(Mandatory)]
        [int[]] $ExpectedExitCodes,

        [Parameter(Mandatory)]
        [string] $ExpectedOutput,

        [Parameter()]
        [AllowEmptyString()]
        [string] $StandardInput
    )

    if ($PSBoundParameters.ContainsKey('StandardInput')) {
        $previousOutputEncoding = $OutputEncoding
        try {
            $OutputEncoding = [Text.UTF8Encoding]::new($false)
            $nativeOutput = @(
                $StandardInput |
                    & $script:ResolvedLauncher @Arguments 2>&1
            )
        }
        finally {
            $OutputEncoding = $previousOutputEncoding
        }
    }
    else {
        $nativeOutput = @(& $script:ResolvedLauncher @Arguments 2>&1)
    }
    $exitCode = $LASTEXITCODE
    $outputText = ($nativeOutput |
        ForEach-Object { $_.ToString() }) -join [Environment]::NewLine

    if ($exitCode -notin $ExpectedExitCodes) {
        throw (
            "$Name returned $exitCode; expected " +
            "$($ExpectedExitCodes -join ' or '). Output:`n$outputText"
        )
    }
    if ($outputText -notmatch $ExpectedOutput) {
        throw (
            "$Name did not produce output matching '$ExpectedOutput'. " +
            "Output:`n$outputText"
        )
    }

    Write-Host "[PASS] $Name (exit $exitCode)"
    return [pscustomobject] @{
        ExitCode = $exitCode
        Output   = $outputText
    }
}

function Assert-Equal {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [AllowNull()]
        [object] $Actual,

        [AllowNull()]
        [object] $Expected
    )

    if ($Actual -ne $Expected) {
        throw "$Name was '$Actual'; expected '$Expected'."
    }
    Write-Host "[PASS] $Name"
}

$script:ResolvedLauncher = [System.IO.Path]::GetFullPath($LauncherPath)
if (-not (Test-Path -LiteralPath $script:ResolvedLauncher -PathType Leaf)) {
    throw "Launcher not found: $script:ResolvedLauncher"
}

$localUser = Get-LocalUser `
    -Name $SandboxUser `
    -ErrorAction SilentlyContinue
$hasInstalledAccountFixture =
$null -ne $localUser -and $localUser.Enabled
if (-not $hasInstalledAccountFixture) {
    Write-Host (
        "[SKIP] Installed-account checks: local user '$SandboxUser' " +
        'is missing or disabled.'
    )
}

$usageResult = Invoke-Launcher `
    -Name 'No arguments reports usage' `
    -Arguments @() `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$testCredentialTagIsVisible =
    $usageResult.Output.Contains('--test-credential-tag')
$expectedTestCredentialTagIsVisible =
    $ExpectedTestCredentialTagVisibility -eq 'Visible'
Assert-Equal `
    -Name "Test credential option is $($ExpectedTestCredentialTagVisibility.ToLower())" `
    -Actual $testCredentialTagIsVisible `
    -Expected $expectedTestCredentialTagIsVisible

$null = Invoke-Launcher `
    -Name 'Unknown command reports usage' `
    -Arguments @('not-a-command') `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Caller cannot supply account domain syntax' `
    -Arguments @('status', '--user', ".\$SandboxUser") `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Plaintext command-line passwords are rejected' `
    -Arguments @(
    'register',
    '--user',
    $SandboxUser,
    '--password',
    'not-a-real-password'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Password stdin is accepted only by register' `
    -Arguments @(
    'status',
    '--user',
    $SandboxUser,
    '--password-stdin'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Duplicate password stdin options are rejected' `
    -Arguments @(
    'register',
    '--user',
    $SandboxUser,
    '--password-stdin',
    '--password-stdin'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Credential mode is accepted only by run' `
    -Arguments @(
    'status',
    '--user',
    $SandboxUser,
    '--credential-mode',
    'stored'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Unknown credential mode is rejected' `
    -Arguments @(
    'run',
    '--user',
    $SandboxUser,
    '--credential-mode',
    'unknown',
    '--',
    'C:\missing.exe'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Duplicate credential modes are rejected' `
    -Arguments @(
    'run',
    '--user',
    $SandboxUser,
    '--credential-mode',
    'auto',
    '--credential-mode',
    'stored',
    '--',
    'C:\missing.exe'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Invalid test credential tag is rejected' `
    -Arguments @(
    'status',
    '--user',
    $SandboxUser,
    '--test-credential-tag',
    'invalid:tag'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Empty test credential tag cannot select production credential' `
    -Arguments @(
    'status',
    '--user',
    $SandboxUser,
    '--test-credential-tag',
    ''
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Duplicate test credential tags are rejected' `
    -Arguments @(
    'status',
    '--user',
    $SandboxUser,
    '--test-credential-tag',
    'first',
    '--test-credential-tag',
    'second'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Run requires the process separator' `
    -Arguments @(
    'run',
    '--user',
    $SandboxUser,
    'C:\missing.exe'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$null = Invoke-Launcher `
    -Name 'Credential command rejects process arguments' `
    -Arguments @(
    'status',
    '--user',
    $SandboxUser,
    '--',
    'C:\missing.exe'
) `
    -ExpectedExitCodes 2 `
    -ExpectedOutput 'Usage:'

$missingUser = '__L' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$null = Invoke-Launcher `
    -Name 'Register accepts password stdin mode' `
    -Arguments @(
    'register',
    '--user',
    $missingUser,
    '--password-stdin'
) `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Could not resolve local account'

$null = Invoke-Launcher `
    -Name 'Unknown local account is rejected' `
    -Arguments @('status', '--user', $missingUser) `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Could not resolve local account'

if ($hasInstalledAccountFixture) {
    $stdinCredentialTag =
    'stdin-' + [Guid]::NewGuid().ToString('N')
    $null = Invoke-Launcher `
        -Name 'Password stdin rejects an empty line without writing a credential' `
        -Arguments @(
        'register',
        '--user',
        $SandboxUser,
        '--password-stdin',
        '--test-credential-tag',
        $stdinCredentialTag
    ) `
        -ExpectedExitCodes 1 `
        -ExpectedOutput 'exactly one non-empty UTF-8 line' `
        -StandardInput ''

    $null = Invoke-Launcher `
        -Name 'Rejected password stdin leaves no tagged credential' `
        -Arguments @(
        'status',
        '--user',
        $SandboxUser,
        '--test-credential-tag',
        $stdinCredentialTag
    ) `
        -ExpectedExitCodes 3 `
        -ExpectedOutput 'No launcher credential'

    $status = Invoke-Launcher `
        -Name 'Existing local account resolves and credential status is read' `
        -Arguments @('status', '--user', $SandboxUser) `
        -ExpectedExitCodes @(0, 3) `
        -ExpectedOutput 'launcher credential'

    $behaviorCredentialTag =
    'behavior-' + [Guid]::NewGuid().ToString('N')
    $null = Invoke-Launcher `
        -Name 'Tagged test credential is isolated from production credential' `
        -Arguments @(
        'status',
        '--user',
        $SandboxUser,
        '--test-credential-tag',
        $behaviorCredentialTag
    ) `
        -ExpectedExitCodes 3 `
        -ExpectedOutput 'No launcher credential'

    $null = Invoke-Launcher `
        -Name 'Tagged credential cleanup is idempotent' `
        -Arguments @(
        'forget',
        '--user',
        $SandboxUser,
        '--test-credential-tag',
        $behaviorCredentialTag
    ) `
        -ExpectedExitCodes 0 `
        -ExpectedOutput 'No launcher credential'

    $statusAfterTaggedCleanup = Invoke-Launcher `
        -Name 'Tagged cleanup leaves production credential unchanged' `
        -Arguments @('status', '--user', $SandboxUser) `
        -ExpectedExitCodes @(0, 3) `
        -ExpectedOutput 'launcher credential'
    Assert-Equal `
        -Name 'Production credential status after tagged cleanup' `
        -Actual $statusAfterTaggedCleanup.ExitCode `
        -Expected $status.ExitCode
}

$missingRoot = Join-Path `
([System.IO.Path]::GetPathRoot($script:ResolvedLauncher)) `
('claude-win-sandbox-test-missing-' + [Guid]::NewGuid().ToString('N'))
$missingExecutable = Join-Path $missingRoot 'missing.exe'
$null = Invoke-Launcher `
    -Name 'Relative executable is rejected before credential access' `
    -Arguments @(
    'run',
    '--user',
    $SandboxUser,
    '--',
    'cmd.exe'
) `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Executable is not an existing absolute file'

$null = Invoke-Launcher `
    -Name 'Missing executable is rejected before credential access' `
    -Arguments @(
    'run',
    '--user',
    $SandboxUser,
    '--working-directory',
    [System.IO.Path]::GetPathRoot($script:ResolvedLauncher),
    '--',
    $missingExecutable
) `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Executable is not an existing absolute file'

$commandPrompt = Join-Path $env:SystemRoot 'System32\cmd.exe'
$null = Invoke-Launcher `
    -Name 'Missing working directory is rejected before credential access' `
    -Arguments @(
    'run',
    '--user',
    $SandboxUser,
    '--working-directory',
    $missingRoot,
    '--',
    $commandPrompt,
    '/d',
    '/c',
    'exit 37'
) `
    -ExpectedExitCodes 1 `
    -ExpectedOutput 'Working directory is not an existing absolute directory'

if ($hasInstalledAccountFixture) {
    if ($status.ExitCode -eq 0) {
        $null = Invoke-Launcher `
            -Name 'Run propagates the checked child process exit code' `
            -Arguments @(
            'run',
            '--user',
            $SandboxUser,
            '--credential-mode',
            'stored',
            '--working-directory',
            $env:SystemRoot,
            '--',
            $commandPrompt,
            '/d',
            '/c',
            'exit 37'
        ) `
            -ExpectedExitCodes 37 `
            -ExpectedOutput 'exited with code 37'
    }
    else {
        $null = Invoke-Launcher `
            -Name 'Run reports a missing credential distinctly' `
            -Arguments @(
            'run',
            '--user',
            $SandboxUser,
            '--credential-mode',
            'stored',
            '--working-directory',
            $env:SystemRoot,
            '--',
            $commandPrompt,
            '/d',
            '/c',
            'exit 37'
        ) `
            -ExpectedExitCodes 3 `
            -ExpectedOutput 'No stored launcher credential'
    }
}

$version = [Diagnostics.FileVersionInfo]::GetVersionInfo(
    $script:ResolvedLauncher
)
Assert-Equal `
    -Name 'File version metadata' `
    -Actual $version.FileVersion `
    -Expected $ExpectedVersion
Assert-Equal `
    -Name 'Product version metadata' `
    -Actual $version.ProductVersion `
    -Expected $ExpectedVersion
Assert-Equal `
    -Name 'File description metadata' `
    -Actual $version.FileDescription `
    -Expected 'Claude Sandbox Launcher'
Assert-Equal `
    -Name 'Original filename metadata' `
    -Actual $version.OriginalFilename `
    -Expected 'ClaudeSandboxLauncher.exe'
Assert-Equal `
    -Name 'Copyright metadata' `
    -Actual $version.LegalCopyright `
    -Expected 'Copyright (c) 2026 Florian Mücke'

Write-Host "`nAll unattended launcher behavior tests passed."
