# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $DriverPath,

    [Parameter(Mandatory)]
    [string] $AcceptancePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Load only the wait function/call; never execute guest provisioning on the host.
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $DriverPath).Path, [ref] $tokens, [ref] $parseErrors)
if ($parseErrors.Count -ne 0) {
    throw 'The guest acceptance driver did not parse.'
}
foreach ($function in $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Wait-GuestProcess'
        }, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
$waitCommand = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Wait-GuestProcess' -and
        $node.Extent.Text.Contains("'Interactive Sandbox acceptance'")
    }, $false)
if ($null -eq $waitCommand) {
    throw 'Could not locate the interactive acceptance wait.'
}

$acceptanceAst = [Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $AcceptancePath).Path, [ref] $tokens, [ref] $parseErrors)
if ($parseErrors.Count -ne 0) {
    throw 'The acceptance suite did not parse.'
}
$phaseFunction = $acceptanceAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Write-AcceptancePhase'
    }, $false)
if ($null -eq $phaseFunction) {
    throw 'Could not locate acceptance phase reporting.'
}
. ([scriptblock]::Create($phaseFunction.Extent.Text))

$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixture = Join-Path $temporaryRoot ('launch-as-progress-' + [guid]::NewGuid().ToString('N'))
$resultLock = $null
$child = $null
$transcriptStarted = $false
try {
    $null = New-Item -ItemType Directory -Path $fixture
    $localResultPath = Join-Path $fixture 'result.txt'
    $sharedResultPath = Join-Path $fixture 'shared-result.txt'
    # Waiting must not touch a result file, even if it is exclusively locked.
    $resultLock = [IO.File]::Open(
        $localResultPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') `
        -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 2') `
        -WindowStyle Hidden -PassThru
    $acceptance = $child
    & ([scriptblock]::Create($waitCommand.Extent.Text))
    if (-not $child.HasExited -or (Test-Path -LiteralPath $sharedResultPath)) {
        throw 'Waiting must finish the process without publishing a result.'
    }
    $resultLock.Dispose()
    $resultLock = $null
    $child.Dispose()
    $child = $null

    # Phase reporting belongs in the transcript; it must preserve the result file.
    $ProgressPath = $localResultPath
    $expected = 'result-owned-by-caller'
    [IO.File]::WriteAllText($localResultPath, $expected)
    $logPath = Join-Path $fixture 'acceptance.log'
    Start-Transcript -Path $logPath | Out-Null
    $transcriptStarted = $true
    Write-AcceptancePhase 'first-phase'
    Write-AcceptancePhase 'second-phase'
    Stop-Transcript | Out-Null
    $transcriptStarted = $false
    if ([IO.File]::ReadAllText($localResultPath) -ne $expected) {
        throw 'Phase reporting modified the result file.'
    }
    $log = [IO.File]::ReadAllText($logPath)
    if ($log -notmatch 'acceptance-phase=first-phase' -or
        $log -notmatch 'acceptance-phase=second-phase') {
        throw 'The transcript did not retain both acceptance phases.'
    }

    # Timeout handling must finish termination before callers collect files.
    $child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') `
        -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') `
        -WindowStyle Hidden -PassThru
    $timedOut = $false
    try {
        Wait-GuestProcess -Process $child -TimeoutSeconds 1 -Description 'Timeout regression'
    }
    catch {
        if ($_.Exception.Message -notlike 'Timeout regression timed out*') {
            throw
        }
        $timedOut = $true
    }
    if (-not $timedOut -or -not $child.HasExited) {
        throw 'Timeout returned before the guest process exited.'
    }
    Write-Output 'Sandbox acceptance result ownership tests passed.'
}
finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
    if ($null -ne $resultLock) {
        $resultLock.Dispose()
    }
    if ($null -ne $child) {
        if (-not $child.HasExited) {
            Stop-Process -Id $child.Id -Force
            $child.WaitForExit()
        }
        $child.Dispose()
    }
    $resolvedFixture = [IO.Path]::GetFullPath($fixture)
    if (-not $resolvedFixture.StartsWith(
            $temporaryRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean a fixture outside the temporary directory: $resolvedFixture"
    }
    if (Test-Path -LiteralPath $resolvedFixture) {
        Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
    }
}
