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
$probe = Join-Path (Split-Path -Parent $LauncherPath) 'LauncherBrokerWriteScopeProbe.exe'
foreach ($lowIntegrity in @($false, $true)) {
    $scopeRoot = Join-Path $ReportRoot ('write-scope-' + [guid]::NewGuid().ToString('N'))
    $work = Join-Path $scopeRoot 'work'
    $outside = Join-Path $scopeRoot 'outside'
    New-Item -ItemType Directory -Path (Join-Path $work 'existing'), $outside -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $work 'existing\old.txt') -Value 'existing'
    Set-Content -LiteralPath (Join-Path $outside 'outside.txt') -Value 'outside'
    try {
        # The target prepares its labels without borrowing SYSTEM rights.
        & icacls.exe $scopeRoot /grant "${Account}:(OI)(CI)F" /T /Q
        if ($LASTEXITCODE -ne 0) { throw 'Could not grant target access to the scope fixture.' }
        & icacls.exe $scopeRoot /setintegritylevel '(OI)(CI)M' /T /Q
        if ($LASTEXITCODE -ne 0) { throw 'Could not establish the Medium fixture baseline.' }
        New-Item -ItemType HardLink -Path (Join-Path $work 'hardlink.txt') `
            -Value (Join-Path $outside 'outside.txt') | Out-Null
        & cmd.exe /d /c mklink /J (Join-Path $work 'junction') $outside
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the junction regression fixture.' }
        $launchOptions = @()
        $integrity = 'medium'
        $restriction = 'unrestricted'
        if ($lowIntegrity) { $launchOptions += '--low-integrity'; $integrity = 'low' }
        Write-Host "Testing launch flags: integrity=$integrity restriction=$restriction"
        $output = & $LauncherPath --user $Account @launchOptions --working-directory $work -- `
            $probe $work $outside $integrity $restriction 2>&1
        $exitCode = $LASTEXITCODE
        $output | Write-Host
        if ($exitCode -ne 0 -or ($output | Out-String) -notmatch
                'Write-scope installed launch and descendant probes passed') {
            throw "Console launch failed: $integrity/$restriction (exit $exitCode)."
        }
        $interactiveMarker = Join-Path $work 'descendant-passed.txt'
        Remove-Item -LiteralPath $interactiveMarker -Force
        $output = & $LauncherPath --user $Account --mode interactive @launchOptions `
            --working-directory $work -- $probe $work $outside $integrity $restriction 'descendant' 2>&1
        $exitCode = $LASTEXITCODE
        $output | Write-Host
        if ($exitCode -ne 0) {
            throw "Interactive launch failed: $integrity/$restriction (exit $exitCode)."
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $interactiveMarker) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $interactiveMarker)) {
            throw "Interactive process did not finish its assertions: $integrity/$restriction."
        }
        if ($lowIntegrity -and
            (Get-Content -LiteralPath (Join-Path $outside 'outside.txt') -Raw).Trim() -ne 'outside') {
            throw 'Low-integrity process modified the Medium outside file.'
        }
    }
    finally {
        # This fixture owns a single GUID directory under the runner's report root.
        if (Test-Path -LiteralPath (Join-Path $work 'junction')) {
            & cmd.exe /d /c rmdir (Join-Path $work 'junction')
        }
        Remove-Item -LiteralPath $scopeRoot -Recurse -Force
    }
}
Write-Host 'Write-scope acceptance passed'
