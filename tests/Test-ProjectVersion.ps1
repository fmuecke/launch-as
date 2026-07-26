# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: MIT
# Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $RepoRoot,

    [Parameter()]
    [string] $ExpectedVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) {
    $cmakePath = Join-Path $RepoRoot 'CMakeLists.txt'
    $cmakeContent = Get-Content -LiteralPath $cmakePath -Raw
    $cmakeVersionMatch = [regex]::Match(
        $cmakeContent,
        '(?ms)\bproject\s*\(.*?\bVERSION\s+([0-9]+(?:\.[0-9]+){1,3})'
    )
    if (-not $cmakeVersionMatch.Success) {
        throw "Could not read the project version from '$cmakePath'."
    }
    $ExpectedVersion = $cmakeVersionMatch.Groups[1].Value
}

$versionFiles = @(
    'Setup-ClaudeSandbox.ps1'
    'Check-ClaudeSandbox.ps1'
    'bootstrap\Enter-ClaudeDevShell.ps1'
)
$versionPattern = '(?m)^\s*\$Version\s*=\s*''([^'']+)''\s*$'

foreach ($relativePath in $versionFiles) {
    $path = Join-Path $RepoRoot $relativePath
    $content = Get-Content -LiteralPath $path -Raw
    $matches = [regex]::Matches($content, $versionPattern)
    if ($matches.Count -ne 1) {
        throw (
            "Expected exactly one project version declaration in " +
            "'$relativePath'; found $($matches.Count)."
        )
    }

    $actualVersion = $matches[0].Groups[1].Value
    if ($actualVersion -ne $ExpectedVersion) {
        throw (
            "Project version mismatch in '$relativePath': " +
            "'$actualVersion' != '$ExpectedVersion'."
        )
    }
    Write-Host "[PASS] $relativePath version $actualVersion"
}
