# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptText = Get-Content -LiteralPath $Path -Raw
if ($scriptText -notmatch '\[switch\]\s*\$PackageRelease') {
    throw 'build.ps1 must expose the -PackageRelease switch.'
}
if ($scriptText -notmatch 'Join-Path \$outputDirectory ''release-build''') {
    throw 'Release packaging must use a separate clean build directory.'
}
if ($scriptText -notmatch 'Remove-ManagedOutputDirectory \$buildDirectory') {
    throw 'Release packaging must remove its previous build directory.'
}
foreach ($fileName in @(
        'launch-as.exe',
        'launch-as-admin.exe',
        'launch-as-broker.exe',
        'launch-as-conhost.exe',
        'Setup-LaunchAs.ps1',
        'README.md',
        'CHANGELOG.md',
        'LICENSE')) {
    if ($scriptText -notmatch [regex]::Escape($fileName)) {
        throw "Release packaging does not include $fileName."
    }
}
if ($scriptText -notmatch 'Compress-Archive.*-CompressionLevel Optimal') {
    throw 'Release packaging must create an optimally compressed ZIP archive.'
}
