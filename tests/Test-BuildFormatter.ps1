# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Exercise the build script's formatting step without configuring or rebuilding the repo.
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $Path).Path, [ref] $tokens, [ref] $parseErrors)
if ($parseErrors.Count -ne 0) {
    throw 'build.ps1 did not parse.'
}
$statements = @($ast.EndBlock.Statements)
$assignment = $statements | Where-Object {
    $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
    $_.Left.Extent.Text -eq '$clangFormat'
} | Select-Object -First 1
if ($null -eq $assignment) {
    throw 'Could not locate the formatter selection in build.ps1.'
}
$formatting = $statements[[array]::IndexOf($statements, $assignment) + 1]
$formatStep = [scriptblock]::Create($assignment.Extent.Text + "`n" + $formatting.Extent.Text)

$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixture = Join-Path $temporaryRoot ('launch-as-formatter-' + [guid]::NewGuid().ToString('N'))
$originalPath = $env:PATH
try {
    $first = Join-Path $fixture 'First tools'
    $second = Join-Path $fixture 'Second tools'
    $null = New-Item -ItemType Directory -Path $first, $second
    Set-Content -LiteralPath (Join-Path $first 'clang-format.cmd') -Encoding ascii -Value @(
        '@echo off', 'echo first formatter', 'echo %*', 'exit /b 0')
    Set-Content -LiteralPath (Join-Path $second 'clang-format.cmd') -Encoding ascii -Value @(
        '@echo off', 'echo second formatter', 'exit /b 1')
    $env:PATH = "$first;$second"
    if (@(Get-Command clang-format -CommandType Application).Count -ne 2) {
        throw 'The fixture must expose two formatter applications.'
    }
    $nativeSourceFiles = @('sample source.cpp')
    $output = @(& $formatStep)
    if ($output.Count -ne 2 -or $output[0] -ne 'first formatter' -or
        $output[1] -ne '-i -- "sample source.cpp"') {
        throw "The build did not invoke only the first formatter with the source arguments: $output"
    }

    $env:PATH = $fixture
    $output = @(& $formatStep 3>&1)
    if ($output.Count -ne 1 -or $output[0] -isnot [Management.Automation.WarningRecord]) {
        throw 'A missing formatter must warn and allow the build to continue.'
    }
}
finally {
    $env:PATH = $originalPath
    $resolvedFixture = [IO.Path]::GetFullPath($fixture)
    if (-not $resolvedFixture.StartsWith(
            $temporaryRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean a fixture outside the temporary directory: $resolvedFixture"
    }
    if (Test-Path -LiteralPath $resolvedFixture) {
        Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
    }
}
