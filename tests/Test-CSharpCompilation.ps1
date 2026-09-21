# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Path,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $TypeName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "The C# source file does not exist: $Path"
}

Add-Type -Path $Path -ErrorAction Stop
if ($null -eq ($TypeName -as [type])) {
    throw "The compiled C# source did not define the expected type: $TypeName"
}
