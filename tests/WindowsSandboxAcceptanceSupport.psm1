# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

Set-StrictMode -Version Latest

function Get-SingleWindowsSandboxId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject] $ListResult
    )

    $environmentsProperty = $ListResult.PSObject.Properties['WindowsSandboxEnvironments']
    if ($null -eq $environmentsProperty) {
        throw 'The Windows Sandbox list result does not contain WindowsSandboxEnvironments.'
    }

    $environments = @($environmentsProperty.Value)
    if ($environments.Count -ne 1) {
        throw "Expected exactly one running Windows Sandbox; found $($environments.Count)."
    }

    $idProperty = $environments[0].PSObject.Properties['Id']
    $sandboxId = if ($null -eq $idProperty) { '' } else { [string] $idProperty.Value }
    if ([string]::IsNullOrWhiteSpace($sandboxId)) {
        throw 'The running Windows Sandbox did not report an id.'
    }
    return $sandboxId
}

Export-ModuleMember -Function Get-SingleWindowsSandboxId
