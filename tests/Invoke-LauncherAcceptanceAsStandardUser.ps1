# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $TargetUser,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedCaller,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ResultPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$windowProcess = $null
$transcriptStarted = $false

try {
    Start-Transcript -Path $LogPath -Force | Out-Null
    $transcriptStarted = $true
    @(
        'RUNNING'
        'acceptance-phase=standard-caller-preflight'
    ) | Out-File -LiteralPath $ResultPath -Encoding utf8
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not [string]::Equals(
            $identity.Name,
            "$env:COMPUTERNAME\$ExpectedCaller",
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Acceptance ran as '$($identity.Name)'; expected '$env:COMPUTERNAME\$ExpectedCaller'."
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The acceptance caller token is an administrator token.'
    }

    if ($null -eq ('LaunchAs.AcceptanceCallerV1' -as [type])) {
        Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LaunchAs
{
    public static class AcceptanceCallerV1
    {
        private const int TokenElevation = 20;
        private const int StdInputHandle = -10;

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr token, int informationClass, out int information,
            int informationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int standardHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

        public static bool IsElevated(IntPtr token)
        {
            int elevation;
            int returnLength;
            if (!GetTokenInformation(token, TokenElevation, out elevation,
                    sizeof(int), out returnLength))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return elevation != 0;
        }

        public static bool HasConsoleInput()
        {
            IntPtr input = GetStdHandle(StdInputHandle);
            if (input == IntPtr.Zero || input == new IntPtr(-1))
            {
                return false;
            }
            uint mode;
            return GetConsoleMode(input, out mode);
        }
    }
}
'@
    }

    if ([LaunchAs.AcceptanceCallerV1]::IsElevated($identity.Token)) {
        throw 'The acceptance caller token reports TokenElevation=true.'
    }
    if (-not [LaunchAs.AcceptanceCallerV1]::HasConsoleInput()) {
        throw 'The acceptance caller does not have a real console input handle.'
    }

    $windowScript = Join-Path $PSScriptRoot 'Show-LauncherAcceptanceWindow.ps1'
    $windowProcess = Start-Process `
        -FilePath (Join-Path $PSHOME 'powershell.exe') `
        -ArgumentList @(
            '-NoProfile'
            '-Sta'
            '-ExecutionPolicy'
            'Bypass'
            '-File'
            ('"{0}"' -f $windowScript)
        ) `
        -PassThru
    $windowDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 100
        $windowProcess.Refresh()
    } while ($windowProcess.MainWindowHandle -eq 0 -and
        -not $windowProcess.HasExited -and
        [DateTime]::UtcNow -lt $windowDeadline)
    if ($windowProcess.HasExited -or $windowProcess.MainWindowHandle -eq 0) {
        throw 'The standard caller could not create its controlled acceptance window.'
    }

    $acceptancePath = Join-Path $PSScriptRoot 'Invoke-LauncherAcceptanceTest.ps1'
    $launcherPath = Join-Path $PSScriptRoot 'launch-as.exe'
    & $acceptancePath `
        -TargetUser $TargetUser `
        -LauncherPath $launcherPath `
        -CallerWindowProcessId $windowProcess.Id `
        -ProgressPath $ResultPath

    @(
        'PASS'
        "Interactive acceptance passed from .\$ExpectedCaller for .\$TargetUser in Windows Sandbox."
    ) | Out-File -LiteralPath $ResultPath -Encoding utf8
    Write-Host "`nAcceptance passed. This Sandbox will close automatically." -ForegroundColor Green
}
catch {
    @(
        'FAIL'
        $_.Exception.Message
        $_.ScriptStackTrace
    ) | Out-File -LiteralPath $ResultPath -Encoding utf8
    Write-Host "`nAcceptance failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    if ($null -ne $windowProcess -and -not $windowProcess.HasExited) {
        Stop-Process -Id $windowProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
}
