# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [string]$PipeName = 'launch-as-broker.v1',
    [string]$Account = 'LaunchAsUser',
    [string]$AccessProbePath = (
        Join-Path $PSScriptRoot '..\out\build\Release\LauncherBrokerProcessAccessProbe.exe'
    )
)

$ErrorActionPreference = 'Stop'

$caller = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent())
if ($caller.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this acceptance probe from the authorised non-elevated user session. Administrators are outside the broker threat boundary.'
}

$requestId = [guid]::NewGuid().ToString()
$dataPipePrefix = "\\.\pipe\launch-as-probe-$requestId"
$cmd = (Get-Command cmd.exe -CommandType Application).Source

if ($null -eq ('LaunchAs.BrokerProbePipes' -as [type])) {
    Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace LaunchAs
{
    public static class BrokerProbePipes
    {
        private const uint PipeAccessInbound = 0x00000001;
        private const uint PipeAccessOutbound = 0x00000002;
        private const uint FileFlagFirstPipeInstance = 0x00080000;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            public bool InheritHandle;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string value, uint revision, out IntPtr descriptor, IntPtr size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateNamedPipe(
            string name, uint openMode, uint pipeMode, uint maximumInstances,
            uint outputBufferSize, uint inputBufferSize, uint defaultTimeout,
            ref SecurityAttributes securityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static SafeFileHandle Create(string name, bool serverWrites, string sddl)
        {
            IntPtr descriptor;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                var attributes = new SecurityAttributes {
                    Length = Marshal.SizeOf<SecurityAttributes>(),
                    SecurityDescriptor = descriptor,
                    InheritHandle = false
                };
                uint access = serverWrites ? PipeAccessOutbound : PipeAccessInbound;
                IntPtr handle = CreateNamedPipe(name, access | FileFlagFirstPipeInstance, 0,
                    1, 4096, 4096, 0, ref attributes);
                if (handle == new IntPtr(-1))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return new SafeFileHandle(handle, true);
            }
            finally
            {
                LocalFree(descriptor);
            }
        }
    }
}
'@
}

$accountSid = ([System.Security.Principal.NTAccount]::new($env:COMPUTERNAME, $Account)).Translate(
    [System.Security.Principal.SecurityIdentifier]).Value
$pipeSddl = "D:P(A;;GA;;;SY)(A;;GRGW;;;$accountSid)"
$pipeServers = @()

$request = [ordered]@{
    version          = 1
    requestId        = $requestId
    operation        = 'launch'
    profileId        = $Account
    mode             = 'console'
    arguments        = @($cmd, '/d', '/c', 'timeout /t 30 >nul')
    workingDirectory = $PWD.Path
    console          = [ordered]@{
        pipeIn     = "$dataPipePrefix-in"
        pipeOut    = "$dataPipePrefix-out"
        pipeResize = "$dataPipePrefix-resize"
        cols       = 120
        rows       = 30
    }
} | ConvertTo-Json -Compress

$pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
    '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
$processId = 0
try {
    $pipeServers += [LaunchAs.BrokerProbePipes]::Create("$dataPipePrefix-in", $true, $pipeSddl)
    $pipeServers += [LaunchAs.BrokerProbePipes]::Create("$dataPipePrefix-out", $false, $pipeSddl)
    $pipeServers += [LaunchAs.BrokerProbePipes]::Create("$dataPipePrefix-resize", $true, $pipeSddl)
    $pipe.Connect(5000)
    $payload = [System.Text.Encoding]::UTF8.GetBytes($request)
    $pipe.Write($payload, 0, $payload.Length)
    $pipe.Flush()

    $buffer = [byte[]]::new(4096)
    $bytesRead = $pipe.Read($buffer, 0, $buffer.Length)
    if ($bytesRead -eq 0) {
        throw 'The broker closed the control pipe without a response.'
    }
    $responseText = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
    $response = $responseText | ConvertFrom-Json
    if ($response.requestId -ne $requestId -or $response.status -ne 'ok' -or
        $response.reasonCode -ne 'launched' -or $response.processId -le 0) {
        throw "Broker probe failed: $responseText"
    }
    $processId = $response.processId
    $accessProbe = Resolve-Path -LiteralPath $AccessProbePath
    & $accessProbe.Path $processId
    if ($LASTEXITCODE -ne 0) {
        throw "The broker child exposed caller process access; probe exit code: $LASTEXITCODE"
    }
}
finally {
    $pipe.Dispose()
    $pipeServers | ForEach-Object { $_.Dispose() }
}

$deadline = [DateTime]::UtcNow.AddSeconds(5)
while ([DateTime]::UtcNow -lt $deadline -and (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
    Start-Sleep -Milliseconds 100
}
if ($processId -gt 0 -and (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
    throw "Broker child PID $processId survived control-pipe disconnect."
}
Write-Output "Broker probe succeeded; PID $processId denied VM_READ and TERMINATE and ended on disconnect."
