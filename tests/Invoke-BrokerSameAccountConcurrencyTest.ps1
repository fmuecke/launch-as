# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [string] $PipeName = 'launch-as-broker.v1',
    [string] $Account = 'LaunchAsUser'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$caller = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent())
if ($caller.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this acceptance test from the authorised non-elevated user session.'
}

if ($null -eq ('LaunchAs.BrokerSameAccountPipes' -as [type])) {
    Add-Type @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace LaunchAs
{
    public static class BrokerSameAccountPipes
    {
        private const uint PipeAccessInbound = 0x00000001;
        private const uint PipeAccessOutbound = 0x00000002;
        private const uint FileFlagFirstPipeInstance = 0x00080000;
        private const uint ScManagerConnect = 0x00000001;
        private const uint ServiceStart = 0x00000010;
        private const int ErrorServiceAlreadyRunning = 1056;
        private const int ErrorBrokenPipe = 109;
        private const int ErrorNoData = 232;
        private const int ErrorPipeListening = 536;

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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool PeekNamedPipe(SafeFileHandle pipe, byte[] buffer,
            uint bufferSize, out uint bytesRead, out uint available, out uint bytesLeft);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(SafeFileHandle pipe, byte[] buffer,
            uint bytesToRead, out uint bytesRead, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(SafeFileHandle pipe, byte[] buffer,
            uint bytesToWrite, out uint bytesWritten, IntPtr overlapped);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(
            string machineName, string databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(
            IntPtr manager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool StartService(
            IntPtr service, uint argumentCount, IntPtr arguments);

        [DllImport("advapi32.dll")]
        private static extern bool CloseServiceHandle(IntPtr handle);

        public static void EnsureBrokerStarted()
        {
            IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
            if (manager == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                IntPtr service = OpenService(manager, "launch-as-broker", ServiceStart);
                if (service == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                try
                {
                    if (!StartService(service, 0, IntPtr.Zero))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error != ErrorServiceAlreadyRunning)
                        {
                            throw new Win32Exception(error);
                        }
                    }
                }
                finally
                {
                    CloseServiceHandle(service);
                }
            }
            finally
            {
                CloseServiceHandle(manager);
            }
        }

        public static SafeFileHandle Create(string name, bool serverWrites, string sddl)
        {
            IntPtr descriptor;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                sddl, 1, out descriptor, IntPtr.Zero))
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

        public static void WriteTerminalSize(SafeFileHandle pipe, short columns, short rows)
        {
            var size = new byte[4];
            Array.Copy(BitConverter.GetBytes(columns), 0, size, 0, 2);
            Array.Copy(BitConverter.GetBytes(rows), 0, size, 2, 2);
            WriteAll(pipe, size);
        }

        public static string ReadUntil(
            SafeFileHandle pipe, string marker, int timeoutMilliseconds)
        {
            var output = new List<byte>();
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
            while (DateTime.UtcNow < deadline)
            {
                uint ignored;
                uint available;
                uint bytesLeft;
                if (!PeekNamedPipe(pipe, null, 0, out ignored, out available, out bytesLeft))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ErrorBrokenPipe || error == ErrorNoData)
                    {
                        break;
                    }
                    if (error != ErrorPipeListening)
                    {
                        throw new Win32Exception(error);
                    }
                }
                if (available == 0)
                {
                    Thread.Sleep(25);
                    continue;
                }
                var buffer = new byte[(int)Math.Min(available, 4096U)];
                uint bytesRead;
                if (!ReadFile(pipe, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                for (int index = 0; index < (int)bytesRead; ++index)
                {
                    output.Add(buffer[index]);
                }
                string text = Encoding.UTF8.GetString(output.ToArray());
                if (text.Contains(marker))
                {
                    return text;
                }
            }
            throw new TimeoutException("Timed out waiting for broker command output: " + marker);
        }

        private static void WriteAll(SafeFileHandle pipe, byte[] value)
        {
            int offset = 0;
            DateTime deadline = DateTime.UtcNow.AddSeconds(10);
            while (offset < value.Length)
            {
                var remaining = new byte[value.Length - offset];
                Array.Copy(value, offset, remaining, 0, remaining.Length);
                uint bytesWritten;
                if (!WriteFile(pipe, remaining, (uint)remaining.Length,
                        out bytesWritten, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ErrorPipeListening && DateTime.UtcNow < deadline)
                    {
                        Thread.Sleep(25);
                        continue;
                    }
                    throw new Win32Exception(error);
                }
                if (bytesWritten == 0)
                {
                    throw new InvalidOperationException("The broker terminal pipe wrote no data.");
                }
                offset += (int)bytesWritten;
            }
        }
    }
}
'@
}

$accountSid = ([System.Security.Principal.NTAccount]::new(
        $env:COMPUTERNAME, $Account)).Translate(
    [System.Security.Principal.SecurityIdentifier]).Value
$pipeSddl = "D:P(A;;GA;;;SY)(A;;GRGW;;;$accountSid)"
$windowsPowerShell = (Get-Command powershell.exe -CommandType Application).Source
[LaunchAs.BrokerSameAccountPipes]::EnsureBrokerStarted()

function New-BrokerSession {
    param(
        [switch] $AllowSessionLimit,
        [ValidateRange(1, 300)]
        [int] $SleepSeconds = 120
    )

    $requestId = [guid]::NewGuid().ToString()
    $readyMarker = "LAUNCH_AS_READY_$requestId"
    $identityProbe = "& (Join-Path `$env:SystemRoot 'System32\whoami.exe') /logonid; " +
        "Write-Output '$readyMarker'; Start-Sleep -Seconds $SleepSeconds; exit 37"
    $dataPipePrefix = "\\.\pipe\launch-as-concurrency-$requestId"
    $dataPipes = @()
    $controlPipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None)
    try {
        $dataPipes += [LaunchAs.BrokerSameAccountPipes]::Create(
            "$dataPipePrefix-in", $true, $pipeSddl)
        $dataPipes += [LaunchAs.BrokerSameAccountPipes]::Create(
            "$dataPipePrefix-out", $false, $pipeSddl)
        $dataPipes += [LaunchAs.BrokerSameAccountPipes]::Create(
            "$dataPipePrefix-resize", $true, $pipeSddl)

        $request = [ordered]@{
            version          = 1
            requestId        = $requestId
            operation        = 'launch'
            profileId        = $Account
            mode             = 'console'
            arguments        = @($windowsPowerShell, '-NoLogo', '-NoProfile', '-NonInteractive',
                '-Command', $identityProbe)
            workingDirectory = $PWD.Path
            console          = [ordered]@{
                pipeIn     = "$dataPipePrefix-in"
                pipeOut    = "$dataPipePrefix-out"
                pipeResize = "$dataPipePrefix-resize"
                cols       = 120
                rows       = 30
            }
        } | ConvertTo-Json -Compress

        $controlPipe.Connect(5000)
        $payload = [System.Text.Encoding]::UTF8.GetBytes($request)
        $controlPipe.Write($payload, 0, $payload.Length)
        $controlPipe.Flush()

        $buffer = [byte[]]::new(4096)
        $bytesRead = $controlPipe.Read($buffer, 0, $buffer.Length)
        if ($bytesRead -eq 0) {
            throw 'The broker closed the control pipe without a response.'
        }
        $responseText = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
        $response = $responseText | ConvertFrom-Json
        if ($response.reasonCode -eq 'session_limit_reached' -and $AllowSessionLimit) {
            if ($response.requestId -ne $requestId -or $response.status -ne 'error' -or
                $response.win32Error -ne 170) {
                throw "Expected the same-account session limit; broker returned: $responseText"
            }
            $controlPipe.Dispose()
            $dataPipes | ForEach-Object { $_.Dispose() }
            return $null
        }
        if ($response.requestId -ne $requestId -or $response.status -ne 'ok' -or
            $response.reasonCode -ne 'launched' -or $response.processId -le 0) {
            throw "Broker concurrency launch failed: $responseText"
        }
        [LaunchAs.BrokerSameAccountPipes]::WriteTerminalSize($dataPipes[2], 120, 30)
        $output = [LaunchAs.BrokerSameAccountPipes]::ReadUntil(
            $dataPipes[1], $readyMarker, 10000)
        $logonSidMatch = [regex]::Match($output, 'S-1-5-5-[0-9]+-[0-9]+')
        if (-not $logonSidMatch.Success) {
            throw "The broker command did not report a logon SID. Output:`n$output"
        }
        return [pscustomobject]@{
            RequestId   = $requestId
            ProcessId   = [int] $response.processId
            ControlPipe = $controlPipe
            DataPipes   = $dataPipes
            LogonSid    = $logonSidMatch.Value
            Output      = $output
            Closed      = $false
        }
    }
    catch {
        $controlPipe.Dispose()
        $dataPipes | ForEach-Object { $_.Dispose() }
        throw
    }
}

function Disconnect-BrokerSession([object] $Session) {
    if ($null -eq $Session -or $Session.Closed) {
        return
    }
    $Session.Closed = $true
    $Session.ControlPipe.Dispose()
}

function Close-BrokerSession([object] $Session) {
    if ($null -eq $Session) {
        return
    }
    Disconnect-BrokerSession $Session
    $Session.DataPipes | ForEach-Object { $_.Dispose() }
}

function Complete-BrokerSession([object] $Session) {
    $buffer = [byte[]]::new(4096)
    $readTask = $Session.ControlPipe.ReadAsync($buffer, 0, $buffer.Length)
    if (-not $readTask.Wait(20000)) {
        throw "Broker session $($Session.RequestId) did not report command exit."
    }
    $bytesRead = $readTask.Result
    if ($bytesRead -eq 0) {
        throw "Broker session $($Session.RequestId) closed without an exit response."
    }
    $responseText = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
    $response = $responseText | ConvertFrom-Json
    if ($response.requestId -ne $Session.RequestId -or $response.status -ne 'ok' -or
        $response.reasonCode -ne 'exited' -or $response.exitCode -ne 37 -or
        $response.win32Error -ne 0) {
        throw "Unexpected broker exit response: $responseText"
    }
    if (-not (Wait-ProcessExit $Session.ProcessId)) {
        throw "Broker host PID $($Session.ProcessId) remained alive after command exit."
    }
    Close-BrokerSession $Session
}

function Wait-ProcessExit([int] $ProcessId, [int] $TimeoutSeconds = 5) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline -and
        (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
        Start-Sleep -Milliseconds 100
    }
    return $null -eq (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
}

$first = $null
$second = $null
$replacement = $null
$limitResult = $null
try {
    $first = New-BrokerSession
    $second = New-BrokerSession

    if ($first.ProcessId -eq $second.ProcessId) {
        throw "Both sessions reported PID $($first.ProcessId)."
    }
    if ($first.LogonSid -eq $second.LogonSid) {
        throw "Both sessions used logon SID $($first.LogonSid)."
    }
    if (-not (Get-Process -Id $first.ProcessId -ErrorAction SilentlyContinue) -or
        -not (Get-Process -Id $second.ProcessId -ErrorAction SilentlyContinue)) {
        throw 'One of the overlapping broker sessions exited before the concurrency check.'
    }
    $limitResult = New-BrokerSession -AllowSessionLimit
    if ($null -ne $limitResult) {
        throw 'The broker admitted a third same-account session.'
    }

    Disconnect-BrokerSession $first
    if (-not (Get-Process -Id $second.ProcessId -ErrorAction SilentlyContinue)) {
        throw "Second broker child PID $($second.ProcessId) ended with the first session."
    }

    $replacement = New-BrokerSession -AllowSessionLimit -SleepSeconds 1
    if ($null -ne $replacement -and
        (Get-Process -Id $first.ProcessId -ErrorAction SilentlyContinue)) {
        throw 'The broker reused a session slot before the disconnected process tree exited.'
    }
    if (-not (Wait-ProcessExit $first.ProcessId)) {
        throw "First broker child PID $($first.ProcessId) survived its control disconnect."
    }
    $first.DataPipes | ForEach-Object { $_.Dispose() }
    if ($null -eq $replacement) {
        $replacement = New-BrokerSession -SleepSeconds 1
    }
    if (-not (Get-Process -Id $replacement.ProcessId -ErrorAction SilentlyContinue)) {
        throw 'The replacement session exited before the released-slot check.'
    }
    Complete-BrokerSession $replacement
    Disconnect-BrokerSession $second
    if (-not (Wait-ProcessExit $second.ProcessId)) {
        throw "Second broker child PID $($second.ProcessId) survived its control disconnect."
    }
}
finally {
    Close-BrokerSession $first
    Close-BrokerSession $second
    Close-BrokerSession $replacement
    Close-BrokerSession $limitResult
}

$successMessage = ('Same-account concurrency succeeded; PIDs {0} and {1} ran commands under ' +
    'distinct logon SIDs, the third launch was rejected, and the released slot was reused only ' +
    'after teardown.') -f $first.ProcessId, $second.ProcessId
Write-Output $successMessage
