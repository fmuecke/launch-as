# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/launch-as

[CmdletBinding()]
param(
    [string]$PipeName = 'launch-as-broker.v1'
)

$requestId = [guid]::NewGuid().ToString()
$dataPipePrefix = "\\.\pipe\launch-as-probe-$requestId"
$request = [ordered]@{
    version = 1
    requestId = $requestId
    operation = 'launch'
    profileId = 'agent-sandbox'
    mode = 'console'
    arguments = @()
    workingDirectory = $PWD.Path
    console = [ordered]@{
        pipeIn = "$dataPipePrefix-in"
        pipeOut = "$dataPipePrefix-out"
        cols = 120
        rows = 30
    }
} | ConvertTo-Json -Compress

$pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
    '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
try {
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
    Write-Output "Broker probe succeeded; launched PID $($response.processId)."
}
finally {
    $pipe.Dispose()
}
