// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerControlClient.h"

#include "BrokerControlPipe.h"
#include "BrokerProtocol.h"
#include "Win32Support.h"

#include <Windows.h>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace launch_as
{
namespace
{

[[nodiscard]] DWORD SendLaunchRequest(std::wstring requestId, const std::string& request,
    BrokerControlConnection& connection, DWORD& processId, bool log)
{
    LaunchLog diagnostics;
    if (log)
    {
        const DWORD error = diagnostics.Start(requestId);
        if (error != ERROR_SUCCESS)
        {
            std::wcerr << L"Could not start the launch log: " << FormatWindowsError(error) << L"\n";
            return error;
        }
    }
    HANDLE rawPipe = nullptr;
    const DWORD pipeError = broker::OpenBrokerControlPipe(rawPipe);
    if (pipeError != ERROR_SUCCESS)
    {
        diagnostics.Record(L"client.connect_failed", pipeError);
        return pipeError;
    }
    connection.Reset(rawPipe);
    connection.SetRequestId(std::move(requestId));
    connection.log() = std::move(diagnostics);
    const DWORD writeError = broker::WritePipeMessage(connection.get(), request);
    if (writeError != ERROR_SUCCESS)
    {
        connection.log().Record(L"client.request_failed", writeError);
        connection.Reset();
        return writeError;
    }
    std::string response;
    const DWORD readError = broker::ReadPipeMessage(connection.get(), response);
    connection.log().Collect();
    if (readError != ERROR_SUCCESS)
    {
        connection.log().Record(L"client.response_failed", readError);
        connection.Reset();
        return readError;
    }
    if (broker::ParseLaunchSuccessResponse(response, connection.requestId(), processId))
    {
        connection.log().Record(L"client.launch_started", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }
    DWORD brokerError = ERROR_INVALID_DATA;
    if (broker::ParseErrorResponse(response, connection.requestId(), brokerError))
    {
        connection.log().Record(L"client.launch_failed", brokerError);
        connection.Reset();
        return brokerError;
    }
    connection.Reset();
    return ERROR_INVALID_DATA;
}

} // namespace

HANDLE BrokerControlConnection::get() const noexcept { return pipe_.get(); }

BrokerControlConnection::~BrokerControlConnection() { Reset(); }

std::wstring_view BrokerControlConnection::requestId() const noexcept { return requestId_; }

void BrokerControlConnection::SetRequestId(std::wstring value) { requestId_ = std::move(value); }

void BrokerControlConnection::Reset(HANDLE pipe) noexcept
{
    log_.Collect();
    log_ = {};
    pipe_.reset(pipe);
    requestId_.clear();
}

DWORD LaunchBrokerInteractive(std::wstring_view profileId, std::span<const std::wstring> arguments,
    std::wstring_view workingDirectory, std::wstring_view leasePipe, std::wstring_view nonce,
    BrokerControlConnection& connection, DWORD& processId, bool restrictAccess, bool lowIntegrity,
    bool log)
{
    connection.Reset();
    processId = 0;
    std::wstring requestId;
    if (!CreateGuidString(requestId))
    {
        return ERROR_GEN_FAILURE;
    }
    std::string request;
    if (!broker::BuildInteractiveLaunchRequest(requestId,
            profileId,
            arguments,
            workingDirectory,
            leasePipe,
            nonce,
            request,
            restrictAccess,
            lowIntegrity,
            log))
    {
        return ERROR_INVALID_PARAMETER;
    }
    return SendLaunchRequest(std::move(requestId), request, connection, processId, log);
}

DWORD LaunchBrokerConsole(std::wstring_view profileId, std::span<const std::wstring> arguments,
    std::wstring_view workingDirectory, const TerminalPipeNames& pipes, bool inheritCursor,
    BrokerControlConnection& connection, DWORD& processId, bool restrictAccess, bool lowIntegrity,
    bool log)
{
    connection.Reset();
    processId = 0;
    std::wstring requestId;
    if (!CreateGuidString(requestId))
    {
        return ERROR_GEN_FAILURE;
    }
    std::string request;
    if (!broker::BuildConsoleLaunchRequest(requestId,
            profileId,
            arguments,
            workingDirectory,
            pipes.input,
            pipes.output,
            pipes.resize,
            inheritCursor,
            request,
            restrictAccess,
            lowIntegrity,
            log))
    {
        return ERROR_INVALID_PARAMETER;
    }
    return SendLaunchRequest(std::move(requestId), request, connection, processId, log);
}

DWORD WaitForBrokerConsoleExit(
    BrokerControlConnection& connection, DWORD& exitCode, std::wstring& diagnostics)
{
    exitCode = 0;
    diagnostics.clear();
    if (!connection.get())
    {
        return ERROR_INVALID_HANDLE;
    }
    std::string response;
    const DWORD readError = broker::ReadPipeMessage(connection.get(), response);
    connection.log().Collect();
    if (readError != ERROR_SUCCESS)
    {
        return readError;
    }
    if (broker::ParseLaunchExitResponse(response, connection.requestId(), exitCode))
    {
        connection.log().Finish();
        return ERROR_SUCCESS;
    }
    DWORD hostExitCode = 0;
    if (broker::ParseLaunchHostFailureResponse(
            response, connection.requestId(), hostExitCode, diagnostics))
    {
        connection.log().Finish();
        diagnostics = L"Broker console host failed (exit code " + std::to_wstring(hostExitCode) +
                      L"): " + diagnostics;
        return ERROR_GEN_FAILURE;
    }
    DWORD brokerError = ERROR_INVALID_DATA;
    if (broker::ParseErrorResponse(response, connection.requestId(), brokerError))
    {
        return brokerError;
    }
    return ERROR_INVALID_DATA;
}

} // namespace launch_as
