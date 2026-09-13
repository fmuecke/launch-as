// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerControlClient.h"

#include "BrokerControlPipe.h"
#include "BrokerProtocol.h"
#include "Utf8.h"

#include <Windows.h>
#include <array>
#include <objbase.h>
#include <string>
#include <utility>
#include <vector>

namespace launch_as
{
namespace
{

[[nodiscard]] bool AppendValidatedJsonString(std::wstring_view value, std::string& output)
{
    std::string validation;
    if (!WideToUtf8(value, validation))
    {
        return false;
    }
    broker::AppendJsonString(output, value);
    return true;
}

[[nodiscard]] bool BuildLaunchRequest(std::wstring_view requestId, std::wstring_view profileId,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    const TerminalPipeNames& pipes, COORD terminalSize, bool inheritCursor, std::string& request)
{
    if (profileId.empty() || arguments.empty() || workingDirectory.empty() || pipes.input.empty() ||
        pipes.output.empty() || pipes.resize.empty() || terminalSize.X <= 0 || terminalSize.Y <= 0)
    {
        return false;
    }
    request = "{\"version\":1,\"requestId\":";
    if (!AppendValidatedJsonString(requestId, request))
    {
        return false;
    }
    request += ",\"operation\":\"launch\",\"profileId\":";
    if (!AppendValidatedJsonString(profileId, request))
    {
        return false;
    }
    request += ",\"mode\":\"console\",\"arguments\":[";
    for (std::size_t index = 0; index < arguments.size(); ++index)
    {
        if (index != 0)
        {
            request.push_back(',');
        }
        if (!AppendValidatedJsonString(arguments[index], request))
        {
            return false;
        }
    }
    request += "],\"workingDirectory\":";
    if (!AppendValidatedJsonString(workingDirectory, request))
    {
        return false;
    }
    request += ",\"console\":{\"pipeIn\":";
    if (!AppendValidatedJsonString(pipes.input, request))
    {
        return false;
    }
    request += ",\"pipeOut\":";
    if (!AppendValidatedJsonString(pipes.output, request))
    {
        return false;
    }
    request += ",\"pipeResize\":";
    if (!AppendValidatedJsonString(pipes.resize, request))
    {
        return false;
    }
    request += ",\"cols\":" + std::to_string(terminalSize.X) +
               ",\"rows\":" + std::to_string(terminalSize.Y) +
               ",\"inheritCursor\":" + (inheritCursor ? "true" : "false") + "}}";
    return request.size() <= broker::MaximumMessageBytes;
}

} // namespace

HANDLE BrokerControlConnection::get() const noexcept { return pipe_.get(); }

std::wstring_view BrokerControlConnection::requestId() const noexcept { return requestId_; }

void BrokerControlConnection::SetRequestId(std::wstring value) { requestId_ = std::move(value); }

void BrokerControlConnection::Reset(HANDLE pipe) noexcept
{
    pipe_.reset(pipe);
    requestId_.clear();
}

DWORD LaunchBrokerConsole(std::wstring_view profileId, std::span<const std::wstring> arguments,
    std::wstring_view workingDirectory, const TerminalPipeNames& pipes, COORD terminalSize,
    bool inheritCursor, BrokerControlConnection& connection, DWORD& processId)
{
    connection.Reset();
    processId = 0;
    GUID identifier {};
    if (FAILED(CoCreateGuid(&identifier)))
    {
        return ERROR_GEN_FAILURE;
    }
    wchar_t requestIdBuffer[39] {};
    if (StringFromGUID2(
            identifier, requestIdBuffer, static_cast<int>(std::size(requestIdBuffer))) != 39)
    {
        return ERROR_GEN_FAILURE;
    }
    const std::wstring requestId(requestIdBuffer + 1, 36);
    std::string request;
    if (!BuildLaunchRequest(requestId,
            profileId,
            arguments,
            workingDirectory,
            pipes,
            terminalSize,
            inheritCursor,
            request))
    {
        return ERROR_INVALID_PARAMETER;
    }
    HANDLE rawPipe = nullptr;
    const DWORD pipeError = broker::OpenBrokerControlPipe(rawPipe);
    if (pipeError != ERROR_SUCCESS)
    {
        return pipeError;
    }
    connection.Reset(rawPipe);
    connection.SetRequestId(requestId);
    DWORD bytesWritten = 0;
    const BOOL wroteRequest = WriteFile(connection.get(),
        request.data(),
        static_cast<DWORD>(request.size()),
        &bytesWritten,
        nullptr);
    const DWORD writeError = wroteRequest ? ERROR_SUCCESS : GetLastError();
    if (!wroteRequest || bytesWritten != request.size())
    {
        connection.Reset();
        return wroteRequest ? ERROR_WRITE_FAULT : writeError;
    }
    std::array<char, broker::MaximumMessageBytes> responseBuffer {};
    DWORD bytesRead = 0;
    const BOOL readResponse = ReadFile(connection.get(),
        responseBuffer.data(),
        static_cast<DWORD>(responseBuffer.size()),
        &bytesRead,
        nullptr);
    const DWORD readError = readResponse ? ERROR_SUCCESS : GetLastError();
    if (!readResponse)
    {
        connection.Reset();
        return readError;
    }
    const std::string_view response(responseBuffer.data(), bytesRead);
    if (broker::ParseLaunchSuccessResponse(response, connection.requestId(), processId))
    {
        return ERROR_SUCCESS;
    }
    DWORD brokerError = ERROR_INVALID_DATA;
    if (broker::ParseErrorResponse(response, connection.requestId(), brokerError))
    {
        connection.Reset();
        return brokerError;
    }
    connection.Reset();
    return ERROR_INVALID_DATA;
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
    std::array<char, broker::MaximumMessageBytes> responseBuffer {};
    DWORD bytesRead = 0;
    const BOOL readResponse = ReadFile(connection.get(),
        responseBuffer.data(),
        static_cast<DWORD>(responseBuffer.size()),
        &bytesRead,
        nullptr);
    const DWORD readError = readResponse ? ERROR_SUCCESS : GetLastError();
    if (!readResponse)
    {
        return readError;
    }
    const std::string_view response(responseBuffer.data(), bytesRead);
    if (broker::ParseLaunchExitResponse(response, connection.requestId(), exitCode))
    {
        return ERROR_SUCCESS;
    }
    DWORD hostExitCode = 0;
    if (broker::ParseLaunchHostFailureResponse(
            response, connection.requestId(), hostExitCode, diagnostics))
    {
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
