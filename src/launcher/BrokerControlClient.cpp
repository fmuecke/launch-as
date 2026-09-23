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

[[nodiscard]] bool BuildLaunchRequest(std::wstring_view requestId, std::wstring_view profileId,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    const TerminalPipeNames& pipes, COORD terminalSize, bool inheritCursor, std::string& request)
{
    if (profileId.empty() || arguments.empty() || workingDirectory.empty() || pipes.input.empty() ||
        pipes.output.empty() || pipes.resize.empty() || terminalSize.X <= 0 || terminalSize.Y <= 0)
    {
        return false;
    }
    if (!IsValidUtf16(requestId) || !IsValidUtf16(profileId) || !IsValidUtf16(workingDirectory) ||
        !IsValidUtf16(pipes.input) || !IsValidUtf16(pipes.output) || !IsValidUtf16(pipes.resize))
    {
        return false;
    }
    for (const std::wstring& argument : arguments)
    {
        if (!IsValidUtf16(argument))
        {
            return false;
        }
    }
    request = "{\"version\":1,\"requestId\":";
    broker::AppendJsonString(request, requestId);
    request += ",\"operation\":\"launch\",\"profileId\":";
    broker::AppendJsonString(request, profileId);
    request += ",\"mode\":\"console\",\"arguments\":[";
    for (std::size_t index = 0; index < arguments.size(); ++index)
    {
        if (index != 0)
        {
            request.push_back(',');
        }
        broker::AppendJsonString(request, arguments[index]);
    }
    request += "],\"workingDirectory\":";
    broker::AppendJsonString(request, workingDirectory);
    request += ",\"console\":{\"pipeIn\":";
    broker::AppendJsonString(request, pipes.input);
    request += ",\"pipeOut\":";
    broker::AppendJsonString(request, pipes.output);
    request += ",\"pipeResize\":";
    broker::AppendJsonString(request, pipes.resize);
    request += ",\"cols\":" + std::to_string(terminalSize.X) +
               ",\"rows\":" + std::to_string(terminalSize.Y) +
               ",\"inheritCursor\":" + (inheritCursor ? "true" : "false") + "}}";
    return request.size() <= broker::MaximumMessageBytes;
}

[[nodiscard]] DWORD CreateRequestId(std::wstring& requestId)
{
    requestId.clear();
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
    requestId.assign(requestIdBuffer + 1, 36);
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD SendLaunchRequest(std::wstring requestId, const std::string& request,
    BrokerControlConnection& connection, DWORD& processId)
{
    HANDLE rawPipe = nullptr;
    const DWORD pipeError = broker::OpenBrokerControlPipe(rawPipe);
    if (pipeError != ERROR_SUCCESS)
    {
        return pipeError;
    }
    connection.Reset(rawPipe);
    connection.SetRequestId(std::move(requestId));
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

} // namespace

bool BuildInteractiveLaunchRequest(std::wstring_view requestId, std::wstring_view profileId,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    std::wstring_view leasePipe, std::wstring_view nonce, std::string& request)
{
    if (requestId.empty() || profileId.empty() || arguments.empty() || workingDirectory.empty() ||
        leasePipe.empty() || nonce.empty() || !IsValidUtf16(requestId) ||
        !IsValidUtf16(profileId) || !IsValidUtf16(workingDirectory) || !IsValidUtf16(leasePipe) ||
        !IsValidUtf16(nonce))
    {
        return false;
    }
    for (const std::wstring& argument : arguments)
    {
        if (!IsValidUtf16(argument))
        {
            return false;
        }
    }
    request = "{\"version\":1,\"requestId\":";
    broker::AppendJsonString(request, requestId);
    request += ",\"operation\":\"launch\",\"profileId\":";
    broker::AppendJsonString(request, profileId);
    request += ",\"mode\":\"interactive\",\"arguments\":[";
    for (std::size_t index = 0; index < arguments.size(); ++index)
    {
        if (index != 0)
        {
            request.push_back(',');
        }
        broker::AppendJsonString(request, arguments[index]);
    }
    request += "],\"workingDirectory\":";
    broker::AppendJsonString(request, workingDirectory);
    request += ",\"interactive\":{\"leasePipe\":";
    broker::AppendJsonString(request, leasePipe);
    request += ",\"nonce\":";
    broker::AppendJsonString(request, nonce);
    request += "}}";
    return request.size() <= broker::MaximumMessageBytes;
}

HANDLE BrokerControlConnection::get() const noexcept { return pipe_.get(); }

std::wstring_view BrokerControlConnection::requestId() const noexcept { return requestId_; }

void BrokerControlConnection::SetRequestId(std::wstring value) { requestId_ = std::move(value); }

void BrokerControlConnection::Reset(HANDLE pipe) noexcept
{
    pipe_.reset(pipe);
    requestId_.clear();
}

DWORD LaunchBrokerInteractive(std::wstring_view profileId, std::span<const std::wstring> arguments,
    std::wstring_view workingDirectory, std::wstring_view leasePipe, std::wstring_view nonce,
    BrokerControlConnection& connection, DWORD& processId)
{
    connection.Reset();
    processId = 0;
    std::wstring requestId;
    const DWORD requestIdError = CreateRequestId(requestId);
    if (requestIdError != ERROR_SUCCESS)
    {
        return requestIdError;
    }
    std::string request;
    if (!BuildInteractiveLaunchRequest(
            requestId, profileId, arguments, workingDirectory, leasePipe, nonce, request))
    {
        return ERROR_INVALID_PARAMETER;
    }
    return SendLaunchRequest(std::move(requestId), request, connection, processId);
}

DWORD LaunchBrokerConsole(std::wstring_view profileId, std::span<const std::wstring> arguments,
    std::wstring_view workingDirectory, const TerminalPipeNames& pipes, COORD terminalSize,
    bool inheritCursor, BrokerControlConnection& connection, DWORD& processId)
{
    connection.Reset();
    processId = 0;
    std::wstring requestId;
    const DWORD requestIdError = CreateRequestId(requestId);
    if (requestIdError != ERROR_SUCCESS)
    {
        return requestIdError;
    }
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
    return SendLaunchRequest(std::move(requestId), request, connection, processId);
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
