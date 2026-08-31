// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerControlClient.h"

#include "BrokerControlPipe.h"
#include "BrokerProtocol.h"

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

[[nodiscard]] bool AppendUtf8(std::wstring_view value, std::string& output)
{
    const int characterCount = WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (characterCount <= 0)
    {
        return false;
    }
    const std::size_t start = output.size();
    output.resize(start + static_cast<std::size_t>(characterCount));
    return WideCharToMultiByte(CP_UTF8,
               WC_ERR_INVALID_CHARS,
               value.data(),
               static_cast<int>(value.size()),
               output.data() + start,
               characterCount,
               nullptr,
               nullptr) == characterCount;
}

[[nodiscard]] bool AppendJsonString(std::wstring_view value, std::string& output)
{
    std::string utf8;
    if (!AppendUtf8(value, utf8))
    {
        return false;
    }
    output.push_back('"');
    for (const unsigned char character : utf8)
    {
        if (character == '"' || character == '\\')
        {
            output.push_back('\\');
            output.push_back(static_cast<char>(character));
        }
        else if (character < 0x20)
        {
            constexpr char hexadecimal[] = "0123456789ABCDEF";
            output += "\\u00";
            output.push_back(hexadecimal[(character >> 4) & 0xF]);
            output.push_back(hexadecimal[character & 0xF]);
        }
        else
        {
            output.push_back(static_cast<char>(character));
        }
    }
    output.push_back('"');
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
    if (!AppendJsonString(requestId, request))
    {
        return false;
    }
    request += ",\"operation\":\"launch\",\"profileId\":";
    if (!AppendJsonString(profileId, request))
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
        if (!AppendJsonString(arguments[index], request))
        {
            return false;
        }
    }
    request += "],\"workingDirectory\":";
    if (!AppendJsonString(workingDirectory, request))
    {
        return false;
    }
    request += ",\"console\":{\"pipeIn\":";
    if (!AppendJsonString(pipes.input, request))
    {
        return false;
    }
    request += ",\"pipeOut\":";
    if (!AppendJsonString(pipes.output, request))
    {
        return false;
    }
    request += ",\"pipeResize\":";
    if (!AppendJsonString(pipes.resize, request))
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

DWORD WaitForBrokerConsoleExit(BrokerControlConnection& connection, DWORD& exitCode)
{
    exitCode = 0;
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
    DWORD brokerError = ERROR_INVALID_DATA;
    if (broker::ParseErrorResponse(response, connection.requestId(), brokerError))
    {
        return brokerError;
    }
    return ERROR_INVALID_DATA;
}

} // namespace launch_as
