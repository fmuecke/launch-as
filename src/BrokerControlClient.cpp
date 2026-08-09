// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerControlClient.h"

#include "BrokerProtocol.h"

#include <Windows.h>
#include <array>
#include <objbase.h>
#include <string>
#include <vector>

namespace launch_as
{
namespace
{

constexpr wchar_t ServiceName[] = L"launch-as-broker";
constexpr DWORD BrokerStartTimeoutMilliseconds = 5'000;

class ServiceHandle final
{
  public:
    explicit ServiceHandle(SC_HANDLE value = nullptr) noexcept : value_(value) {}
    ~ServiceHandle()
    {
        if (value_ != nullptr)
        {
            CloseServiceHandle(value_);
        }
    }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }

  private:
    SC_HANDLE value_ = nullptr;
};

[[nodiscard]] DWORD StartBrokerService()
{
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager)
    {
        const DWORD managerError = GetLastError();
        return managerError;
    }
    ServiceHandle service(OpenServiceW(manager.get(), ServiceName, SERVICE_START));
    if (!service)
    {
        const DWORD serviceError = GetLastError();
        return serviceError;
    }
    if (StartServiceW(service.get(), 0, nullptr))
    {
        return ERROR_SUCCESS;
    }
    const DWORD startError = GetLastError();
    return startError == ERROR_SERVICE_ALREADY_RUNNING ? ERROR_SUCCESS : startError;
}

[[nodiscard]] DWORD WaitForControlPipe()
{
    const ULONGLONG deadline = GetTickCount64() + BrokerStartTimeoutMilliseconds;
    DWORD waitError = ERROR_FILE_NOT_FOUND;
    do
    {
        if (WaitNamedPipeW(broker::ControlPipeName.data(), 0))
        {
            return ERROR_SUCCESS;
        }
        waitError = GetLastError();
        if (waitError != ERROR_FILE_NOT_FOUND && waitError != ERROR_PIPE_BUSY)
        {
            return waitError;
        }
        Sleep(50);
    } while (GetTickCount64() < deadline);
    return waitError;
}

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
    const TerminalPipeNames& pipes, COORD terminalSize, std::string& request)
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
               ",\"rows\":" + std::to_string(terminalSize.Y) + "}}";
    return request.size() <= broker::MaximumMessageBytes;
}

[[nodiscard]] DWORD OpenControlPipe(BrokerControlConnection& connection)
{
    if (!WaitNamedPipeW(broker::ControlPipeName.data(), 0))
    {
        const DWORD waitError = GetLastError();
        if (waitError != ERROR_FILE_NOT_FOUND)
        {
            return waitError;
        }
        const DWORD startError = StartBrokerService();
        if (startError != ERROR_SUCCESS)
        {
            return startError;
        }
        const DWORD readyError = WaitForControlPipe();
        if (readyError != ERROR_SUCCESS)
        {
            return readyError;
        }
    }
    HANDLE rawPipe = CreateFileW(broker::ControlPipeName.data(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    const DWORD openError = rawPipe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (rawPipe == INVALID_HANDLE_VALUE)
    {
        return openError;
    }
    connection.Reset(rawPipe);
    return ERROR_SUCCESS;
}

} // namespace

HANDLE BrokerControlConnection::get() const noexcept { return pipe_.get(); }

void BrokerControlConnection::Reset(HANDLE pipe) noexcept { pipe_.reset(pipe); }

DWORD LaunchBrokerConsole(std::wstring_view profileId, std::span<const std::wstring> arguments,
    std::wstring_view workingDirectory, const TerminalPipeNames& pipes, COORD terminalSize,
    BrokerControlConnection& connection, DWORD& processId)
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
    if (!BuildLaunchRequest(
            requestId, profileId, arguments, workingDirectory, pipes, terminalSize, request))
    {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD pipeError = OpenControlPipe(connection);
    if (pipeError != ERROR_SUCCESS)
    {
        return pipeError;
    }
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
    if (broker::ParseLaunchSuccessResponse(response, requestId, processId))
    {
        return ERROR_SUCCESS;
    }
    DWORD brokerError = ERROR_INVALID_DATA;
    if (broker::ParseErrorResponse(response, requestId, brokerError))
    {
        connection.Reset();
        return brokerError;
    }
    connection.Reset();
    return ERROR_INVALID_DATA;
}

} // namespace launch_as
