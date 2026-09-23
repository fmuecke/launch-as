// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "InteractiveDesktopLeaseClient.h"

#include "BrokerProtocol.h"

#include <Sddl.h>
#include <Windows.h>
#include <array>
#include <string>
#include <utility>

namespace launch_as::broker
{
namespace
{

constexpr DWORD ConnectTimeoutMilliseconds = 5'000;

[[nodiscard]] bool IsInteractiveLeasePipeName(std::wstring_view value) noexcept
{
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\launch-as-interactive-";
    return value.size() > prefix.size() && value.size() <= 256 && value.starts_with(prefix) &&
           value.find_first_of(L"\\/", prefix.size()) == std::wstring_view::npos;
}

[[nodiscard]] DWORD OpenInteractiveLeasePipe(std::wstring_view pipeName, HANDLE& pipe)
{
    pipe = nullptr;
    if (!IsInteractiveLeasePipeName(pipeName))
    {
        return ERROR_INVALID_NAME;
    }
    const std::wstring name(pipeName);
    const ULONGLONG deadline = GetTickCount64() + ConnectTimeoutMilliseconds;
    DWORD lastError = ERROR_FILE_NOT_FOUND;
    do
    {
        HANDLE opened = CreateFileW(name.c_str(),
            FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
            0,
            nullptr,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr);
        if (opened != INVALID_HANDLE_VALUE)
        {
            DWORD readMode = PIPE_READMODE_MESSAGE;
            if (!SetNamedPipeHandleState(opened, &readMode, nullptr, nullptr))
            {
                const DWORD modeError = GetLastError();
                CloseHandle(opened);
                return modeError;
            }
            pipe = opened;
            return ERROR_SUCCESS;
        }
        lastError = GetLastError();
        if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PIPE_BUSY)
        {
            return lastError;
        }
        static_cast<void>(WaitNamedPipeW(name.c_str(), 50));
    } while (GetTickCount64() < deadline);
    return lastError;
}

[[nodiscard]] DWORD WriteMessage(HANDLE pipe, std::string_view message)
{
    DWORD bytesWritten = 0;
    if (!WriteFile(
            pipe, message.data(), static_cast<DWORD>(message.size()), &bytesWritten, nullptr))
    {
        const DWORD writeError = GetLastError();
        return writeError;
    }
    return bytesWritten == message.size() ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
}

[[nodiscard]] DWORD ReadMessage(HANDLE pipe, std::string& message)
{
    std::array<char, MaximumMessageBytes> buffer {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr))
    {
        const DWORD readError = GetLastError();
        return readError;
    }
    if (bytesRead == 0)
    {
        return ERROR_BROKEN_PIPE;
    }
    message.assign(buffer.data(), bytesRead);
    return ERROR_SUCCESS;
}

} // namespace

InteractiveDesktopLeaseConnection::~InteractiveDesktopLeaseConnection() { Reset(); }

InteractiveDesktopLeaseConnection::InteractiveDesktopLeaseConnection(
    InteractiveDesktopLeaseConnection&& other) noexcept
    : pipe_(std::exchange(other.pipe_, nullptr)), nonce_(std::move(other.nonce_))
{
}

InteractiveDesktopLeaseConnection& InteractiveDesktopLeaseConnection::operator=(
    InteractiveDesktopLeaseConnection&& other) noexcept
{
    if (this != &other)
    {
        Reset();
        pipe_ = std::exchange(other.pipe_, nullptr);
        nonce_ = std::move(other.nonce_);
    }
    return *this;
}

InteractiveDesktopLeaseConnection::operator bool() const noexcept { return pipe_ != nullptr; }

void InteractiveDesktopLeaseConnection::Reset() noexcept
{
    if (pipe_ != nullptr)
    {
        CloseHandle(pipe_);
        pipe_ = nullptr;
    }
    nonce_.clear();
}

DWORD AcquireInteractiveDesktopLease(std::wstring_view pipeName, std::wstring_view nonce,
    PSID childLogonSid, InteractiveDesktopLeaseConnection& connection)
{
    connection.Reset();
    if (!IsValidSid(childLogonSid))
    {
        return ERROR_INVALID_SID;
    }
    PWSTR rawSidText = nullptr;
    if (!ConvertSidToStringSidW(childLogonSid, &rawSidText))
    {
        const DWORD sidError = GetLastError();
        return sidError;
    }
    const std::wstring sidText(rawSidText);
    LocalFree(rawSidText);
    const std::string request = BuildInteractiveLeaseAcquireRequest(nonce, sidText);
    if (request.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    HANDLE pipe = nullptr;
    const DWORD openError = OpenInteractiveLeasePipe(pipeName, pipe);
    if (openError != ERROR_SUCCESS)
    {
        return openError;
    }
    connection.pipe_ = pipe;
    connection.nonce_ = nonce;
    const DWORD writeError = WriteMessage(connection.pipe_, request);
    if (writeError != ERROR_SUCCESS)
    {
        connection.Reset();
        return writeError;
    }
    std::string response;
    const DWORD readError = ReadMessage(connection.pipe_, response);
    if (readError != ERROR_SUCCESS)
    {
        connection.Reset();
        return readError;
    }
    DWORD leaseError = ERROR_INVALID_DATA;
    if (!ParseInteractiveLeaseResponse(
            response, InteractiveLeaseOperation::Acquire, nonce, leaseError))
    {
        connection.Reset();
        return ERROR_INVALID_DATA;
    }
    if (leaseError != ERROR_SUCCESS)
    {
        connection.Reset();
    }
    return leaseError;
}

DWORD ReleaseInteractiveDesktopLease(InteractiveDesktopLeaseConnection& connection)
{
    if (!connection)
    {
        return ERROR_INVALID_HANDLE;
    }
    const std::string request = BuildInteractiveLeaseReleaseRequest(connection.nonce_);
    const DWORD writeError = WriteMessage(connection.pipe_, request);
    if (writeError != ERROR_SUCCESS)
    {
        connection.Reset();
        return writeError;
    }
    std::string response;
    const DWORD readError = ReadMessage(connection.pipe_, response);
    if (readError != ERROR_SUCCESS)
    {
        connection.Reset();
        return readError;
    }
    DWORD leaseError = ERROR_INVALID_DATA;
    const bool parsed = ParseInteractiveLeaseResponse(
        response, InteractiveLeaseOperation::Release, connection.nonce_, leaseError);
    connection.Reset();
    return parsed ? leaseError : ERROR_INVALID_DATA;
}

} // namespace launch_as::broker
