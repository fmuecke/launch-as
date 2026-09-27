// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "InteractiveDesktopLeaseClient.h"

#include "BrokerProtocol.h"

#include <Sddl.h>
#include <Windows.h>
#include <string>
#include <utility>

namespace launch_as::broker
{
namespace
{

constexpr DWORD ConnectTimeoutMilliseconds = 5'000;

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
    const DWORD writeError = WritePipeMessage(connection.pipe_, request);
    if (writeError != ERROR_SUCCESS)
    {
        connection.Reset();
        return writeError;
    }
    std::string response;
    const DWORD readError = ReadPipeMessage(connection.pipe_, response);
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
    const DWORD writeError = WritePipeMessage(connection.pipe_, request);
    if (writeError != ERROR_SUCCESS)
    {
        connection.Reset();
        return writeError;
    }
    std::string response;
    const DWORD readError = ReadPipeMessage(connection.pipe_, response);
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
