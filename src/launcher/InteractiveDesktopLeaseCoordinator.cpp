// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "InteractiveDesktopLeaseCoordinator.h"

#include "BrokerProtocol.h"
#include "InteractiveDesktopAclLease.h"

#include <Sddl.h>
#include <Windows.h>
#include <array>
#include <string>
#include <vector>

namespace launch_as
{
namespace
{

[[nodiscard]] bool IsInteractiveLeasePipeName(std::wstring_view value) noexcept
{
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\launch-as-interactive-";
    return value.size() > prefix.size() && value.size() <= 256 && value.starts_with(prefix) &&
           value.find_first_of(L"\\/", prefix.size()) == std::wstring_view::npos;
}

[[nodiscard]] DWORD ValidateLocalSystemToken(HANDLE token)
{
    DWORD userBytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &userBytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || userBytes == 0)
    {
        return sizeError;
    }
    std::vector<BYTE> userBuffer(userBytes);
    if (!GetTokenInformation(token, TokenUser, userBuffer.data(), userBytes, &userBytes))
    {
        const DWORD userError = GetLastError();
        return userError;
    }
    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid {};
    DWORD systemSidBytes = static_cast<DWORD>(systemSid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidBytes))
    {
        const DWORD sidError = GetLastError();
        return sidError;
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    if (!IsValidSid(user->User.Sid) || EqualSid(user->User.Sid, systemSid.data()) == FALSE)
    {
        return ERROR_ACCESS_DENIED;
    }
    DWORD sessionId = MAXDWORD;
    DWORD returnedBytes = 0;
    if (!GetTokenInformation(
            token, TokenSessionId, &sessionId, sizeof(sessionId), &returnedBytes) ||
        returnedBytes != sizeof(sessionId))
    {
        const DWORD sessionError = GetLastError();
        return sessionError;
    }
    return sessionId == 0 ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}

[[nodiscard]] DWORD ValidateBrokerPeer(HANDLE pipe)
{
    if (!ImpersonateNamedPipeClient(pipe))
    {
        const DWORD impersonationError = GetLastError();
        return impersonationError;
    }
    HANDLE threadToken = nullptr;
    const BOOL openedThreadToken =
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &threadToken);
    const DWORD tokenError = openedThreadToken ? ERROR_SUCCESS : GetLastError();
    const BOOL reverted = RevertToSelf();
    if (!reverted)
    {
        RaiseFailFastException(nullptr, nullptr, 0);
        return ERROR_ACCESS_DENIED;
    }
    if (!openedThreadToken)
    {
        return tokenError;
    }
    const DWORD threadIdentityError = ValidateLocalSystemToken(threadToken);
    CloseHandle(threadToken);
    if (threadIdentityError != ERROR_SUCCESS)
    {
        return threadIdentityError;
    }

    ULONG clientProcessId = 0;
    if (!GetNamedPipeClientProcessId(pipe, &clientProcessId) || clientProcessId == 0)
    {
        const DWORD processIdError = GetLastError();
        return processIdError == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : processIdError;
    }
    ULONG clientSessionId = MAXDWORD;
    if (!GetNamedPipeClientSessionId(pipe, &clientSessionId))
    {
        const DWORD sessionError = GetLastError();
        return sessionError;
    }
    return clientSessionId == 0 ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}

[[nodiscard]] DWORD ReadMessage(HANDLE pipe, std::string& message)
{
    std::array<char, broker::MaximumMessageBytes> buffer {};
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

} // namespace

DWORD CreateInteractiveDesktopLeasePipe(std::wstring_view pipeName, HANDLE& pipe)
{
    pipe = nullptr;
    if (!IsInteractiveLeasePipeName(pipeName))
    {
        return ERROR_INVALID_NAME;
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }
    SECURITY_ATTRIBUTES attributes {};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    const std::wstring name(pipeName);
    HANDLE created = CreateNamedPipeW(name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        static_cast<DWORD>(broker::MaximumMessageBytes),
        static_cast<DWORD>(broker::MaximumMessageBytes),
        0,
        &attributes);
    const DWORD pipeError = created == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    LocalFree(descriptor);
    if (pipeError != ERROR_SUCCESS)
    {
        return pipeError;
    }
    pipe = created;
    return ERROR_SUCCESS;
}

DWORD CoordinateInteractiveDesktopLease(
    HANDLE pipe, std::wstring_view expectedNonce, HANDLE launchCompletedEvent)
{
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE || launchCompletedEvent == nullptr ||
        launchCompletedEvent == INVALID_HANDLE_VALUE)
    {
        return ERROR_INVALID_HANDLE;
    }
    DWORD pipeMode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
    if (!SetNamedPipeHandleState(pipe, &pipeMode, nullptr, nullptr))
    {
        const DWORD modeError = GetLastError();
        return modeError;
    }
    for (;;)
    {
        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        const DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (connected || connectError == ERROR_PIPE_CONNECTED)
        {
            break;
        }
        if (connectError != ERROR_PIPE_LISTENING)
        {
            return connectError;
        }
        const DWORD waitResult = WaitForSingleObject(launchCompletedEvent, 10);
        if (waitResult == WAIT_OBJECT_0)
        {
            return ERROR_CANCELLED;
        }
        if (waitResult != WAIT_TIMEOUT)
        {
            return waitResult == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
        }
    }
    pipeMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    if (!SetNamedPipeHandleState(pipe, &pipeMode, nullptr, nullptr))
    {
        const DWORD modeError = GetLastError();
        return modeError;
    }
    return ServeInteractiveDesktopLease(pipe, expectedNonce);
}

DWORD ServeInteractiveDesktopLease(HANDLE connectedPipe, std::wstring_view expectedNonce)
{
    if (connectedPipe == nullptr || connectedPipe == INVALID_HANDLE_VALUE)
    {
        return ERROR_INVALID_HANDLE;
    }
    const DWORD peerError = ValidateBrokerPeer(connectedPipe);
    if (peerError != ERROR_SUCCESS)
    {
        return peerError;
    }
    std::string requestMessage;
    const DWORD readAcquireError = ReadMessage(connectedPipe, requestMessage);
    if (readAcquireError != ERROR_SUCCESS)
    {
        return readAcquireError;
    }
    broker::InteractiveLeaseRequest request;
    if (!broker::ParseInteractiveLeaseRequest(requestMessage, expectedNonce, request) ||
        request.operation != broker::InteractiveLeaseOperation::Acquire)
    {
        return ERROR_INVALID_DATA;
    }
    PSID logonSid = nullptr;
    if (!ConvertStringSidToSidW(request.childLogonSid.c_str(), &logonSid))
    {
        const DWORD sidError = GetLastError();
        return sidError;
    }
    InteractiveDesktopAclLease lease;
    const DWORD acquireError = lease.Acquire(logonSid);
    LocalFree(logonSid);
    const std::string acquireResponse = broker::BuildInteractiveLeaseResponse(
        broker::InteractiveLeaseOperation::Acquire, expectedNonce, acquireError);
    const DWORD writeAcquireError = WriteMessage(connectedPipe, acquireResponse);
    if (writeAcquireError != ERROR_SUCCESS || acquireError != ERROR_SUCCESS)
    {
        return writeAcquireError != ERROR_SUCCESS ? writeAcquireError : acquireError;
    }

    requestMessage.clear();
    const DWORD readReleaseError = ReadMessage(connectedPipe, requestMessage);
    if (readReleaseError != ERROR_SUCCESS)
    {
        return readReleaseError;
    }
    if (!broker::ParseInteractiveLeaseRequest(requestMessage, expectedNonce, request) ||
        request.operation != broker::InteractiveLeaseOperation::Release)
    {
        return ERROR_INVALID_DATA;
    }
    const DWORD releaseError = lease.Release();
    const std::string releaseResponse = broker::BuildInteractiveLeaseResponse(
        broker::InteractiveLeaseOperation::Release, expectedNonce, releaseError);
    const DWORD writeReleaseError = WriteMessage(connectedPipe, releaseResponse);
    return writeReleaseError == ERROR_SUCCESS ? releaseError : writeReleaseError;
}

} // namespace launch_as
