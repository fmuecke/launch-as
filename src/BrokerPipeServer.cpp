// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerPipeServer.h"

#include "BrokerProtocol.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <string>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr DWORD RequestTimeoutMilliseconds = 5'000;

[[nodiscard]] bool WaitForOperation(HANDLE pipe, HANDLE stopEvent, OVERLAPPED& overlapped,
    HANDLE operationEvent, DWORD& bytesTransferred)
{
    const std::array waitHandles {stopEvent, operationEvent};
    const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(waitHandles.size()),
        waitHandles.data(),
        FALSE,
        RequestTimeoutMilliseconds);
    if (wait != WAIT_OBJECT_0 + 1)
    {
        CancelIoEx(pipe, &overlapped);
        static_cast<void>(GetOverlappedResult(pipe, &overlapped, &bytesTransferred, TRUE));
        return false;
    }
    return GetOverlappedResult(pipe, &overlapped, &bytesTransferred, FALSE) != FALSE;
}

void BeginOverlappedOperation(OVERLAPPED& overlapped, HANDLE event)
{
    overlapped = {};
    overlapped.hEvent = event;
    ResetEvent(event);
}

[[nodiscard]] bool ReadRequest(HANDLE pipe, HANDLE stopEvent, std::string& message)
{
    std::vector<char> buffer(MaximumMessageBytes);
    UniqueHandle operationEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!operationEvent)
    {
        return false;
    }

    OVERLAPPED overlapped {};
    BeginOverlappedOperation(overlapped, operationEvent.get());
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, &overlapped))
    {
        const DWORD readError = GetLastError();
        if (readError != ERROR_IO_PENDING ||
            !WaitForOperation(pipe, stopEvent, overlapped, operationEvent.get(), bytesRead))
        {
            return false;
        }
    }
    if (bytesRead == 0)
    {
        return false;
    }
    message.assign(buffer.data(), bytesRead);
    return true;
}

[[nodiscard]] bool WriteResponse(HANDLE pipe, HANDLE stopEvent, const std::string& response)
{
    UniqueHandle operationEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!operationEvent)
    {
        return false;
    }

    OVERLAPPED overlapped {};
    BeginOverlappedOperation(overlapped, operationEvent.get());
    DWORD bytesWritten = 0;
    if (!WriteFile(
            pipe, response.data(), static_cast<DWORD>(response.size()), &bytesWritten, &overlapped))
    {
        const DWORD writeError = GetLastError();
        if (writeError != ERROR_IO_PENDING ||
            !WaitForOperation(pipe, stopEvent, overlapped, operationEvent.get(), bytesWritten))
        {
            return false;
        }
    }
    return bytesWritten == response.size();
}

[[nodiscard]] bool CaptureCallerIdentity(HANDLE pipe, BrokerCallerIdentity& identity)
{
    if (!ImpersonateNamedPipeClient(pipe))
    {
        return false;
    }

    HANDLE rawToken = nullptr;
    const BOOL openedToken = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &rawToken);
    const DWORD tokenError = openedToken ? ERROR_SUCCESS : GetLastError();
    const BOOL reverted = RevertToSelf();
    const DWORD revertError = reverted ? ERROR_SUCCESS : GetLastError();
    UniqueHandle token(rawToken);
    if (!openedToken || !reverted)
    {
        return false;
    }

    DWORD tokenUserBytes = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &tokenUserBytes);
    const DWORD sizeError = GetLastError();
    if (tokenError != ERROR_SUCCESS || revertError != ERROR_SUCCESS ||
        sizeError != ERROR_INSUFFICIENT_BUFFER || tokenUserBytes == 0)
    {
        return false;
    }
    std::vector<BYTE> tokenUser(tokenUserBytes);
    if (!GetTokenInformation(
            token.get(), TokenUser, tokenUser.data(), tokenUserBytes, &tokenUserBytes))
    {
        return false;
    }
    const auto* tokenUserInformation = reinterpret_cast<const TOKEN_USER*>(tokenUser.data());
    if (!IsValidSid(tokenUserInformation->User.Sid))
    {
        return false;
    }
    const DWORD callerSidBytes = GetLengthSid(tokenUserInformation->User.Sid);
    identity.userSid.resize(callerSidBytes);
    if (!CopySid(callerSidBytes, identity.userSid.data(), tokenUserInformation->User.Sid))
    {
        return false;
    }
    if (GetTokenLogonSid(token.get(), identity.logonSid) != ERROR_SUCCESS)
    {
        return false;
    }
    DWORD returnedBytes = 0;
    if (!GetTokenInformation(token.get(),
            TokenSessionId,
            &identity.sessionId,
            sizeof(identity.sessionId),
            &returnedBytes) ||
        returnedBytes != sizeof(identity.sessionId))
    {
        return false;
    }
    DWORD integrityBytes = 0;
    GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &integrityBytes);
    const DWORD integritySizeError = GetLastError();
    if (integritySizeError != ERROR_INSUFFICIENT_BUFFER || integrityBytes == 0)
    {
        return false;
    }
    std::vector<BYTE> integrity(integrityBytes);
    if (!GetTokenInformation(
            token.get(), TokenIntegrityLevel, integrity.data(), integrityBytes, &integrityBytes))
    {
        return false;
    }
    const auto* integrityLabel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrity.data());
    if (!IsValidSid(integrityLabel->Label.Sid))
    {
        return false;
    }
    const UCHAR* subAuthorityCount = GetSidSubAuthorityCount(integrityLabel->Label.Sid);
    if (subAuthorityCount == nullptr || *subAuthorityCount == 0)
    {
        return false;
    }
    const DWORD* integritySubAuthority =
        GetSidSubAuthority(integrityLabel->Label.Sid, *subAuthorityCount - 1);
    if (integritySubAuthority == nullptr)
    {
        return false;
    }
    identity.integrityLevel = *integritySubAuthority;
    TOKEN_ELEVATION elevation {};
    if (!GetTokenInformation(
            token.get(), TokenElevation, &elevation, sizeof(elevation), &returnedBytes) ||
        returnedBytes != sizeof(elevation))
    {
        return false;
    }
    identity.isElevated = elevation.TokenIsElevated != 0;

    ULONG clientProcessId = 0;
    if (!GetNamedPipeClientProcessId(pipe, &clientProcessId) || clientProcessId == 0)
    {
        return false;
    }
    UniqueHandle clientProcess(
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, clientProcessId));
    if (!clientProcess)
    {
        return false;
    }
    HANDLE rawClientToken = nullptr;
    if (!OpenProcessToken(clientProcess.get(), TOKEN_QUERY, &rawClientToken))
    {
        return false;
    }
    UniqueHandle clientToken(rawClientToken);

    DWORD clientTokenUserBytes = 0;
    GetTokenInformation(clientToken.get(), TokenUser, nullptr, 0, &clientTokenUserBytes);
    const DWORD clientSizeError = GetLastError();
    if (clientSizeError != ERROR_INSUFFICIENT_BUFFER || clientTokenUserBytes == 0)
    {
        return false;
    }
    std::vector<BYTE> clientTokenUser(clientTokenUserBytes);
    if (!GetTokenInformation(clientToken.get(),
            TokenUser,
            clientTokenUser.data(),
            clientTokenUserBytes,
            &clientTokenUserBytes))
    {
        return false;
    }

    const auto* client = reinterpret_cast<const TOKEN_USER*>(clientTokenUser.data());
    return IsValidSid(identity.userSid.data()) && IsValidSid(client->User.Sid) &&
           EqualSid(identity.userSid.data(), client->User.Sid) != FALSE;
}

} // namespace

void ServeControlPipeRequest(HANDLE pipe, HANDLE stopEvent,
    ConfigurationRequestHandler configurationRequestHandler, void* configurationContext,
    LaunchRequestHandler launchRequestHandler, void* launchContext)
{
    std::string message;
    BrokerRequest request;
    BrokerCallerIdentity caller;
    BrokerChildProcess child;
    std::string response;
    if (!ReadRequest(pipe, stopEvent, message) || !CaptureCallerIdentity(pipe, caller))
    {
        response = BuildErrorResponse(L"", "caller_identity", ERROR_ACCESS_DENIED);
    }
    else if (ParseBrokerRequest(message, request) != ParseResult::Success)
    {
        response = BuildErrorResponse(L"", "invalid_request", ERROR_INVALID_DATA);
    }
    else if (request.operation == RequestOperation::Enroll ||
             request.operation == RequestOperation::List ||
             request.operation == RequestOperation::Unenroll ||
             request.operation == RequestOperation::UnenrollAll)
    {
        if (configurationRequestHandler == nullptr)
        {
            response = BuildErrorResponse(request.requestId, "not_configured", ERROR_NOT_READY);
        }
        else
        {
            std::vector<std::wstring> accounts;
            const DWORD configurationError =
                configurationRequestHandler(configurationContext, request, caller, accounts);
            if (configurationError != ERROR_SUCCESS)
            {
                const char* reasonCode = request.operation == RequestOperation::Enroll
                                             ? "enrollment_failed"
                                             : "unenrollment_failed";
                response = BuildErrorResponse(request.requestId, reasonCode, configurationError);
            }
            else if (request.operation == RequestOperation::List)
            {
                response = BuildListResponse(request.requestId, accounts);
            }
            else
            {
                response = BuildSuccessResponse(request.requestId,
                    request.operation == RequestOperation::Enroll ? "enrolled" : "unenrolled");
            }
        }
    }
    else if (request.operation == RequestOperation::ConsoleLaunch)
    {
        if (launchRequestHandler == nullptr)
        {
            response = BuildErrorResponse(request.requestId, "not_configured", ERROR_NOT_READY);
        }
        else
        {
            const DWORD launchError = launchRequestHandler(launchContext, request, caller, child);
            if (launchError == ERROR_SUCCESS && child)
            {
                response = BuildLaunchSuccessResponse(request.requestId, child.processId());
            }
            else
            {
                response = BuildErrorResponse(request.requestId,
                    "launch_failed",
                    launchError == ERROR_SUCCESS ? ERROR_INVALID_DATA : launchError);
            }
        }
    }
    else
    {
        response = BuildErrorResponse(request.requestId, "invalid_request", ERROR_INVALID_DATA);
    }
    if (WriteResponse(pipe, stopEvent, response) && child)
    {
        std::string ignored;
        static_cast<void>(ReadRequest(pipe, stopEvent, ignored));
    }
}

} // namespace launch_as::broker
