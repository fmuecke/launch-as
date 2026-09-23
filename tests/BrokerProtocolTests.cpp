// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProtocol.h"
#include "TestSupport.h"
#include "Utf8.h"

#include <array>
#include <iostream>
#include <string>
#include <utility>

namespace
{

static_assert(!noexcept(launch_as::broker::ParseBrokerRequest(
    std::declval<std::string_view>(), std::declval<launch_as::broker::BrokerRequest&>())));

constexpr char ValidRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "launch",
  "profileId": "LaunchAsUser",
  "mode": "console",
  "arguments": ["--resume", "caf\u00e9", "emoji \uD83D\uDE80"],
  "workingDirectory": "C:\\dev\\LaunchAsUser\\repo",
  "console": {
    "pipeIn": "\\\\.\\pipe\\launch-as-123-in",
    "pipeOut": "\\\\.\\pipe\\launch-as-123-out",
    "pipeResize": "\\\\.\\pipe\\launch-as-123-resize",
    "cols": 120,
    "rows": 30,
    "inheritCursor": true
  }
})json";

constexpr char LegacyConsoleRequest[] =
    R"json({"version":1,"requestId":"123e4567-e89b-12d3-a456-426614174000","operation":"launch","profileId":"LaunchAsUser","mode":"console","arguments":[],"workingDirectory":"C:\\repo","console":{"pipeIn":"\\\\.\\pipe\\launch-as-123-in","pipeOut":"\\\\.\\pipe\\launch-as-123-out","pipeResize":"\\\\.\\pipe\\launch-as-123-resize","cols":120,"rows":30}})json";

constexpr char InteractiveRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "launch",
  "profileId": "LaunchAsUser",
  "mode": "interactive",
  "arguments": ["--resume"],
  "workingDirectory": "C:\\dev\\LaunchAsUser\\repo",
  "interactive": {
    "leasePipe": "\\\\.\\pipe\\launch-as-interactive-123e4567e89b12d3a456426614174000",
    "nonce": "6f9619ff-8b86-d011-b42d-00c04fc964ff"
  }
})json";

constexpr char ListRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "list"
})json";

constexpr char ForgetRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "forget",
  "profileId": "LaunchAsUser",
  "confirmed": true
})json";

constexpr char DeleteRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "delete",
  "profileId": "LaunchAsUser",
  "confirmed": true,
  "force": true
})json";

constexpr char UnconfirmedCreateRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "create",
  "profileId": "sandbox"
})json";

constexpr wchar_t InteractiveLeaseNonce[] = L"6f9619ff-8b86-d011-b42d-00c04fc964ff";
constexpr wchar_t InteractiveLeaseLogonSid[] = L"S-1-5-5-123-456";

} // namespace

int wmain()
{
    launch_as::broker::BrokerRequest request;
    if (!Expect(launch_as::broker::ParseBrokerRequest(ValidRequest, request) ==
                    launch_as::broker::ParseResult::Success,
            L"Valid console request was rejected.") ||
        !Expect(request.arguments.size() == 3 && request.arguments[1] == L"café" &&
                    request.arguments[2] == L"emoji \U0001F680",
            L"Unicode argument was not decoded.") ||
        !Expect(request.console.columns == 120 && request.console.rows == 30,
            L"Console size was not decoded.") ||
        !Expect(request.console.inheritCursor, L"Cursor-inheritance capability was not decoded.") ||
        !Expect(request.profileId == L"LaunchAsUser", L"Profile id was not decoded."))
    {
        return 1;
    }
    if (!Expect(launch_as::broker::ParseBrokerRequest(LegacyConsoleRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    !request.console.inheritCursor,
            L"A console request without cursor inheritance did not default to false."))
    {
        return 1;
    }

    std::string controlCharacterProfile(ValidRequest);
    controlCharacterProfile.replace(
        controlCharacterProfile.find("LaunchAsUser"), 12, "LaunchAsUser\\n");
    if (!Expect(launch_as::broker::ParseBrokerRequest(controlCharacterProfile, request) ==
                    launch_as::broker::ParseResult::InvalidRequest,
            L"A profile id containing a control character was accepted."))
    {
        return 1;
    }

    if (!Expect(launch_as::broker::IsValidProfileId(L"LaunchAsUser"),
            L"A valid profile id was rejected by the shared validator.") ||
        !Expect(!launch_as::broker::IsValidProfileId(L"LaunchAsUser=result=allowed"),
            L"The shared profile validator accepted an audit-field separator."))
    {
        return 1;
    }

    if (!Expect(launch_as::broker::ParseBrokerRequest(ListRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::List,
            L"List request was rejected.") ||
        !Expect(launch_as::broker::ParseBrokerRequest(ForgetRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::Forget,
            L"Forget request was rejected."))
    {
        return 1;
    }
    if (!Expect(launch_as::broker::ParseBrokerRequest(DeleteRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::Delete &&
                    request.force,
            L"Forced delete request was rejected."))
    {
        return 1;
    }
    if (!Expect(launch_as::broker::ParseBrokerRequest(UnconfirmedCreateRequest, request) ==
                    launch_as::broker::ParseResult::InvalidRequest,
            L"Unconfirmed registration request was accepted."))
    {
        return 1;
    }

    launch_as::broker::InteractiveLeaseRequest leaseRequest;
    const std::string acquireLease = launch_as::broker::BuildInteractiveLeaseAcquireRequest(
        InteractiveLeaseNonce, InteractiveLeaseLogonSid);
    if (!Expect(acquireLease == "{\"version\":1,\"operation\":\"acquire\",\"nonce\":"
                                "\"6f9619ff-8b86-d011-b42d-00c04fc964ff\",\"desktop\":"
                                "\"WinSta0\\\\Default\",\"childLogonSid\":\"S-1-5-5-123-456\"}",
            L"Interactive lease acquire encoding is not stable.") ||
        !Expect(
            launch_as::broker::ParseInteractiveLeaseRequest(
                acquireLease, InteractiveLeaseNonce, leaseRequest) &&
                leaseRequest.operation == launch_as::broker::InteractiveLeaseOperation::Acquire &&
                leaseRequest.nonce == InteractiveLeaseNonce &&
                leaseRequest.desktop == L"WinSta0\\Default" &&
                leaseRequest.childLogonSid == InteractiveLeaseLogonSid,
            L"Interactive lease acquire request was not decoded."))
    {
        return 1;
    }

    std::string unexpectedLeaseField = acquireLease;
    unexpectedLeaseField.insert(unexpectedLeaseField.rfind('}'), ",\"sessionId\":1");
    std::string accountSidLease = acquireLease;
    accountSidLease.replace(accountSidLease.find("S-1-5-5-123-456"),
        std::string("S-1-5-5-123-456").size(),
        "S-1-5-21-1-2-3-1000");
    if (!Expect(!launch_as::broker::ParseInteractiveLeaseRequest(
                    acquireLease, L"00000000-0000-0000-0000-000000000000", leaseRequest),
            L"Interactive lease request accepted a mismatched nonce.") ||
        !Expect(!launch_as::broker::ParseInteractiveLeaseRequest(
                    unexpectedLeaseField, InteractiveLeaseNonce, leaseRequest),
            L"Interactive lease request accepted an unexpected session id.") ||
        !Expect(!launch_as::broker::ParseInteractiveLeaseRequest(
                    accountSidLease, InteractiveLeaseNonce, leaseRequest),
            L"Interactive lease request accepted an account SID instead of a logon SID."))
    {
        return 1;
    }

    const std::string acquiredLease = launch_as::broker::BuildInteractiveLeaseResponse(
        launch_as::broker::InteractiveLeaseOperation::Acquire,
        InteractiveLeaseNonce,
        ERROR_SUCCESS);
    DWORD leaseError = ERROR_INVALID_DATA;
    if (!Expect(acquiredLease == "{\"version\":1,\"operation\":\"acquire\",\"nonce\":"
                                 "\"6f9619ff-8b86-d011-b42d-00c04fc964ff\",\"status\":\"ok\","
                                 "\"win32Error\":0}",
            L"Interactive lease acknowledgement encoding is not stable.") ||
        !Expect(launch_as::broker::ParseInteractiveLeaseResponse(acquiredLease,
                    launch_as::broker::InteractiveLeaseOperation::Acquire,
                    InteractiveLeaseNonce,
                    leaseError) &&
                    leaseError == ERROR_SUCCESS,
            L"Interactive lease acknowledgement was not decoded."))
    {
        return 1;
    }

    const std::string releaseLease =
        launch_as::broker::BuildInteractiveLeaseReleaseRequest(InteractiveLeaseNonce);
    if (!Expect(
            launch_as::broker::ParseInteractiveLeaseRequest(
                releaseLease, InteractiveLeaseNonce, leaseRequest) &&
                leaseRequest.operation == launch_as::broker::InteractiveLeaseOperation::Release &&
                leaseRequest.desktop.empty() && leaseRequest.childLogonSid.empty(),
            L"Interactive lease release request was not decoded."))
    {
        return 1;
    }
    const std::string managementRequest =
        launch_as::broker::BuildManagementRequest(launch_as::broker::RequestOperation::TakeOver,
            L"123e4567-e89b-12d3-a456-426614174000",
            L"account with space",
            true,
            true);
    if (!Expect(launch_as::broker::ParseBrokerRequest(managementRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::TakeOver &&
                    request.profileId == L"account with space" && request.confirmed &&
                    request.force,
            L"Built management request was not accepted by the protocol parser.") ||
        !Expect(launch_as::broker::RequestOperationSuccessReason(
                    launch_as::broker::RequestOperation::TakeOver) == "taken_over" &&
                    launch_as::broker::RequestOperationFailureReason(
                        launch_as::broker::RequestOperation::TakeOver) == "takeover_failed",
            L"Management operation reasons are not centralized."))
    {
        return 1;
    }

    std::string encodedString;
    launch_as::broker::AppendJsonString(
        encodedString, L"quote \" backslash \\ newline\n café \U0001F680");
    if (!Expect(encodedString ==
                    "\"quote \\\" backslash \\\\ newline\\u000A caf\\u00E9 \\uD83D\\uDE80\"",
            L"JSON string encoding is not stable."))
    {
        return 1;
    }
    if (!Expect(!launch_as::IsValidUtf16(std::wstring(1, L'\xD800')),
            L"UTF-16 validation accepted an unpaired surrogate."))
    {
        return 1;
    }

    std::string removedOperation = managementRequest;
    removedOperation.replace(removedOperation.find("takeover"), 8, "rotate");
    if (!Expect(launch_as::broker::ParseBrokerRequest(removedOperation, request) ==
                    launch_as::broker::ParseResult::InvalidRequest,
            L"The removed password-rotation operation was accepted."))
    {
        return 1;
    }

    if (!Expect(launch_as::broker::ParseBrokerRequest(InteractiveRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::InteractiveLaunch &&
                    request.interactive.leasePipe == L"\\\\.\\pipe\\launch-as-interactive-"
                                                     L"123e4567e89b12d3a456426614174000" &&
                    request.interactive.nonce == InteractiveLeaseNonce,
            L"A valid private interactive broker request was rejected."))
    {
        return 1;
    }

    std::string clientSuppliedIdentity(InteractiveRequest);
    clientSuppliedIdentity.insert(clientSuppliedIdentity.find("\"leasePipe\""), "\"sessionId\":1,");
    if (!Expect(launch_as::broker::ParseBrokerRequest(clientSuppliedIdentity, request) ==
                    launch_as::broker::ParseResult::InvalidRequest,
            L"An interactive request was allowed to supply caller identity."))
    {
        return 1;
    }

    std::string unknownMode(ValidRequest);
    unknownMode.replace(unknownMode.find("\"console\""), 9, "\"unknown\"");
    if (!Expect(launch_as::broker::ParseBrokerRequest(unknownMode, request) ==
                    launch_as::broker::ParseResult::InvalidRequest,
            L"Unknown mode was not rejected as an invalid request."))
    {
        return 1;
    }

    std::string duplicate(ValidRequest);
    duplicate.insert(duplicate.rfind('}'), ",\"mode\":\"console\"");
    if (!Expect(launch_as::broker::ParseBrokerRequest(duplicate, request) !=
                    launch_as::broker::ParseResult::Success,
            L"Duplicate request field was accepted."))
    {
        return 1;
    }

    std::string invalidThenValidMode(ValidRequest);
    const std::size_t modeOffset = invalidThenValidMode.find("\"console\"");
    invalidThenValidMode.replace(modeOffset, 9, "\"invalid\"");
    invalidThenValidMode.insert(invalidThenValidMode.rfind('}'), ",\"mode\":\"console\"");
    if (!Expect(launch_as::broker::ParseBrokerRequest(invalidThenValidMode, request) !=
                    launch_as::broker::ParseResult::Success,
            L"Invalid duplicate request field was accepted."))
    {
        return 1;
    }

    const std::string response = launch_as::broker::BuildErrorResponse(
        L"123e4567-e89b-12d3-a456-426614174000", "not_configured", ERROR_NOT_READY);
    if (!Expect(response ==
                    "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                    "\"status\":\"error\",\"reasonCode\":\"not_configured\",\"win32Error\":21}",
            L"Error response is not stable."))
    {
        return 1;
    }
    DWORD parsedError = ERROR_SUCCESS;
    if (!Expect(launch_as::broker::ParseErrorResponse(
                    response, L"123e4567-e89b-12d3-a456-426614174000", parsedError) &&
                    parsedError == ERROR_NOT_READY,
            L"Error response did not preserve its Win32 error."))
    {
        return 1;
    }
    if (!Expect(launch_as::broker::BuildSuccessResponse(
                    L"123e4567-e89b-12d3-a456-426614174000", "registered") ==
                    "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                    "\"status\":\"ok\",\"reasonCode\":\"registered\",\"win32Error\":0}",
            L"Success response is not stable."))
    {
        return 1;
    }
    const std::array accounts {std::wstring(L"LaunchAsUser"), std::wstring(L"AnotherAccount")};
    const std::string listResponse =
        launch_as::broker::BuildListResponse(L"123e4567-e89b-12d3-a456-426614174000", accounts);
    std::vector<std::wstring> listedAccounts;
    if (!Expect(listResponse ==
                    "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                    "\"status\":\"ok\",\"accounts\":[\"LaunchAsUser\",\"AnotherAccount\"],"
                    "\"reasonCode\":\"listed\","
                    "\"win32Error\":0}",
            L"List response is not stable.") ||
        !Expect(launch_as::broker::ParseListResponse(
                    listResponse, L"123e4567-e89b-12d3-a456-426614174000", listedAccounts) &&
                    listedAccounts == std::vector<std::wstring>(accounts.begin(), accounts.end()),
            L"List response was not decoded."))
    {
        return 1;
    }
    const std::string launchResponse =
        launch_as::broker::BuildLaunchSuccessResponse(L"123e4567-e89b-12d3-a456-426614174000", 456);
    const std::string unexpectedLaunchResponse =
        "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
        "\"status\":\"ok\",\"processId\":456,\"reasonCode\":\"launched\","
        "\"win32Error\":0,\"unexpected\":true}";
    DWORD processId = 0;
    const std::string exitResponse =
        launch_as::broker::BuildLaunchExitResponse(L"123e4567-e89b-12d3-a456-426614174000", 37);
    DWORD exitCode = 0;
    const std::string hostFailureResponse = launch_as::broker::BuildLaunchHostFailureResponse(
        L"123e4567-e89b-12d3-a456-426614174000", 1, L"The target could not be started.");
    DWORD hostExitCode = 0;
    std::wstring diagnostics;
    return Expect(launchResponse ==
                      "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                      "\"status\":\"ok\",\"processId\":456,\"reasonCode\":\"launched\","
                      "\"win32Error\":0}",
               L"Launch success response is not stable.") &&
                   Expect(launch_as::broker::ParseLaunchSuccessResponse(
                              launchResponse, L"123e4567-e89b-12d3-a456-426614174000", processId) &&
                              processId == 456,
                       L"Launch success response was not decoded.") &&
                   Expect(!launch_as::broker::ParseLaunchSuccessResponse(unexpectedLaunchResponse,
                              L"123e4567-e89b-12d3-a456-426614174000",
                              processId) &&
                              processId == 0,
                       L"Launch success response accepted an unexpected field.") &&
                   Expect(
                       exitResponse ==
                           "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                           "\"status\":\"ok\",\"exitCode\":37,\"reasonCode\":\"exited\","
                           "\"win32Error\":0}",
                       L"Launch exit response is not stable.") &&
                   Expect(launch_as::broker::ParseLaunchExitResponse(
                              exitResponse, L"123e4567-e89b-12d3-a456-426614174000", exitCode) &&
                              exitCode == 37,
                       L"Launch exit response was not decoded.") &&
                   Expect(
                       hostFailureResponse ==
                           "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                           "\"status\":\"error\",\"hostExitCode\":1,"
                           "\"diagnostic\":\"The target could not be started.\","
                           "\"reasonCode\":\"host_failed\",\"win32Error\":31}",
                       L"Launch host-failure response is not stable.") &&
                   Expect(launch_as::broker::ParseLaunchHostFailureResponse(hostFailureResponse,
                              L"123e4567-e89b-12d3-a456-426614174000",
                              hostExitCode,
                              diagnostics) &&
                              hostExitCode == 1 &&
                              diagnostics == L"The target could not be started.",
                       L"Launch host-failure response was not decoded.")
               ? 0
               : 1;
}
