// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProtocol.h"

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
  "profileId": "agent-sandbox",
  "mode": "console",
  "arguments": ["--resume", "caf\u00e9", "emoji \uD83D\uDE80"],
  "workingDirectory": "C:\\dev\\AgentSandbox\\repo",
  "console": {
    "pipeIn": "\\\\.\\pipe\\launch-as-123-in",
    "pipeOut": "\\\\.\\pipe\\launch-as-123-out",
    "pipeResize": "\\\\.\\pipe\\launch-as-123-resize",
    "cols": 120,
    "rows": 30
  }
})json";

constexpr char ListRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "list"
})json";

constexpr char UnenrollRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "unenroll",
  "profileId": "agent-sandbox",
  "confirmed": true
})json";

constexpr char UnenrollAllRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "unenroll-all",
  "confirmed": true
})json";

constexpr char RotateRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "rotate",
  "profileId": "agent-sandbox",
  "confirmed": true
})json";

constexpr char TestRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "test",
  "profileId": "agent-sandbox"
})json";

constexpr char UnconfirmedEnrollRequest[] = R"json({
  "version": 1,
  "requestId": "123e4567-e89b-12d3-a456-426614174000",
  "operation": "enroll",
  "profileId": "sandbox"
})json";

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

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
        !Expect(request.profileId == L"agent-sandbox", L"Profile id was not decoded."))
    {
        return 1;
    }

    if (!Expect(launch_as::broker::ParseBrokerRequest(ListRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::List,
            L"List request was rejected.") ||
        !Expect(launch_as::broker::ParseBrokerRequest(UnenrollRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::Unenroll,
            L"Unenroll request was rejected."))
    {
        return 1;
    }
    if (!Expect(launch_as::broker::ParseBrokerRequest(UnenrollAllRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::UnenrollAll,
            L"Unenroll-all request was rejected."))
    {
        return 1;
    }
    if (!Expect(launch_as::broker::ParseBrokerRequest(RotateRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::Rotate,
            L"Rotate request was rejected.") ||
        !Expect(launch_as::broker::ParseBrokerRequest(TestRequest, request) ==
                        launch_as::broker::ParseResult::Success &&
                    request.operation == launch_as::broker::RequestOperation::Test,
            L"Credential test request was rejected."))
    {
        return 1;
    }
    if (!Expect(launch_as::broker::ParseBrokerRequest(UnconfirmedEnrollRequest, request) ==
                    launch_as::broker::ParseResult::InvalidRequest,
            L"Unconfirmed registration request was accepted."))
    {
        return 1;
    }

    std::string wrongMode(ValidRequest);
    wrongMode.replace(wrongMode.find("\"console\""), 9, "\"interactive\"");
    if (!Expect(launch_as::broker::ParseBrokerRequest(wrongMode, request) ==
                    launch_as::broker::ParseResult::InvalidRequest,
            L"Interactive mode was accepted by the console protocol."))
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
    const std::array accounts {std::wstring(L"AgentSandbox"), std::wstring(L"AnotherAccount")};
    const std::string listResponse =
        launch_as::broker::BuildListResponse(L"123e4567-e89b-12d3-a456-426614174000", accounts);
    std::vector<std::wstring> listedAccounts;
    if (!Expect(listResponse ==
                    "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                    "\"status\":\"ok\",\"accounts\":[\"AgentSandbox\",\"AnotherAccount\"],"
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
    DWORD processId = 0;
    const std::string exitResponse =
        launch_as::broker::BuildLaunchExitResponse(L"123e4567-e89b-12d3-a456-426614174000", 37);
    DWORD exitCode = 0;
    return Expect(launchResponse ==
                      "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                      "\"status\":\"ok\",\"processId\":456,\"reasonCode\":\"launched\","
                      "\"win32Error\":0}",
               L"Launch success response is not stable.") &&
                   Expect(launch_as::broker::ParseLaunchSuccessResponse(
                              launchResponse, L"123e4567-e89b-12d3-a456-426614174000", processId) &&
                              processId == 456,
                       L"Launch success response was not decoded.") &&
                   Expect(
                       exitResponse ==
                           "{\"version\":1,\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\","
                           "\"status\":\"ok\",\"exitCode\":37,\"reasonCode\":\"exited\","
                           "\"win32Error\":0}",
                       L"Launch exit response is not stable.") &&
                   Expect(launch_as::broker::ParseLaunchExitResponse(
                              exitResponse, L"123e4567-e89b-12d3-a456-426614174000", exitCode) &&
                              exitCode == 37,
                       L"Launch exit response was not decoded.")
               ? 0
               : 1;
}
