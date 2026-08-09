// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

inline constexpr std::wstring_view ControlPipeName = L"\\\\.\\pipe\\launch-as-broker.v1";
inline constexpr std::size_t MaximumMessageBytes = 64 * 1024;
inline constexpr std::size_t MaximumArguments = 64;

struct ConsoleRequest
{
    std::wstring pipeIn;
    std::wstring pipeOut;
    std::wstring pipeResize;
    SHORT columns = 0;
    SHORT rows = 0;
};

enum class RequestOperation
{
    ConsoleLaunch,
    Enroll,
    Rotate,
    Test,
    List,
    Unenroll,
    UnenrollAll
};

struct BrokerRequest
{
    RequestOperation operation = RequestOperation::ConsoleLaunch;
    std::wstring requestId;
    std::wstring profileId;
    bool confirmed = false;
    std::vector<std::wstring> arguments;
    std::wstring workingDirectory;
    ConsoleRequest console;
};

enum class ParseResult
{
    Success,
    InvalidJson,
    InvalidRequest
};

[[nodiscard]] ParseResult ParseBrokerRequest(std::string_view message, BrokerRequest& request);
[[nodiscard]] std::string BuildErrorResponse(
    std::wstring_view requestId, std::string_view reasonCode, DWORD win32Error);
[[nodiscard]] std::string BuildSuccessResponse(
    std::wstring_view requestId, std::string_view reasonCode);
[[nodiscard]] std::string BuildListResponse(
    std::wstring_view requestId, std::span<const std::wstring> accounts);
[[nodiscard]] bool ParseListResponse(
    std::string_view response, std::wstring_view requestId, std::vector<std::wstring>& accounts);
[[nodiscard]] bool ParseErrorResponse(
    std::string_view response, std::wstring_view requestId, DWORD& win32Error);
[[nodiscard]] std::string BuildLaunchSuccessResponse(std::wstring_view requestId, DWORD processId);
[[nodiscard]] bool ParseLaunchSuccessResponse(
    std::string_view response, std::wstring_view requestId, DWORD& processId);
[[nodiscard]] std::string BuildLaunchExitResponse(std::wstring_view requestId, DWORD exitCode);
[[nodiscard]] bool ParseLaunchExitResponse(
    std::string_view response, std::wstring_view requestId, DWORD& exitCode);

} // namespace launch_as::broker
