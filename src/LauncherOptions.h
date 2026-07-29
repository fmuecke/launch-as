// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace launch_as
{

using ExitCode = std::uint32_t;

inline constexpr ExitCode ExitSuccess = 0;              // ERROR_SUCCESS
inline constexpr ExitCode ExitFailure = 1;              // ERROR_INVALID_FUNCTION
inline constexpr ExitCode ExitUsage = 87;               // ERROR_INVALID_PARAMETER
inline constexpr ExitCode ExitCredentialMissing = 1326; // ERROR_LOGON_FAILURE
inline constexpr ExitCode ExitCancelled = 1223;         // ERROR_CANCELLED

enum class Command
{
    Register,
    Run,
    Status,
    Forget
};

enum class CredentialMode
{
    Auto,
    Stored,
    Prompt
};

struct Options
{
    Command command;
    std::wstring username;
    std::wstring testCredentialTag;
    bool testCredentialTagSpecified = false;
    bool passwordFromStdin = false;
    CredentialMode credentialMode = CredentialMode::Auto;
    bool credentialModeSpecified = false;
    std::filesystem::path workingDirectory;
    std::filesystem::path executablePath;
    std::vector<std::wstring> processArguments;
    bool terminal = false;
};

void PrintUsage();

[[nodiscard]] std::optional<Options> ParseOptions(std::span<wchar_t*> arguments);

} // namespace launch_as
