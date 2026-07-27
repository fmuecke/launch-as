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

inline constexpr ExitCode ExitSuccess = 0;
inline constexpr ExitCode ExitFailure = 1;
inline constexpr ExitCode ExitUsage = 2;
inline constexpr ExitCode ExitCredentialMissing = 3;
inline constexpr ExitCode ExitCancelled = 4;

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

enum class LaunchMode
{
    Default,
    NewConsole,
    Terminal
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
    LaunchMode launchMode = LaunchMode::Default;
    bool launchModeSpecified = false;
};

void PrintUsage();

[[nodiscard]] std::optional<Options> ParseOptions(std::span<wchar_t*> arguments);

} // namespace launch_as
