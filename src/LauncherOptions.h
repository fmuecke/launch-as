// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace sandbox_launcher
{

using ExitCode = std::uint32_t;

inline constexpr ExitCode ExitSuccess = 0;
inline constexpr ExitCode ExitFailure = 1;
inline constexpr ExitCode ExitUsage = 2;
inline constexpr ExitCode ExitCredentialMissing = 3;

enum class Command
{
    Register,
    Run,
    Status,
    Forget
};

struct Options
{
    Command command;
    std::wstring username;
    std::wstring testCredentialTag;
    bool testCredentialTagSpecified = false;
    std::filesystem::path workingDirectory;
    std::filesystem::path executablePath;
    std::vector<std::wstring> processArguments;
    bool newConsole = false;
};

void PrintUsage();

[[nodiscard]] std::optional<Options> ParseOptions(std::span<wchar_t*> arguments);

} // namespace sandbox_launcher
