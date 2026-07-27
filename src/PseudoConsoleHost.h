// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#pragma once

#include "LauncherOptions.h"

#include <Windows.h>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace sandbox_launcher
{

[[nodiscard]] bool IsPseudoConsoleHostInvocation(std::span<wchar_t*> arguments) noexcept;
[[nodiscard]] ExitCode RunPseudoConsoleHost(std::span<wchar_t*> arguments);
[[nodiscard]] std::filesystem::path GetLauncherExecutablePath(std::wstring& error);
[[nodiscard]] std::vector<std::wstring> BuildPseudoConsoleHostArguments(
    const Options& options, COORD terminalSize, bool inheritCursor);

} // namespace sandbox_launcher
