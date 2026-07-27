// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "LauncherOptions.h"

#include <Windows.h>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace launch_as
{

[[nodiscard]] bool IsPseudoConsoleHostInvocation(std::span<wchar_t*> arguments) noexcept;
[[nodiscard]] ExitCode RunPseudoConsoleHost(std::span<wchar_t*> arguments);
[[nodiscard]] std::filesystem::path GetLauncherExecutablePath(std::wstring& error);
[[nodiscard]] std::vector<std::wstring> BuildPseudoConsoleHostArguments(
    const Options& options, COORD terminalSize, bool inheritCursor);

} // namespace launch_as
