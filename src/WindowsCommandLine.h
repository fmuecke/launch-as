// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#pragma once

#include <span>
#include <string>
#include <string_view>

namespace sandbox_launcher
{

[[nodiscard]] std::wstring QuoteWindowsCommandLineArgument(std::wstring_view argument);

[[nodiscard]] std::wstring BuildWindowsCommandLine(std::wstring_view executable,
                                                   std::span<const std::wstring> arguments);

} // namespace sandbox_launcher
