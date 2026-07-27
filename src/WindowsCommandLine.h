// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <span>
#include <string>
#include <string_view>

namespace launch_as
{

[[nodiscard]] std::wstring QuoteWindowsCommandLineArgument(std::wstring_view argument);

[[nodiscard]] std::wstring BuildWindowsCommandLine(
    std::wstring_view executable, std::span<const std::wstring> arguments);

} // namespace launch_as
