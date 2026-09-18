// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace launch_as
{

struct PseudoConsoleHostInvocation
{
    COORD terminalSize {};
    bool inheritCursor = false;
    std::filesystem::path executable;
    std::vector<std::wstring> processArguments;
    std::wstring pipeIn;
    std::wstring pipeOut;
    std::wstring pipeResize;
};

[[nodiscard]] bool IsPseudoConsoleHostInvocation(std::span<wchar_t*> arguments) noexcept;
[[nodiscard]] bool ParsePseudoConsoleHostInvocation(
    std::span<wchar_t*> arguments, PseudoConsoleHostInvocation& invocation);

} // namespace launch_as
