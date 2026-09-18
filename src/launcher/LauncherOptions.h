// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "ExitCodes.h"

#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace launch_as
{

struct Options
{
    std::wstring username;
    std::filesystem::path workingDirectory;
    std::filesystem::path executablePath;
    std::vector<std::wstring> processArguments;
};

void PrintUsage();

[[nodiscard]] std::optional<Options> ParseOptions(std::span<wchar_t*> arguments);

} // namespace launch_as
