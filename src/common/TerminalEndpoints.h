// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <string>

namespace launch_as
{

struct TerminalPipeNames
{
    std::wstring input;
    std::wstring output;
    std::wstring resize;
};

} // namespace launch_as
