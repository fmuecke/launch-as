// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>

namespace launch_as
{

// The broker supplies stdout to the internal console host as a private binary
// channel.  A successful host writes this report after its ConPTY child exits.
inline constexpr DWORD PseudoConsoleHostExitReportMagic = 0x4C415348;

struct PseudoConsoleHostExitReport
{
    DWORD magic = PseudoConsoleHostExitReportMagic;
    DWORD childExitCode = 0;
};

} // namespace launch_as
