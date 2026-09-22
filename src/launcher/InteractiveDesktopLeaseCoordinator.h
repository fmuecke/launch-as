// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <string_view>

namespace launch_as
{

[[nodiscard]] DWORD CreateInteractiveDesktopLeasePipe(std::wstring_view pipeName, HANDLE& pipe);
[[nodiscard]] DWORD ServeInteractiveDesktopLease(
    HANDLE connectedPipe, std::wstring_view expectedNonce);

} // namespace launch_as
