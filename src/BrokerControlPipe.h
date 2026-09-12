// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>

namespace launch_as::broker
{

// FILE_GENERIC_READ permits receiving broker responses. FILE_WRITE_DATA permits sending a
// request without FILE_APPEND_DATA, which is FILE_CREATE_PIPE_INSTANCE for named pipes.
inline constexpr DWORD ControlPipeClientAccess = FILE_GENERIC_READ | FILE_WRITE_DATA;
static_assert((ControlPipeClientAccess & FILE_CREATE_PIPE_INSTANCE) == 0);

[[nodiscard]] DWORD OpenBrokerControlPipe(HANDLE& pipe);

} // namespace launch_as::broker
