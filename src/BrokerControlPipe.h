// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>

namespace launch_as::broker
{

[[nodiscard]] DWORD OpenBrokerControlPipe(HANDLE& pipe);

} // namespace launch_as::broker
