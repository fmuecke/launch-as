// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerApplication.h"

#include <Windows.h>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

[[nodiscard]] DWORD BuildBrokerControlPipeDacl(
    const std::vector<BYTE>& authorizedCallerSid, std::wstring& dacl);
[[nodiscard]] DWORD RunBrokerControlPipeListener(
    HANDLE stopEvent, BrokerApplication& application, std::wstring_view controlPipeDacl);

} // namespace launch_as::broker
