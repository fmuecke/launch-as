// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <string_view>

namespace launch_as::broker
{

[[nodiscard]] DWORD InstallBrokerService();
[[nodiscard]] DWORD UninstallBrokerService();
[[nodiscard]] DWORD InstallDemandStartBrokerService(
    std::wstring_view serviceName, std::wstring_view executablePath);
[[nodiscard]] DWORD UninstallDemandStartBrokerService(std::wstring_view serviceName);

} // namespace launch_as::broker
