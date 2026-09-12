// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <string>
#include <string_view>

namespace launch_as::broker
{

[[nodiscard]] DWORD CreateSecureDirectory(std::wstring_view path);
[[nodiscard]] DWORD GetBrokerDataDirectoryPath(std::wstring& directory);
[[nodiscard]] DWORD GetBrokerDataDirectory(std::wstring& directory);
[[nodiscard]] DWORD GetBrokerEnrollmentDirectory(std::wstring& directory);

} // namespace launch_as::broker
