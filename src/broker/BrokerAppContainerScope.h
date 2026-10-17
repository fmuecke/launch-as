// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "AppContainerOptions.h"
#include "Win32Support.h"

namespace launch_as::broker
{

// Create the profile as the account. Authorize and pin each root as the account, then
// grant inheritable package Modify access using a broker-opened root handle. Windows
// propagates to existing descendants while impersonating the account, on every launch.
// Root/ancestor reparse points are rejected. ACL changes persist; labels are unchanged.
[[nodiscard]] DWORD PrepareBrokerAppContainerScope(HANDLE token,
    const std::wstring& profileDirectory, const std::wstring& workingDirectory,
    const AppContainerOptions& options, std::wstring& context);

#ifdef LAUNCH_AS_TESTING
[[nodiscard]] DWORD PrepareBrokerAppContainerRootForTesting(
    HANDLE token, const std::wstring& directory, PSID sid, std::wstring& context);
#endif

} // namespace launch_as::broker
