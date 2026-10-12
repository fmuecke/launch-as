// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "Win32Support.h"

#include <Windows.h>
#include <string_view>

namespace launch_as::broker
{

// Preparation runs under the account's medium token, never the broker's SYSTEM identity.
// Labels persist. Reparse points and multiply-linked files are not relabelled.
// Depth/object limits return ERROR_NOT_ENOUGH_QUOTA; the shared deadline returns ERROR_TIMEOUT.
[[nodiscard]] DWORD PrepareBrokerWriteScope(
    HANDLE token, std::wstring_view profileDirectory, std::wstring_view workingDirectory);
[[nodiscard]] DWORD CreateBrokerLaunchToken(
    HANDLE token, bool restrictWrites, bool lowIntegrity, UniqueHandle& launchToken);

#ifdef LAUNCH_AS_TESTING
[[nodiscard]] DWORD PrepareBrokerWriteScopeWithLimitsForTesting(HANDLE token,
    std::wstring_view profileDirectory, std::wstring_view workingDirectory, DWORD maximumObjects,
    DWORD timeoutMilliseconds);
void SetBrokerWriteScopeObserverForTesting(void (*observer)(HANDLE, bool labelled)) noexcept;
void SetBrokerWriteScopeChildObserverForTesting(
    void (*observer)(HANDLE parent, std::wstring_view name)) noexcept;
#endif

} // namespace launch_as::broker
