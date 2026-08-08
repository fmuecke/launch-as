// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

inline constexpr std::wstring_view AuthorizedCallerPolicyFileName = L"authorized-caller.sid";

[[nodiscard]] DWORD StoreAuthorizedCallerSid(std::wstring_view path, PSID callerSid);
[[nodiscard]] DWORD LoadAuthorizedCallerSid(std::wstring_view path, std::vector<BYTE>& callerSid);
[[nodiscard]] bool IsAuthorizedCaller(
    const std::vector<BYTE>& authorizedCallerSid, const std::vector<BYTE>& callerSid);
[[nodiscard]] std::wstring GetAuthorizedCallerPolicyPath(std::wstring_view dataDirectory);

} // namespace launch_as::broker
