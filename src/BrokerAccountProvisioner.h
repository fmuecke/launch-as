// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerCredentialStore.h"

#include <Windows.h>
#include <string_view>

namespace launch_as::broker
{

[[nodiscard]] bool IsValidBrokerAccountName(std::wstring_view accountName) noexcept;
[[nodiscard]] DWORD ValidateBrokerAccountForRegistration(std::wstring_view accountName);
[[nodiscard]] DWORD ProvisionStandardLocalAccount(
    std::wstring_view accountName, const SecurePassword& password);

} // namespace launch_as::broker
