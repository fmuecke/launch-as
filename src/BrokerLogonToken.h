// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerPassword.h"

#include <Windows.h>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

class BrokerLogonToken final
{
  public:
    BrokerLogonToken() = default;
    ~BrokerLogonToken();

    BrokerLogonToken(const BrokerLogonToken&) = delete;
    BrokerLogonToken& operator=(const BrokerLogonToken&) = delete;

    [[nodiscard]] HANDLE get() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept;
    void Reset(HANDLE token = nullptr) noexcept;

  private:
    HANDLE token_ = nullptr;
};

[[nodiscard]] DWORD GetBrokerAccountSid(std::wstring_view accountName, std::vector<BYTE>& sid);
[[nodiscard]] DWORD LogOnBrokerAccount(
    std::wstring_view accountName, const SecurePassword& password, BrokerLogonToken& token);

} // namespace launch_as::broker
