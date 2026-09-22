// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <string>
#include <string_view>

namespace launch_as::broker
{

class InteractiveDesktopLeaseConnection final
{
  public:
    InteractiveDesktopLeaseConnection() = default;
    ~InteractiveDesktopLeaseConnection();

    InteractiveDesktopLeaseConnection(const InteractiveDesktopLeaseConnection&) = delete;
    InteractiveDesktopLeaseConnection& operator=(const InteractiveDesktopLeaseConnection&) = delete;

    [[nodiscard]] explicit operator bool() const noexcept;
    void Reset() noexcept;

  private:
    HANDLE pipe_ = nullptr;
    std::wstring nonce_;

    friend DWORD AcquireInteractiveDesktopLease(std::wstring_view pipeName, std::wstring_view nonce,
        PSID childLogonSid, InteractiveDesktopLeaseConnection& connection);
    friend DWORD ReleaseInteractiveDesktopLease(InteractiveDesktopLeaseConnection& connection);
};

[[nodiscard]] DWORD AcquireInteractiveDesktopLease(std::wstring_view pipeName,
    std::wstring_view nonce, PSID childLogonSid, InteractiveDesktopLeaseConnection& connection);
[[nodiscard]] DWORD ReleaseInteractiveDesktopLease(InteractiveDesktopLeaseConnection& connection);

} // namespace launch_as::broker
