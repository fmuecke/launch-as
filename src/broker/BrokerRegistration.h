// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerEnrollmentStore.h"
#include "BrokerPassword.h"

#include <Windows.h>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

class RegistrationService final
{
  public:
    explicit RegistrationService(std::wstring_view enrollmentDirectory);

    [[nodiscard]] DWORD Create(std::wstring_view accountName);
    [[nodiscard]] DWORD TakeOver(std::wstring_view accountName, bool allowEnable);
    [[nodiscard]] DWORD ResetPassword(
        std::wstring_view accountName, const SecurePassword& password) const;
    [[nodiscard]] DWORD Forget(std::wstring_view accountName);
    [[nodiscard]] DWORD Delete(std::wstring_view accountName);
    [[nodiscard]] DWORD List(std::vector<std::wstring>& accountNames) const;

  private:
    EnrollmentStore enrollments_;
};

} // namespace launch_as::broker
