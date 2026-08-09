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

    [[nodiscard]] DWORD Enroll(std::wstring_view accountName);
    [[nodiscard]] DWORD ResetPassword(
        std::wstring_view accountName, const SecurePassword& password) const;
    [[nodiscard]] DWORD Unenroll(std::wstring_view accountName);
    [[nodiscard]] DWORD UnenrollAll();
    [[nodiscard]] DWORD List(std::vector<std::wstring>& accountNames) const;

  private:
    EnrollmentStore enrollments_;
};

} // namespace launch_as::broker
