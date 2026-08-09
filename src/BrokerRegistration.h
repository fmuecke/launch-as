// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerCredentialStore.h"

#include <Windows.h>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

class RegistrationService final
{
  public:
    explicit RegistrationService(std::wstring_view credentialDirectory);

    [[nodiscard]] DWORD Enroll(std::wstring_view accountName);
    [[nodiscard]] DWORD Rotate(std::wstring_view accountName);
    [[nodiscard]] DWORD Test(std::wstring_view accountName) const;
    [[nodiscard]] DWORD Unenroll(std::wstring_view accountName);
    [[nodiscard]] DWORD UnenrollAll();
    [[nodiscard]] DWORD List(std::vector<std::wstring>& accountNames) const;

  private:
    CredentialStore store_;
};

} // namespace launch_as::broker
