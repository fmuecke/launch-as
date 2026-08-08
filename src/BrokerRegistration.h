// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerCredentialStore.h"

#include <Windows.h>
#include <string>
#include <string_view>

namespace launch_as::broker
{

class RegistrationService final
{
  public:
    RegistrationService(std::wstring_view accountName, std::wstring_view credentialDirectory);

    [[nodiscard]] DWORD Register();

  private:
    std::wstring accountName_;
    CredentialStore store_;
};

} // namespace launch_as::broker
