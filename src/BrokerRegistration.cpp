// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerRegistration.h"

#include "BrokerAccountProvisioner.h"
#include "BrokerPassword.h"

namespace launch_as::broker
{

RegistrationService::RegistrationService(
    std::wstring_view accountName, std::wstring_view credentialDirectory)
    : accountName_(accountName), store_(credentialDirectory)
{
}

DWORD RegistrationService::Register()
{
    SecurePassword password;
    const DWORD passwordError = GenerateBrokerPassword(password);
    if (passwordError != ERROR_SUCCESS)
    {
        return passwordError;
    }
    const DWORD accountError = ProvisionStandardLocalAccount(accountName_, password);
    if (accountError != ERROR_SUCCESS)
    {
        return accountError;
    }
    const DWORD storeError = store_.Store(L"agent-sandbox", password.characters());
    password.Clear();
    return storeError;
}

} // namespace launch_as::broker
