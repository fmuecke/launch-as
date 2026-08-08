// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerRegistration.h"

#include "BrokerAccountProvisioner.h"
#include "BrokerPassword.h"

#include <Lm.h>
#include <algorithm>
#include <vector>

namespace launch_as::broker
{

RegistrationService::RegistrationService(std::wstring_view credentialDirectory)
    : store_(credentialDirectory)
{
}

DWORD RegistrationService::Register(std::wstring_view accountName)
{
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }
    SecurePassword password;
    const DWORD passwordError = GenerateBrokerPassword(password);
    if (passwordError != ERROR_SUCCESS)
    {
        return passwordError;
    }
    const DWORD accountError = ProvisionStandardLocalAccount(accountName, password);
    if (accountError != ERROR_SUCCESS)
    {
        return accountError;
    }
    const DWORD storeError = store_.Store(accountName, password.characters());
    password.Clear();
    return storeError;
}

DWORD RegistrationService::Drop(std::wstring_view accountName)
{
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD credentialError = store_.Remove(accountName);
    if (credentialError != ERROR_SUCCESS)
    {
        return credentialError;
    }
    const std::wstring name(accountName);
    LPBYTE rawAccount = nullptr;
    const NET_API_STATUS readStatus = NetUserGetInfo(nullptr, name.c_str(), 4, &rawAccount);
    if (readStatus == NERR_UserNotFound)
    {
        return ERROR_SUCCESS;
    }
    if (readStatus != NERR_Success || rawAccount == nullptr)
    {
        if (rawAccount != nullptr)
        {
            NetApiBufferFree(rawAccount);
        }
        return readStatus == NERR_Success ? ERROR_INVALID_DATA : readStatus;
    }
    const auto* account = reinterpret_cast<const USER_INFO_4*>(rawAccount);
    USER_INFO_1008 flags {};
    flags.usri1008_flags = account->usri4_flags | UF_ACCOUNTDISABLE;
    NetApiBufferFree(rawAccount);
    return NetUserSetInfo(nullptr, name.c_str(), 1008, reinterpret_cast<LPBYTE>(&flags), nullptr);
}

DWORD RegistrationService::DropAll()
{
    std::vector<std::wstring> accounts;
    const DWORD listError = store_.List(accounts);
    if (listError != ERROR_SUCCESS)
    {
        return listError;
    }
    DWORD firstDropError = ERROR_SUCCESS;
    for (const std::wstring& account : accounts)
    {
        const DWORD dropError = Drop(account);
        if (dropError != ERROR_SUCCESS && firstDropError == ERROR_SUCCESS)
        {
            firstDropError = dropError;
        }
    }
    return firstDropError;
}

DWORD RegistrationService::List(std::vector<std::wstring>& accountNames) const
{
    const DWORD listError = store_.List(accountNames);
    if (listError != ERROR_SUCCESS)
    {
        return listError;
    }
    accountNames.erase(std::remove_if(accountNames.begin(),
                           accountNames.end(),
                           [](const std::wstring& accountName)
                           {
                               LPBYTE account = nullptr;
                               const NET_API_STATUS status =
                                   NetUserGetInfo(nullptr, accountName.c_str(), 0, &account);
                               if (account != nullptr)
                               {
                                   NetApiBufferFree(account);
                               }
                               return status != NERR_Success;
                           }),
        accountNames.end());
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
