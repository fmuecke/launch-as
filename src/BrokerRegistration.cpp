// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerRegistration.h"

#include "BrokerAccountProvisioner.h"
#include "BrokerLogonToken.h"
#include "BrokerPassword.h"

#include <Lm.h>
#include <algorithm>
#include <vector>

namespace launch_as::broker
{

RegistrationService::RegistrationService(std::wstring_view enrollmentDirectory)
    : enrollments_(enrollmentDirectory)
{
}

DWORD RegistrationService::Enroll(std::wstring_view accountName)
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
    password.Clear();
    if (accountError != ERROR_SUCCESS)
    {
        return accountError;
    }
    std::vector<BYTE> accountSid;
    const DWORD sidError = GetBrokerAccountSid(accountName, accountSid);
    if (sidError != ERROR_SUCCESS)
    {
        return sidError;
    }
    return enrollments_.Store(accountName, accountSid);
}

DWORD RegistrationService::ResetPassword(
    std::wstring_view accountName, const SecurePassword& password) const
{
    if (!IsValidBrokerAccountName(accountName) || password.characters().empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    std::vector<BYTE> enrolledSid;
    const DWORD enrollmentError = enrollments_.Load(accountName, enrolledSid);
    if (enrollmentError != ERROR_SUCCESS)
    {
        return enrollmentError;
    }
    std::vector<BYTE> currentSid;
    const DWORD sidError = GetBrokerAccountSid(accountName, currentSid);
    if (sidError != ERROR_SUCCESS)
    {
        return sidError;
    }
    if (EqualSid(enrolledSid.data(), currentSid.data()) == FALSE)
    {
        return ERROR_ACCESS_DENIED;
    }
    const std::wstring name(accountName);
    USER_INFO_1003 replacementPassword {};
    replacementPassword.usri1003_password = const_cast<wchar_t*>(password.c_str());
    return NetUserSetInfo(
        nullptr, name.c_str(), 1003, reinterpret_cast<LPBYTE>(&replacementPassword), nullptr);
}

DWORD RegistrationService::Unenroll(std::wstring_view accountName)
{
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }
    std::vector<BYTE> enrolledSid;
    const DWORD enrollmentError = enrollments_.Load(accountName, enrolledSid);
    if (enrollmentError != ERROR_SUCCESS)
    {
        return enrollmentError;
    }
    const std::wstring name(accountName);
    LPBYTE rawAccount = nullptr;
    const NET_API_STATUS readStatus = NetUserGetInfo(nullptr, name.c_str(), 4, &rawAccount);
    if (readStatus == NERR_UserNotFound)
    {
        return enrollments_.Remove(accountName);
    }
    if (readStatus != NERR_Success || rawAccount == nullptr)
    {
        if (rawAccount != nullptr)
        {
            NetApiBufferFree(rawAccount);
        }
        return readStatus == NERR_Success ? ERROR_INVALID_DATA : readStatus;
    }
    std::vector<BYTE> currentSid;
    const DWORD sidError = GetBrokerAccountSid(accountName, currentSid);
    const auto* account = reinterpret_cast<const USER_INFO_4*>(rawAccount);
    USER_INFO_1008 flags {};
    flags.usri1008_flags = account->usri4_flags | UF_ACCOUNTDISABLE;
    NetApiBufferFree(rawAccount);
    if (sidError != ERROR_SUCCESS)
    {
        return sidError;
    }
    if (EqualSid(enrolledSid.data(), currentSid.data()) == FALSE)
    {
        return ERROR_ACCESS_DENIED;
    }
    const NET_API_STATUS disableStatus =
        NetUserSetInfo(nullptr, name.c_str(), 1008, reinterpret_cast<LPBYTE>(&flags), nullptr);
    return disableStatus == NERR_Success ? enrollments_.Remove(accountName) : disableStatus;
}

DWORD RegistrationService::UnenrollAll()
{
    std::vector<std::wstring> accounts;
    const DWORD listError = enrollments_.List(accounts);
    if (listError != ERROR_SUCCESS)
    {
        return listError;
    }
    DWORD firstError = ERROR_SUCCESS;
    for (const std::wstring& account : accounts)
    {
        const DWORD dropError = Unenroll(account);
        if (dropError != ERROR_SUCCESS && firstError == ERROR_SUCCESS)
        {
            firstError = dropError;
        }
    }
    return firstError;
}

DWORD RegistrationService::List(std::vector<std::wstring>& accountNames) const
{
    const DWORD listError = enrollments_.List(accountNames);
    if (listError != ERROR_SUCCESS)
    {
        return listError;
    }
    accountNames.erase(
        std::remove_if(accountNames.begin(),
            accountNames.end(),
            [this](const std::wstring& accountName)
            {
                std::vector<BYTE> enrolledSid;
                std::vector<BYTE> currentSid;
                return enrollments_.Load(accountName, enrolledSid) != ERROR_SUCCESS ||
                       GetBrokerAccountSid(accountName, currentSid) != ERROR_SUCCESS ||
                       EqualSid(enrolledSid.data(), currentSid.data()) == FALSE;
            }),
        accountNames.end());
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
