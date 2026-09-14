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

DWORD RegistrationService::Create(std::wstring_view accountName)
{
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }
    EnrollmentRecord existingEnrollment;
    const DWORD enrollmentError = enrollments_.Load(accountName, existingEnrollment);
    if (enrollmentError == ERROR_SUCCESS)
    {
        return ERROR_ALREADY_EXISTS;
    }
    if (enrollmentError != ERROR_FILE_NOT_FOUND)
    {
        return enrollmentError;
    }

    SecurePassword password;
    const DWORD passwordError = GenerateBrokerPassword(password);
    if (passwordError != ERROR_SUCCESS)
    {
        return passwordError;
    }
    const DWORD accountError = CreateBrokerManagedLocalAccount(accountName, password);
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
    return enrollments_.Store(accountName, accountSid, true);
}

DWORD RegistrationService::TakeOver(std::wstring_view accountName, bool allowEnable)
{
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }

    EnrollmentRecord existingEnrollment;
    const DWORD enrollmentError = enrollments_.Load(accountName, existingEnrollment);
    if (enrollmentError != ERROR_SUCCESS && enrollmentError != ERROR_FILE_NOT_FOUND)
    {
        return enrollmentError;
    }
    if (enrollmentError == ERROR_SUCCESS && existingEnrollment.brokerManaged)
    {
        std::vector<BYTE> currentSid;
        const DWORD sidError = GetBrokerAccountSid(accountName, currentSid);
        if (sidError != ERROR_SUCCESS && (sidError != NERR_UserNotFound || !allowEnable))
        {
            return sidError;
        }
        if (sidError == ERROR_SUCCESS &&
            EqualSid(existingEnrollment.accountSid.data(), currentSid.data()) == FALSE &&
            !allowEnable)
        {
            return ERROR_ACCESS_DENIED;
        }
    }

    SecurePassword password;
    const DWORD passwordError = GenerateBrokerPassword(password);
    if (passwordError != ERROR_SUCCESS)
    {
        return passwordError;
    }
    DWORD accountError = TakeOverExistingLocalAccount(accountName, password, allowEnable);
    if (accountError == NERR_UserNotFound && allowEnable)
    {
        accountError = CreateBrokerManagedLocalAccount(accountName, password);
        if (accountError == NERR_UserExists)
        {
            accountError = TakeOverExistingLocalAccount(accountName, password, true);
        }
    }
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
    return enrollments_.Store(accountName, accountSid, true);
}

DWORD RegistrationService::ResetPassword(
    std::wstring_view accountName, const SecurePassword& password) const
{
    if (!IsValidBrokerAccountName(accountName) || password.characters().empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    EnrollmentRecord enrollment;
    const DWORD enrollmentError = enrollments_.Load(accountName, enrollment);
    if (enrollmentError != ERROR_SUCCESS)
    {
        return enrollmentError;
    }
    if (!enrollment.brokerManaged)
    {
        return ERROR_ACCESS_DENIED;
    }
    std::vector<BYTE> currentSid;
    const DWORD sidError = GetBrokerAccountSid(accountName, currentSid);
    if (sidError != ERROR_SUCCESS)
    {
        return sidError;
    }
    if (EqualSid(enrollment.accountSid.data(), currentSid.data()) == FALSE)
    {
        return ERROR_ACCESS_DENIED;
    }
    const std::wstring name(accountName);
    USER_INFO_1003 replacementPassword {};
    replacementPassword.usri1003_password = const_cast<wchar_t*>(password.c_str());
    return NetUserSetInfo(
        nullptr, name.c_str(), 1003, reinterpret_cast<LPBYTE>(&replacementPassword), nullptr);
}

DWORD RegistrationService::Forget(std::wstring_view accountName)
{
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD removeError = enrollments_.Remove(accountName);
    return removeError == ERROR_FILE_NOT_FOUND ? ERROR_NOT_FOUND : removeError;
}

DWORD RegistrationService::Delete(std::wstring_view accountName)
{
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }
    EnrollmentRecord enrollment;
    const DWORD enrollmentError = enrollments_.Load(accountName, enrollment);
    if (enrollmentError != ERROR_SUCCESS)
    {
        return enrollmentError == ERROR_FILE_NOT_FOUND ? ERROR_NOT_FOUND : enrollmentError;
    }
    if (!enrollment.brokerManaged)
    {
        return ERROR_ACCESS_DENIED;
    }
    std::vector<BYTE> currentSid;
    const DWORD sidError = GetBrokerAccountSid(accountName, currentSid);
    if (sidError == ERROR_NONE_MAPPED)
    {
        return enrollments_.Remove(accountName);
    }
    if (sidError != ERROR_SUCCESS)
    {
        return sidError;
    }
    if (EqualSid(enrollment.accountSid.data(), currentSid.data()) == FALSE)
    {
        return ERROR_ACCESS_DENIED;
    }
    const std::wstring name(accountName);
    const NET_API_STATUS deleteStatus = NetUserDel(nullptr, name.c_str());
    return deleteStatus == NERR_Success ? enrollments_.Remove(accountName) : deleteStatus;
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
                EnrollmentRecord enrollment;
                std::vector<BYTE> currentSid;
                return enrollments_.Load(accountName, enrollment) != ERROR_SUCCESS ||
                       !enrollment.brokerManaged ||
                       GetBrokerAccountSid(accountName, currentSid) != ERROR_SUCCESS ||
                       EqualSid(enrollment.accountSid.data(), currentSid.data()) == FALSE;
            }),
        accountNames.end());
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
