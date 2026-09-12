// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAccountProvisioner.h"

#include <Lm.h>
#include <Lmcons.h>
#include <algorithm>
#include <array>
#include <string>

namespace launch_as::broker
{
namespace
{

constexpr DWORD RequiredAccountFlags =
    UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE;
constexpr wchar_t ManagedAccountComment[] = L"Managed by launch-as.";

[[nodiscard]] NET_API_STATUS EnableAndHardenBrokerManagedAccount(const std::wstring& accountName)
{
    LPBYTE rawAccount = nullptr;
    const NET_API_STATUS readStatus = NetUserGetInfo(nullptr, accountName.c_str(), 4, &rawAccount);
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
    flags.usri1008_flags = (account->usri4_flags | RequiredAccountFlags) & ~UF_ACCOUNTDISABLE;
    NetApiBufferFree(rawAccount);
    return NetUserSetInfo(
        nullptr, accountName.c_str(), 1008, reinterpret_cast<LPBYTE>(&flags), nullptr);
}

[[nodiscard]] NET_API_STATUS SetManagedAccountComment(const std::wstring& accountName)
{
    USER_INFO_1007 comment {};
    comment.usri1007_comment = const_cast<wchar_t*>(ManagedAccountComment);
    return NetUserSetInfo(
        nullptr, accountName.c_str(), 1007, reinterpret_cast<LPBYTE>(&comment), nullptr);
}

[[nodiscard]] DWORD RejectAdministratorAccount(std::wstring_view accountName)
{
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid {};
    DWORD administratorsSidSize = static_cast<DWORD>(administratorsSid.size());
    if (!CreateWellKnownSid(
            WinBuiltinAdministratorsSid, nullptr, administratorsSid.data(), &administratorsSidSize))
    {
        const DWORD sidError = GetLastError();
        return sidError;
    }

    const std::wstring name(accountName);
    LPLOCALGROUP_USERS_INFO_0 rawGroups = nullptr;
    DWORD groupsRead = 0;
    DWORD groupsAvailable = 0;
    const NET_API_STATUS groupStatus = NetUserGetLocalGroups(nullptr,
        name.c_str(),
        0,
        LG_INCLUDE_INDIRECT,
        reinterpret_cast<LPBYTE*>(&rawGroups),
        MAX_PREFERRED_LENGTH,
        &groupsRead,
        &groupsAvailable);
    if (groupStatus == NERR_UserNotFound)
    {
        return ERROR_SUCCESS;
    }
    if (groupStatus != NERR_Success)
    {
        return groupStatus;
    }
    for (DWORD index = 0; index < groupsRead; ++index)
    {
        std::array<BYTE, SECURITY_MAX_SID_SIZE> groupSid {};
        DWORD groupSidSize = static_cast<DWORD>(groupSid.size());
        std::array<wchar_t, 256> domain {};
        DWORD domainSize = static_cast<DWORD>(domain.size());
        SID_NAME_USE use {};
        if (!LookupAccountNameW(nullptr,
                rawGroups[index].lgrui0_name,
                groupSid.data(),
                &groupSidSize,
                domain.data(),
                &domainSize,
                &use))
        {
            const DWORD lookupError = GetLastError();
            NetApiBufferFree(rawGroups);
            return lookupError;
        }
        if (EqualSid(groupSid.data(), administratorsSid.data()))
        {
            NetApiBufferFree(rawGroups);
            return ERROR_MEMBER_IN_GROUP;
        }
    }
    NetApiBufferFree(rawGroups);
    return ERROR_SUCCESS;
}

} // namespace

bool IsValidBrokerAccountName(std::wstring_view accountName) noexcept
{
    constexpr std::wstring_view InvalidCharacters = L"\\/[]:;|=,+*?<>\"";
    return !accountName.empty() && accountName.size() <= UNLEN &&
           accountName.find_first_of(InvalidCharacters) == std::wstring_view::npos &&
           std::all_of(accountName.begin(),
               accountName.end(),
               [](wchar_t character) { return character >= L' '; });
}

DWORD ValidateBrokerAccountForRegistration(std::wstring_view accountName)
{
    return IsValidBrokerAccountName(accountName) ? RejectAdministratorAccount(accountName)
                                                 : ERROR_INVALID_PARAMETER;
}

DWORD CreateBrokerManagedLocalAccount(std::wstring_view accountName, const SecurePassword& password)
{
    if (password.characters().empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD accountValidationError = ValidateBrokerAccountForRegistration(accountName);
    if (accountValidationError != ERROR_SUCCESS)
    {
        return accountValidationError;
    }

    const std::wstring name(accountName);
    USER_INFO_1 account {};
    account.usri1_name = const_cast<wchar_t*>(name.c_str());
    account.usri1_password = const_cast<wchar_t*>(password.c_str());
    account.usri1_priv = USER_PRIV_USER;
    account.usri1_flags = UF_SCRIPT | RequiredAccountFlags;
    account.usri1_comment = const_cast<wchar_t*>(ManagedAccountComment);
    DWORD parameterError = 0;
    const NET_API_STATUS createStatus =
        NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&account), &parameterError);
    return createStatus;
}

DWORD TakeOverExistingLocalAccount(
    std::wstring_view accountName, const SecurePassword& password, bool allowEnable)
{
    if (password.characters().empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD accountValidationError = ValidateBrokerAccountForRegistration(accountName);
    if (accountValidationError != ERROR_SUCCESS)
    {
        return accountValidationError;
    }

    const std::wstring name(accountName);
    LPBYTE rawAccount = nullptr;
    const NET_API_STATUS accountStatus = NetUserGetInfo(nullptr, name.c_str(), 4, &rawAccount);
    if (accountStatus != NERR_Success || rawAccount == nullptr)
    {
        if (rawAccount != nullptr)
        {
            NetApiBufferFree(rawAccount);
        }
        return accountStatus == NERR_Success ? ERROR_INVALID_DATA : accountStatus;
    }
    const auto* existingAccount = reinterpret_cast<const USER_INFO_4*>(rawAccount);
    const bool accountDisabled = (existingAccount->usri4_flags & UF_ACCOUNTDISABLE) != 0;
    NetApiBufferFree(rawAccount);
    if (accountDisabled && !allowEnable)
    {
        return ERROR_ACCOUNT_DISABLED;
    }

    return RefreshBrokerManagedLocalAccount(accountName, password);
}

DWORD RefreshBrokerManagedLocalAccount(
    std::wstring_view accountName, const SecurePassword& password)
{
    if (password.characters().empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    const DWORD accountValidationError = ValidateBrokerAccountForRegistration(accountName);
    if (accountValidationError != ERROR_SUCCESS)
    {
        return accountValidationError;
    }

    const std::wstring name(accountName);
    USER_INFO_1003 replacementPassword {};
    replacementPassword.usri1003_password = const_cast<wchar_t*>(password.c_str());
    const NET_API_STATUS passwordStatus = NetUserSetInfo(
        nullptr, name.c_str(), 1003, reinterpret_cast<LPBYTE>(&replacementPassword), nullptr);
    if (passwordStatus != NERR_Success)
    {
        return passwordStatus;
    }
    const NET_API_STATUS hardenStatus = EnableAndHardenBrokerManagedAccount(name);
    return hardenStatus == NERR_Success ? SetManagedAccountComment(name) : hardenStatus;
}

} // namespace launch_as::broker
