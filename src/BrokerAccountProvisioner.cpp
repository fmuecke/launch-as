// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAccountProvisioner.h"

#include <Lm.h>
#include <Lmcons.h>
#include <string>

namespace launch_as::broker
{
namespace
{

constexpr DWORD RequiredAccountFlags =
    UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE;

[[nodiscard]] bool IsValidAccountName(std::wstring_view accountName)
{
    constexpr std::wstring_view InvalidCharacters = L"\\/[]:;|=,+*?<>\"";
    return !accountName.empty() && accountName.size() <= UNLEN &&
           accountName.find_first_of(InvalidCharacters) == std::wstring_view::npos;
}

[[nodiscard]] NET_API_STATUS ApplyAccountFlags(const std::wstring& accountName)
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

} // namespace

DWORD ProvisionStandardLocalAccount(std::wstring_view accountName, const SecurePassword& password)
{
    if (!IsValidAccountName(accountName) || password.characters().empty())
    {
        return ERROR_INVALID_PARAMETER;
    }

    const std::wstring name(accountName);
    USER_INFO_1 account {};
    account.usri1_name = const_cast<wchar_t*>(name.c_str());
    account.usri1_password = const_cast<wchar_t*>(password.c_str());
    account.usri1_priv = USER_PRIV_USER;
    account.usri1_flags = UF_SCRIPT | RequiredAccountFlags;
    DWORD parameterError = 0;
    const NET_API_STATUS createStatus =
        NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&account), &parameterError);
    if (createStatus == NERR_Success)
    {
        return ERROR_SUCCESS;
    }
    if (createStatus != NERR_UserExists)
    {
        return createStatus;
    }

    USER_INFO_1003 replacementPassword {};
    replacementPassword.usri1003_password = const_cast<wchar_t*>(password.c_str());
    const NET_API_STATUS passwordStatus = NetUserSetInfo(
        nullptr, name.c_str(), 1003, reinterpret_cast<LPBYTE>(&replacementPassword), nullptr);
    if (passwordStatus != NERR_Success)
    {
        return passwordStatus;
    }
    return ApplyAccountFlags(name);
}

} // namespace launch_as::broker
