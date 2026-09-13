// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerLogonToken.h"

#include <algorithm>
#include <array>
#include <ntsecapi.h>
#include <string>
#include <vector>

namespace launch_as::broker
{
namespace
{

[[nodiscard]] DWORD LookupLocalUserSid(std::wstring_view accountName, std::vector<BYTE>& sid)
{
    std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> computerName {};
    DWORD computerNameCharacters = static_cast<DWORD>(computerName.size());
    if (!GetComputerNameW(computerName.data(), &computerNameCharacters))
    {
        const DWORD computerNameError = GetLastError();
        return computerNameError;
    }
    const std::wstring qualifiedName = std::wstring(computerName.data(), computerNameCharacters) +
                                       L"\\" + std::wstring(accountName);
    DWORD sidBytes = 0;
    DWORD domainCharacters = 0;
    SID_NAME_USE sidType {};
    LookupAccountNameW(
        nullptr, qualifiedName.c_str(), nullptr, &sidBytes, nullptr, &domainCharacters, &sidType);
    const DWORD lookupSizeError = GetLastError();
    if (lookupSizeError != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0 || domainCharacters == 0)
    {
        return lookupSizeError;
    }
    sid.resize(sidBytes);
    std::vector<wchar_t> domain(domainCharacters);
    if (!LookupAccountNameW(nullptr,
            qualifiedName.c_str(),
            sid.data(),
            &sidBytes,
            domain.data(),
            &domainCharacters,
            &sidType))
    {
        const DWORD lookupError = GetLastError();
        return lookupError;
    }
    if (sidType != SidTypeUser || !IsValidSid(sid.data()))
    {
        return ERROR_INVALID_SID;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD ValidateTokenUser(HANDLE token, std::vector<BYTE>& expectedSid)
{
    DWORD tokenUserBytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &tokenUserBytes);
    const DWORD tokenUserSizeError = GetLastError();
    if (tokenUserSizeError != ERROR_INSUFFICIENT_BUFFER || tokenUserBytes == 0)
    {
        return tokenUserSizeError;
    }
    std::vector<BYTE> tokenUserBuffer(tokenUserBytes);
    if (!GetTokenInformation(
            token, TokenUser, tokenUserBuffer.data(), tokenUserBytes, &tokenUserBytes))
    {
        const DWORD tokenUserError = GetLastError();
        return tokenUserError;
    }
    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenUserBuffer.data());
    if (!IsValidSid(tokenUser->User.Sid) ||
        EqualSid(tokenUser->User.Sid, reinterpret_cast<PSID>(expectedSid.data())) == FALSE)
    {
        return ERROR_ACCESS_DENIED;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD ValidateNonAdministrativeToken(HANDLE token)
{
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid {};
    DWORD administratorsSidBytes = static_cast<DWORD>(administratorsSid.size());
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid,
            nullptr,
            administratorsSid.data(),
            &administratorsSidBytes))
    {
        const DWORD administratorsSidError = GetLastError();
        return administratorsSidError;
    }
    DWORD tokenGroupsBytes = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &tokenGroupsBytes);
    const DWORD tokenGroupsSizeError = GetLastError();
    if (tokenGroupsSizeError != ERROR_INSUFFICIENT_BUFFER || tokenGroupsBytes == 0)
    {
        return tokenGroupsSizeError;
    }
    std::vector<BYTE> tokenGroupsBuffer(tokenGroupsBytes);
    if (!GetTokenInformation(
            token, TokenGroups, tokenGroupsBuffer.data(), tokenGroupsBytes, &tokenGroupsBytes))
    {
        const DWORD tokenGroupsError = GetLastError();
        return tokenGroupsError;
    }
    const auto* tokenGroups = reinterpret_cast<const TOKEN_GROUPS*>(tokenGroupsBuffer.data());
    for (DWORD index = 0; index < tokenGroups->GroupCount; ++index)
    {
        if (EqualSid(tokenGroups->Groups[index].Sid, administratorsSid.data()))
        {
            return ERROR_ACCESS_DENIED;
        }
    }
    return ERROR_SUCCESS;
}

// Membership-based rejection only ever covers the groups it explicitly names (Administrators),
// so Backup Operators, Hyper-V Administrators, and any locally-granted powerful privilege sail
// through. Enumerate what the minted token can actually do instead, and allow only the handful
// of privileges every standard token carries. Well-known privilege LUIDs are not exposed to
// user-mode code as constants (only the SE_xxx_NAME strings are), so each name is resolved via
// LookupPrivilegeValueW.
constexpr std::array<LPCWSTR, 5> AllowedTokenPrivilegeNames {
    SE_CHANGE_NOTIFY_NAME,
    SE_INC_WORKING_SET_NAME,
    SE_SHUTDOWN_NAME,
    SE_UNDOCK_NAME,
    SE_TIME_ZONE_NAME,
};

[[nodiscard]] bool IsAllowedTokenPrivilege(std::wstring_view privilegeName) noexcept
{
    return std::any_of(AllowedTokenPrivilegeNames.begin(),
        AllowedTokenPrivilegeNames.end(),
        [privilegeName](LPCWSTR allowedPrivilege) { return privilegeName == allowedPrivilege; });
}

[[nodiscard]] bool LuidEqual(const LUID& a, const LUID& b) noexcept
{
    return a.LowPart == b.LowPart && a.HighPart == b.HighPart;
}

[[nodiscard]] DWORD ValidateTokenPrivilegeAllowList(HANDLE token)
{
    std::array<LUID, AllowedTokenPrivilegeNames.size()> allowedPrivileges {};
    for (std::size_t index = 0; index < AllowedTokenPrivilegeNames.size(); ++index)
    {
        if (!LookupPrivilegeValueW(
                nullptr, AllowedTokenPrivilegeNames[index], &allowedPrivileges[index]))
        {
            const DWORD lookupError = GetLastError();
            return lookupError;
        }
    }

    DWORD tokenPrivilegesBytes = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &tokenPrivilegesBytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || tokenPrivilegesBytes == 0)
    {
        return sizeError;
    }
    std::vector<BYTE> tokenPrivilegesBuffer(tokenPrivilegesBytes);
    if (!GetTokenInformation(token,
            TokenPrivileges,
            tokenPrivilegesBuffer.data(),
            tokenPrivilegesBytes,
            &tokenPrivilegesBytes))
    {
        const DWORD tokenPrivilegesError = GetLastError();
        return tokenPrivilegesError;
    }
    const auto* tokenPrivileges =
        reinterpret_cast<const TOKEN_PRIVILEGES*>(tokenPrivilegesBuffer.data());
    for (DWORD index = 0; index < tokenPrivileges->PrivilegeCount; ++index)
    {
        const LUID& privilege = tokenPrivileges->Privileges[index].Luid;
        const bool allowed = std::any_of(allowedPrivileges.begin(),
            allowedPrivileges.end(),
            [&privilege](const LUID& allowedPrivilege)
            { return LuidEqual(allowedPrivilege, privilege); });
        if (!allowed)
        {
            return ERROR_ACCESS_DENIED;
        }
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD ValidateMediumIntegrityLevel(HANDLE token)
{
    DWORD integrityBytes = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &integrityBytes);
    const DWORD integritySizeError = GetLastError();
    if (integritySizeError != ERROR_INSUFFICIENT_BUFFER || integrityBytes == 0)
    {
        return integritySizeError;
    }
    std::vector<BYTE> integrityBuffer(integrityBytes);
    if (!GetTokenInformation(
            token, TokenIntegrityLevel, integrityBuffer.data(), integrityBytes, &integrityBytes))
    {
        const DWORD integrityError = GetLastError();
        return integrityError;
    }
    const auto* integrity = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrityBuffer.data());
    if (!IsValidSid(integrity->Label.Sid))
    {
        return ERROR_INVALID_SID;
    }
    const PUCHAR subAuthorityCount = GetSidSubAuthorityCount(integrity->Label.Sid);
    if (subAuthorityCount == nullptr || *subAuthorityCount == 0)
    {
        return ERROR_INVALID_SID;
    }
    const PDWORD integrityRid =
        GetSidSubAuthority(integrity->Label.Sid, static_cast<DWORD>(*subAuthorityCount - 1));
    if (integrityRid == nullptr || *integrityRid != SECURITY_MANDATORY_MEDIUM_RID)
    {
        return ERROR_ACCESS_DENIED;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD ValidateRestrictedTokenPrivileges(HANDLE token)
{
    LUID changeNotifyPrivilege {};
    if (!LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &changeNotifyPrivilege))
    {
        const DWORD lookupError = GetLastError();
        return lookupError;
    }
    DWORD tokenPrivilegesBytes = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &tokenPrivilegesBytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || tokenPrivilegesBytes == 0)
    {
        return sizeError;
    }
    std::vector<BYTE> tokenPrivilegesBuffer(tokenPrivilegesBytes);
    if (!GetTokenInformation(token,
            TokenPrivileges,
            tokenPrivilegesBuffer.data(),
            tokenPrivilegesBytes,
            &tokenPrivilegesBytes))
    {
        const DWORD tokenPrivilegesError = GetLastError();
        return tokenPrivilegesError;
    }
    const auto* tokenPrivileges =
        reinterpret_cast<const TOKEN_PRIVILEGES*>(tokenPrivilegesBuffer.data());
    for (DWORD index = 0; index < tokenPrivileges->PrivilegeCount; ++index)
    {
        const LUID_AND_ATTRIBUTES& privilege = tokenPrivileges->Privileges[index];
        if ((privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0 &&
            !LuidEqual(privilege.Luid, changeNotifyPrivilege))
        {
            return ERROR_ACCESS_DENIED;
        }
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD RestrictToken(HANDLE sourceToken, HANDLE& restrictedToken)
{
    restrictedToken = nullptr;
    if (!CreateRestrictedToken(sourceToken,
            DISABLE_MAX_PRIVILEGE,
            0,
            nullptr,
            0,
            nullptr,
            0,
            nullptr,
            &restrictedToken))
    {
        const DWORD restrictionError = GetLastError();
        return restrictionError;
    }
    const DWORD integrityError = ValidateMediumIntegrityLevel(restrictedToken);
    if (integrityError != ERROR_SUCCESS)
    {
        CloseHandle(restrictedToken);
        restrictedToken = nullptr;
        return integrityError;
    }
    const DWORD privilegesError = ValidateRestrictedTokenPrivileges(restrictedToken);
    if (privilegesError != ERROR_SUCCESS)
    {
        CloseHandle(restrictedToken);
        restrictedToken = nullptr;
        return privilegesError;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD ValidateAccountPrivilegeAllowList(PSID accountSid)
{
    LSA_OBJECT_ATTRIBUTES attributes {};
    LSA_HANDLE policy = nullptr;
    const NTSTATUS openStatus = LsaOpenPolicy(nullptr, &attributes, POLICY_LOOKUP_NAMES, &policy);
    if (openStatus != 0)
    {
        return LsaNtStatusToWinError(openStatus);
    }

    PLSA_UNICODE_STRING accountRights = nullptr;
    ULONG accountRightCount = 0;
    const NTSTATUS enumerateStatus =
        LsaEnumerateAccountRights(policy, accountSid, &accountRights, &accountRightCount);
    LsaClose(policy);
    if (enumerateStatus != 0)
    {
        const DWORD enumerateError = LsaNtStatusToWinError(enumerateStatus);
        return enumerateError == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : enumerateError;
    }

    DWORD validationError = ERROR_SUCCESS;
    for (ULONG index = 0; index < accountRightCount; ++index)
    {
        const LSA_UNICODE_STRING& right = accountRights[index];
        if (right.Buffer == nullptr || right.Length % sizeof(wchar_t) != 0)
        {
            validationError = ERROR_INVALID_DATA;
            break;
        }
        const std::wstring_view rightName(right.Buffer, right.Length / sizeof(wchar_t));
        constexpr std::wstring_view PrivilegePrefix = L"Se";
        constexpr std::wstring_view PrivilegeSuffix = L"Privilege";
        const bool isPrivilege =
            rightName.size() >= PrivilegePrefix.size() + PrivilegeSuffix.size() &&
            rightName.starts_with(PrivilegePrefix) && rightName.ends_with(PrivilegeSuffix);
        if (isPrivilege && !IsAllowedTokenPrivilege(rightName))
        {
            validationError = ERROR_ACCESS_DENIED;
            break;
        }
    }
    if (accountRights != nullptr)
    {
        LsaFreeMemory(accountRights);
    }
    return validationError;
}

} // namespace

BrokerLogonToken::~BrokerLogonToken() { Reset(); }

HANDLE BrokerLogonToken::get() const noexcept { return token_; }

BrokerLogonToken::operator bool() const noexcept { return token_ != nullptr; }

void BrokerLogonToken::Reset(HANDLE token) noexcept
{
    if (token_ != nullptr)
    {
        CloseHandle(token_);
    }
    token_ = token;
}

DWORD GetBrokerAccountSid(std::wstring_view accountName, std::vector<BYTE>& sid)
{
    return LookupLocalUserSid(accountName, sid);
}

DWORD LogOnBrokerAccount(
    std::wstring_view accountName, const SecurePassword& password, BrokerLogonToken& token)
{
    token.Reset();
    if (accountName.empty() || password.characters().empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    std::vector<BYTE> expectedSid;
    const DWORD expectedSidError = LookupLocalUserSid(accountName, expectedSid);
    if (expectedSidError != ERROR_SUCCESS)
    {
        return expectedSidError;
    }
    const DWORD accountPrivilegeError = ValidateAccountPrivilegeAllowList(expectedSid.data());
    if (accountPrivilegeError != ERROR_SUCCESS)
    {
        return accountPrivilegeError;
    }
    HANDLE rawToken = nullptr;
    const BOOL loggedOn = LogonUserW(std::wstring(accountName).c_str(),
        L".",
        password.c_str(),
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &rawToken);
    const DWORD logonError = loggedOn ? ERROR_SUCCESS : GetLastError();
    if (!loggedOn)
    {
        return logonError;
    }
    token.Reset(rawToken);

    const DWORD tokenUserError = ValidateTokenUser(token.get(), expectedSid);
    if (tokenUserError != ERROR_SUCCESS)
    {
        token.Reset();
        return tokenUserError;
    }
    const DWORD tokenGroupsError = ValidateNonAdministrativeToken(token.get());
    if (tokenGroupsError != ERROR_SUCCESS)
    {
        token.Reset();
        return tokenGroupsError;
    }
    const DWORD tokenPrivilegeError = ValidateTokenPrivilegeAllowList(token.get());
    if (tokenPrivilegeError != ERROR_SUCCESS)
    {
        token.Reset();
        return tokenPrivilegeError;
    }

    HANDLE restrictedToken = nullptr;
    const DWORD restrictionError = RestrictToken(token.get(), restrictedToken);
    if (restrictionError != ERROR_SUCCESS)
    {
        token.Reset();
        return restrictionError;
    }
    token.Reset(restrictedToken);

    const DWORD restrictedTokenUserError = ValidateTokenUser(token.get(), expectedSid);
    if (restrictedTokenUserError != ERROR_SUCCESS)
    {
        token.Reset();
        return restrictedTokenUserError;
    }
    const DWORD restrictedTokenGroupsError = ValidateNonAdministrativeToken(token.get());
    if (restrictedTokenGroupsError != ERROR_SUCCESS)
    {
        token.Reset();
        return restrictedTokenGroupsError;
    }
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
