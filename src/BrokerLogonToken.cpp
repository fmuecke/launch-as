// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerLogonToken.h"

#include <array>
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

    std::vector<BYTE> expectedSid;
    const DWORD expectedSidError = LookupLocalUserSid(accountName, expectedSid);
    if (expectedSidError != ERROR_SUCCESS)
    {
        token.Reset();
        return expectedSidError;
    }
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
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
