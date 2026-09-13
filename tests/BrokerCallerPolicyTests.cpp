// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerCallerPolicy.h"
#include "TestSupport.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <string>
#include <vector>

namespace
{

[[nodiscard]] DWORD GetCurrentUserSid(std::vector<BYTE>& sid)
{
    sid.clear();
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        const DWORD tokenError = GetLastError();
        return tokenError;
    }
    DWORD requiredBytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &requiredBytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || requiredBytes == 0)
    {
        CloseHandle(token);
        return sizeError;
    }
    std::vector<BYTE> tokenUser(requiredBytes);
    if (!GetTokenInformation(token, TokenUser, tokenUser.data(), requiredBytes, &requiredBytes))
    {
        const DWORD userError = GetLastError();
        CloseHandle(token);
        return userError;
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(tokenUser.data());
    if (!IsValidSid(user->User.Sid))
    {
        CloseHandle(token);
        return ERROR_INVALID_SID;
    }
    const DWORD sidBytes = GetLengthSid(user->User.Sid);
    sid.resize(sidBytes);
    if (!CopySid(sidBytes, sid.data(), user->User.Sid))
    {
        const DWORD copyError = GetLastError();
        CloseHandle(token);
        return copyError;
    }
    CloseHandle(token);
    return ERROR_SUCCESS;
}

} // namespace

int wmain()
{
    launch_as::test::TemporaryDirectory directory;
    if (!Expect(directory.created(), L"Could not create the disposable policy directory."))
    {
        return 1;
    }

    const std::wstring policyPath = (directory.path() / L"caller.sid").native();
    std::vector<BYTE> currentUserSid;
    if (!Expect(GetCurrentUserSid(currentUserSid) == ERROR_SUCCESS,
            L"Could not resolve the current user SID."))
    {
        return 1;
    }
    if (!Expect(launch_as::broker::StoreAuthorizedCallerSid(policyPath, currentUserSid.data()) ==
                    ERROR_SUCCESS,
            L"Could not store the authorised caller SID."))
    {
        return 1;
    }

    std::vector<BYTE> storedSid;
    if (!Expect(launch_as::broker::LoadAuthorizedCallerSid(policyPath, storedSid) == ERROR_SUCCESS,
            L"Could not load the authorised caller SID."))
    {
        return 1;
    }

    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid {};
    DWORD systemSidBytes = static_cast<DWORD>(systemSid.size());
    if (!Expect(CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidBytes),
            L"Could not construct the SYSTEM SID."))
    {
        return 1;
    }

    return Expect(launch_as::broker::IsAuthorizedCaller(storedSid, currentUserSid),
               L"The stored caller SID did not authorize its owner.") &&
                   Expect(!launch_as::broker::IsAuthorizedCaller(storedSid,
                              std::vector<BYTE>(
                                  systemSid.begin(), systemSid.begin() + systemSidBytes)),
                       L"The stored caller SID authorized a different user.")
               ? 0
               : 1;
}
