// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "Win32Support.h"

#include <Aclapi.h>
#include <filesystem>

namespace launch_as::test
{
// Elevated runners can inherit only an Administrators grant. Restricted launch tokens
// disable that group, so fixtures need the explicit user access a managed account has.
inline bool GrantScopeFixtureAccess(const std::filesystem::path& directory)
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        return false;
    }
    UniqueHandle token(rawToken);
    std::vector<BYTE> user;
    PACL original = nullptr;
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    if (QueryTokenInformation(token.get(), TokenUser, user) != ERROR_SUCCESS ||
        GetNamedSecurityInfoW(directory.c_str(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &original,
            nullptr,
            descriptor.address()) != ERROR_SUCCESS)
    {
        return false;
    }
    EXPLICIT_ACCESSW access {};
    access.grfAccessPermissions = FILE_ALL_ACCESS;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.ptstrName =
        static_cast<LPWSTR>(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid);
    LocalAllocation<PACL> updated;
    return SetEntriesInAclW(1, &access, original, updated.address()) == ERROR_SUCCESS &&
           SetNamedSecurityInfoW(const_cast<LPWSTR>(directory.c_str()),
               SE_FILE_OBJECT,
               DACL_SECURITY_INFORMATION,
               nullptr,
               nullptr,
               updated.get(),
               nullptr) == ERROR_SUCCESS;
}
} // namespace launch_as::test
