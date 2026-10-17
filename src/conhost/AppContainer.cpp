// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "AppContainer.h"

#include <Aclapi.h>

namespace launch_as
{
namespace
{
DWORD GrantWindowObject(HANDLE object, PSID sid, DWORD mask)
{
    PACL oldDacl = nullptr;
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    DWORD error = GetSecurityInfo(object,
        SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &oldDacl,
        nullptr,
        descriptor.address());
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    if (!oldDacl)
    {
        return ERROR_INVALID_ACL;
    }
    for (DWORD index = 0; index < oldDacl->AceCount; ++index)
    {
        void* raw = nullptr;
        if (!GetAce(oldDacl, index, &raw))
        {
            return GetLastError();
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (ace->Header.AceFlags & INHERIT_ONLY_ACE) == 0 && (ace->Mask & mask) == mask &&
            EqualSid(const_cast<DWORD*>(&ace->SidStart), sid))
        {
            return ERROR_SUCCESS;
        }
    }
    EXPLICIT_ACCESSW access {};
    access.grfAccessPermissions = mask;
    access.grfAccessMode = GRANT_ACCESS;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    access.Trustee.ptstrName = static_cast<LPWSTR>(sid);
    LocalAllocation<PACL> dacl;
    error = SetEntriesInAclW(1, &access, oldDacl, dacl.address());
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    return SetSecurityInfo(
        object, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl.get(), nullptr);
}
} // namespace

DWORD AppContainer::Initialize(const AppContainerOptions& options)
{
    failureContext_ = L"query managed account and working directory";
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        return GetLastError();
    }
    UniqueHandle token(rawToken);
    const DWORD characters = GetCurrentDirectoryW(0, nullptr);
    if (!characters)
    {
        return GetLastError();
    }
    std::vector<wchar_t> directory(characters);
    if (!GetCurrentDirectoryW(characters, directory.data()))
    {
        return GetLastError();
    }
    DWORD error = identity_.Initialize(token.get(), directory.data(), options);
    if (error != ERROR_SUCCESS)
    {
        failureContext_ = identity_.failureContext();
        return error;
    }
    failureContext_ = L"grant AppContainer window-station access";
    error = GrantWindowObject(GetProcessWindowStation(),
        identity_.security()->AppContainerSid,
        WINSTA_ACCESSGLOBALATOMS | WINSTA_READATTRIBUTES | WINSTA_ENUMDESKTOPS | READ_CONTROL);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    failureContext_ = L"grant AppContainer desktop access";
    return GrantWindowObject(GetThreadDesktop(GetCurrentThreadId()),
        identity_.security()->AppContainerSid,
        DESKTOP_READOBJECTS | READ_CONTROL);
}

} // namespace launch_as
