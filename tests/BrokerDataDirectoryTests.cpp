// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerDataDirectory.h"

#include <Aclapi.h>
#include <Windows.h>
#include <array>
#include <iostream>
#include <sddl.h>
#include <string>

namespace
{

class TemporaryDirectory final
{
  public:
    TemporaryDirectory()
    {
        std::array<wchar_t, MAX_PATH> temporaryPath {};
        const DWORD length =
            GetTempPathW(static_cast<DWORD>(temporaryPath.size()), temporaryPath.data());
        if (length == 0 || length >= temporaryPath.size())
        {
            return;
        }
        path_ = std::wstring(temporaryPath.data(), length) + L"launch-as-data-root-" +
                std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount());
        created_ = CreateDirectoryW(path_.c_str(), nullptr) != FALSE;
    }

    ~TemporaryDirectory()
    {
        if (created_)
        {
            RemoveDirectoryW((path_ + L"\\credentials").c_str());
            RemoveDirectoryW(path_.c_str());
        }
    }

    [[nodiscard]] bool created() const noexcept { return created_; }
    [[nodiscard]] std::wstring CredentialDirectory() const { return path_ + L"\\credentials"; }

  private:
    std::wstring path_;
    bool created_ = false;
};

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] bool HasProtectedSystemAndAdministratorsDacl(std::wstring_view path)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    const DWORD securityError = GetNamedSecurityInfoW(const_cast<wchar_t*>(path.data()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &dacl,
        nullptr,
        &descriptor);
    if (securityError != ERROR_SUCCESS || descriptor == nullptr || dacl == nullptr)
    {
        if (descriptor != nullptr)
        {
            LocalFree(descriptor);
        }
        return false;
    }
    SECURITY_DESCRIPTOR_CONTROL control = {};
    DWORD revision = 0;
    const BOOL controlled = GetSecurityDescriptorControl(descriptor, &control, &revision);
    ACL_SIZE_INFORMATION aclInfo {};
    const BOOL sized = GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation);
    bool valid = controlled != FALSE && (control & SE_DACL_PROTECTED) != 0 && sized != FALSE &&
                 aclInfo.AceCount == 2;
    for (DWORD index = 0; valid && index < aclInfo.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(dacl, index, &rawAce))
        {
            valid = false;
            break;
        }
        const auto* ace = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(rawAce);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Mask != FILE_ALL_ACCESS)
        {
            valid = false;
            break;
        }
        const PSID sid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
        std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid {};
        std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid {};
        DWORD systemSidSize = static_cast<DWORD>(systemSid.size());
        DWORD administratorsSidSize = static_cast<DWORD>(administratorsSid.size());
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidSize) ||
            !CreateWellKnownSid(WinBuiltinAdministratorsSid,
                nullptr,
                administratorsSid.data(),
                &administratorsSidSize) ||
            (EqualSid(sid, systemSid.data()) == FALSE &&
                EqualSid(sid, administratorsSid.data()) == FALSE))
        {
            valid = false;
        }
    }
    LocalFree(descriptor);
    return valid;
}

} // namespace

int wmain()
{
    TemporaryDirectory directory;
    if (!Expect(directory.created(), L"Could not create the disposable data root."))
    {
        return 1;
    }
    const std::wstring credentialDirectory = directory.CredentialDirectory();
    return Expect(launch_as::broker::CreateSecureDirectory(credentialDirectory) == ERROR_SUCCESS,
               L"Could not create the secure credential directory.") &&
                   Expect(HasProtectedSystemAndAdministratorsDacl(credentialDirectory),
                       L"Credential directory DACL is not restricted to SYSTEM and Administrators.")
               ? 0
               : 1;
}
