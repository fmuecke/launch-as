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
    [[nodiscard]] const std::wstring& path() const noexcept { return path_; }
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

// Junctions never require elevation or SeCreateSymbolicLinkPrivilege to create, unlike symlinks,
// so this reproduces what an unprivileged attacker can pre-plant at the target path.
[[nodiscard]] bool CreateDirectoryJunction(const std::wstring& path, const std::wstring& target)
{
    std::wstring commandLine = L"cmd.exe /c mklink /J \"" + path + L"\" \"" + target + L"\" >NUL 2>&1";
    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo {};
    if (!CreateProcessW(nullptr,
            commandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo))
    {
        return false;
    }
    WaitForSingleObject(processInfo.hProcess, INFINITE);
    DWORD exitCode = 1;
    const BOOL gotExitCode = GetExitCodeProcess(processInfo.hProcess, &exitCode);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
    return gotExitCode != FALSE && exitCode == 0;
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
    const bool freshCreationOk =
        Expect(launch_as::broker::CreateSecureDirectory(credentialDirectory) == ERROR_SUCCESS,
            L"Could not create the secure credential directory.") &&
        Expect(HasProtectedSystemAndAdministratorsDacl(credentialDirectory),
            L"Credential directory DACL is not restricted to SYSTEM and Administrators.");

    // A directory the caller itself already owns (i.e. a standard user pre-created it before the
    // broker ever ran) must never be adopted, even though NTFS ownership would let the owner
    // re-grant themselves access no matter what DACL gets stamped on top of it afterwards.
    const std::wstring untrustedOwnerDirectory = directory.path() + L"\\untrusted-owner";
    const bool untrustedOwnerRejected =
        Expect(CreateDirectoryW(untrustedOwnerDirectory.c_str(), nullptr) != FALSE,
            L"Could not pre-create the untrusted-owner directory fixture.") &&
        Expect(launch_as::broker::CreateSecureDirectory(untrustedOwnerDirectory) != ERROR_SUCCESS,
            L"CreateSecureDirectory adopted a pre-existing directory it does not own.");
    RemoveDirectoryW(untrustedOwnerDirectory.c_str());

    // A pre-existing reparse point must be rejected outright: SetFileSecurityW follows reparse
    // points, so adopting one would let an attacker redirect the DACL stamp anywhere.
    const std::wstring junctionDirectory = directory.path() + L"\\reparse-point";
    const bool reparsePointRejected =
        Expect(CreateDirectoryJunction(junctionDirectory, directory.path()),
            L"Could not pre-create the reparse-point directory fixture.") &&
        Expect(launch_as::broker::CreateSecureDirectory(junctionDirectory) != ERROR_SUCCESS,
            L"CreateSecureDirectory followed a reparse point instead of rejecting it.");
    RemoveDirectoryW(junctionDirectory.c_str());

    return freshCreationOk && untrustedOwnerRejected && reparsePointRejected ? 0 : 1;
}
