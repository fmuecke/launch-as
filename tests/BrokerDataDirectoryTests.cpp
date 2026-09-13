// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerDataDirectory.h"
#include "TestSupport.h"

#include <Aclapi.h>
#include <ShlObj.h>
#include <Windows.h>
#include <array>
#include <iostream>
#include <sddl.h>
#include <string>
#include <vector>

namespace
{

class ScopedEnvironmentVariable final
{
  public:
    explicit ScopedEnvironmentVariable(const wchar_t* name) : name_(name)
    {
        const DWORD requiredCharacters = GetEnvironmentVariableW(name_, nullptr, 0);
        if (requiredCharacters == 0)
        {
            wasPresent_ = GetLastError() != ERROR_ENVVAR_NOT_FOUND;
            return;
        }
        originalValue_.resize(requiredCharacters);
        if (GetEnvironmentVariableW(
                name_, originalValue_.data(), static_cast<DWORD>(originalValue_.size())) == 0)
        {
            originalValue_.clear();
            return;
        }
        originalValue_.pop_back();
        wasPresent_ = true;
    }

    ~ScopedEnvironmentVariable()
    {
        SetEnvironmentVariableW(name_, wasPresent_ ? originalValue_.c_str() : nullptr);
    }

    ScopedEnvironmentVariable(const ScopedEnvironmentVariable&) = delete;
    ScopedEnvironmentVariable& operator=(const ScopedEnvironmentVariable&) = delete;

  private:
    const wchar_t* name_;
    std::wstring originalValue_;
    bool wasPresent_ = false;
};

[[nodiscard]] bool LookupBrokerServiceSid(std::vector<BYTE>& sid, bool& found)
{
    constexpr wchar_t BrokerServiceAccountName[] = L"NT SERVICE\\launch-as-broker";
    sid.clear();
    found = false;
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE use = {};
    if (LookupAccountNameW(
            nullptr, BrokerServiceAccountName, nullptr, &sidSize, nullptr, &domainSize, &use))
    {
        return false;
    }
    const DWORD lookupError = GetLastError();
    if (lookupError == ERROR_NONE_MAPPED)
    {
        return true;
    }
    if (lookupError != ERROR_INSUFFICIENT_BUFFER || sidSize == 0)
    {
        return false;
    }
    sid.resize(sidSize);
    std::vector<wchar_t> domain(domainSize);
    if (!LookupAccountNameW(nullptr,
            BrokerServiceAccountName,
            sid.data(),
            &sidSize,
            domain.data(),
            &domainSize,
            &use))
    {
        sid.clear();
        return false;
    }
    found = IsValidSid(sid.data()) != FALSE;
    return found;
}

[[nodiscard]] bool HasProtectedSystemAndAdministratorsDacl(std::wstring_view path)
{
    std::vector<BYTE> brokerServiceSid;
    bool brokerServiceSidFound = false;
    if (!LookupBrokerServiceSid(brokerServiceSid, brokerServiceSidFound))
    {
        return false;
    }
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
    const DWORD expectedAceCount = brokerServiceSidFound ? 3U : 2U;
    bool valid = controlled != FALSE && (control & SE_DACL_PROTECTED) != 0 && sized != FALSE &&
                 aclInfo.AceCount == expectedAceCount;
    bool hasSystem = false;
    bool hasAdministrators = false;
    bool hasService = false;
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
                &administratorsSidSize))
        {
            valid = false;
            break;
        }
        if (EqualSid(sid, systemSid.data()))
        {
            hasSystem = true;
        }
        else if (EqualSid(sid, administratorsSid.data()))
        {
            hasAdministrators = true;
        }
        else if (brokerServiceSidFound && EqualSid(sid, brokerServiceSid.data()))
        {
            if (hasService)
            {
                valid = false;
                break;
            }
            hasService = true;
        }
        else
        {
            valid = false;
            break;
        }
    }
    LocalFree(descriptor);
    return valid && hasSystem && hasAdministrators && hasService == brokerServiceSidFound;
}

// Junctions never require elevation or SeCreateSymbolicLinkPrivilege to create, unlike symlinks,
// so this reproduces what an unprivileged attacker can pre-plant at the target path.
[[nodiscard]] bool CreateDirectoryJunction(const std::wstring& path, const std::wstring& target)
{
    std::wstring commandLine =
        L"cmd.exe /c mklink /J \"" + path + L"\" \"" + target + L"\" >NUL 2>&1";
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
    launch_as::test::TemporaryDirectory directory;
    if (!Expect(directory.created(), L"Could not create the disposable data root."))
    {
        return 1;
    }
    const std::wstring credentialDirectory = (directory.path() / L"credentials").native();
    const bool freshCreationOk =
        Expect(launch_as::broker::CreateSecureDirectory(credentialDirectory) == ERROR_SUCCESS,
            L"Could not create the secure credential directory.") &&
        Expect(HasProtectedSystemAndAdministratorsDacl(credentialDirectory),
            L"Credential directory DACL is not restricted to SYSTEM and Administrators.");

    // A directory the caller itself already owns (i.e. a standard user pre-created it before the
    // broker ever ran) must never be adopted, even though NTFS ownership would let the owner
    // re-grant themselves access no matter what DACL gets stamped on top of it afterwards.
    const std::wstring untrustedOwnerDirectory = (directory.path() / L"untrusted-owner").native();
    const bool untrustedOwnerRejected =
        Expect(CreateDirectoryW(untrustedOwnerDirectory.c_str(), nullptr) != FALSE,
            L"Could not pre-create the untrusted-owner directory fixture.") &&
        Expect(launch_as::broker::CreateSecureDirectory(untrustedOwnerDirectory) != ERROR_SUCCESS,
            L"CreateSecureDirectory adopted a pre-existing directory it does not own.");
    RemoveDirectoryW(untrustedOwnerDirectory.c_str());

    // A pre-existing reparse point must be rejected outright: SetFileSecurityW follows reparse
    // points, so adopting one would let an attacker redirect the DACL stamp anywhere.
    const std::wstring junctionDirectory = (directory.path() / L"reparse-point").native();
    const bool reparsePointRejected =
        Expect(CreateDirectoryJunction(junctionDirectory, directory.path().native()),
            L"Could not pre-create the reparse-point directory fixture.") &&
        Expect(launch_as::broker::CreateSecureDirectory(junctionDirectory) != ERROR_SUCCESS,
            L"CreateSecureDirectory followed a reparse point instead of rejecting it.");
    RemoveDirectoryW(junctionDirectory.c_str());

    PWSTR programData = nullptr;
    const HRESULT knownFolderResult =
        SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &programData);
    const std::wstring expectedBrokerDirectory =
        SUCCEEDED(knownFolderResult) ? std::wstring(programData) + L"\\launch-as" : L"";
    CoTaskMemFree(programData);
    ScopedEnvironmentVariable programDataOverride(L"ProgramData");
    const std::wstring poisonedProgramData = (directory.path() / L"poisoned-program-data").native();
    const bool environmentOverridden =
        SetEnvironmentVariableW(L"ProgramData", poisonedProgramData.c_str()) != FALSE;
    std::wstring resolvedBrokerDirectory;
    const bool knownFolderUsed =
        SUCCEEDED(knownFolderResult) && environmentOverridden &&
        launch_as::broker::GetBrokerDataDirectoryPath(resolvedBrokerDirectory) == ERROR_SUCCESS &&
        resolvedBrokerDirectory == expectedBrokerDirectory;

    return freshCreationOk && untrustedOwnerRejected && reparsePointRejected &&
                   Expect(knownFolderUsed,
                       L"Broker data directory followed the ProgramData environment variable.")
               ? 0
               : 1;
}
