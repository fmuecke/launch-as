// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerDataDirectory.h"

#include <Aclapi.h>
#include <array>
#include <sddl.h>
#include <string>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr wchar_t RestrictedDirectoryDacl[] = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";

class LocalSecurityDescriptor final
{
  public:
    LocalSecurityDescriptor() = default;

    ~LocalSecurityDescriptor()
    {
        if (value_ != nullptr)
        {
            LocalFree(value_);
        }
    }

    LocalSecurityDescriptor(const LocalSecurityDescriptor&) = delete;
    LocalSecurityDescriptor& operator=(const LocalSecurityDescriptor&) = delete;

    [[nodiscard]] PSECURITY_DESCRIPTOR* address() noexcept { return &value_; }
    [[nodiscard]] PSECURITY_DESCRIPTOR get() const noexcept { return value_; }

  private:
    PSECURITY_DESCRIPTOR value_ = nullptr;
};

// A pre-existing directory is only trustworthy if SYSTEM or Administrators already owns it;
// NTFS ownership grants implicit READ_CONTROL | WRITE_DAC regardless of the DACL we stamp, so an
// attacker-owned directory can re-grant itself access no matter what ACL we apply afterwards.
[[nodiscard]] DWORD VerifyTrustedOwner(const std::wstring& path)
{
    PSID owner = nullptr;
    LocalSecurityDescriptor ownerDescriptor;
    const DWORD queryError = GetNamedSecurityInfoW(path.c_str(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &owner,
        nullptr,
        nullptr,
        nullptr,
        ownerDescriptor.address());
    if (queryError != ERROR_SUCCESS)
    {
        return queryError;
    }
    if (owner == nullptr)
    {
        return ERROR_ACCESS_DENIED;
    }

    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid {};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid {};
    DWORD systemSidSize = static_cast<DWORD>(systemSid.size());
    DWORD administratorsSidSize = static_cast<DWORD>(administratorsSid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidSize))
    {
        return GetLastError();
    }
    if (!CreateWellKnownSid(
            WinBuiltinAdministratorsSid, nullptr, administratorsSid.data(), &administratorsSidSize))
    {
        return GetLastError();
    }
    if (EqualSid(owner, systemSid.data()) || EqualSid(owner, administratorsSid.data()))
    {
        return ERROR_SUCCESS;
    }
    return ERROR_ACCESS_DENIED;
}

} // namespace

DWORD CreateSecureDirectory(std::wstring_view path)
{
    if (path.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }

    LocalSecurityDescriptor securityDescriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            RestrictedDirectoryDacl, SDDL_REVISION_1, securityDescriptor.address(), nullptr))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }
    SECURITY_ATTRIBUTES securityAttributes {};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = securityDescriptor.get();
    if (CreateDirectoryW(path.data(), &securityAttributes))
    {
        return ERROR_SUCCESS;
    }
    const DWORD createError = GetLastError();
    if (createError != ERROR_ALREADY_EXISTS)
    {
        return createError;
    }

    const std::wstring existingPath(path);
    const DWORD attributes = GetFileAttributesW(existingPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        return GetLastError();
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    {
        return ERROR_ACCESS_DENIED;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return ERROR_DIRECTORY;
    }
    const DWORD ownerError = VerifyTrustedOwner(existingPath);
    if (ownerError != ERROR_SUCCESS)
    {
        return ownerError;
    }

    if (!SetFileSecurityW(path.data(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            securityDescriptor.get()))
    {
        const DWORD securityError = GetLastError();
        return securityError;
    }
    return ERROR_SUCCESS;
}

DWORD GetBrokerDataDirectory(std::wstring& directory)
{
    directory.clear();
    const DWORD requiredCharacters = GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
    if (requiredCharacters == 0)
    {
        const DWORD environmentError = GetLastError();
        return environmentError;
    }
    std::vector<wchar_t> programData(requiredCharacters);
    const DWORD copiedCharacters = GetEnvironmentVariableW(
        L"ProgramData", programData.data(), static_cast<DWORD>(programData.size()));
    if (copiedCharacters == 0 || copiedCharacters >= programData.size())
    {
        const DWORD environmentError = GetLastError();
        return environmentError == ERROR_SUCCESS ? ERROR_ENVVAR_NOT_FOUND : environmentError;
    }
    const std::wstring root(programData.data(), copiedCharacters);
    directory = root + L"\\launch-as";
    const DWORD brokerDirectoryError = CreateSecureDirectory(directory);
    if (brokerDirectoryError != ERROR_SUCCESS)
    {
        directory.clear();
        return brokerDirectoryError;
    }
    return ERROR_SUCCESS;
}

DWORD GetBrokerEnrollmentDirectory(std::wstring& directory)
{
    const DWORD brokerDirectoryError = GetBrokerDataDirectory(directory);
    if (brokerDirectoryError != ERROR_SUCCESS)
    {
        return brokerDirectoryError;
    }
    directory += L"\\enrollments";
    const DWORD enrollmentDirectoryError = CreateSecureDirectory(directory);
    if (enrollmentDirectoryError != ERROR_SUCCESS)
    {
        directory.clear();
        return enrollmentDirectoryError;
    }
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
