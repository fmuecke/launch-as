// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerDataDirectory.h"

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

DWORD GetBrokerCredentialDirectory(std::wstring& directory)
{
    const DWORD brokerDirectoryError = GetBrokerDataDirectory(directory);
    if (brokerDirectoryError != ERROR_SUCCESS)
    {
        return brokerDirectoryError;
    }
    directory += L"\\credentials";
    const DWORD credentialDirectoryError = CreateSecureDirectory(directory);
    if (credentialDirectoryError != ERROR_SUCCESS)
    {
        directory.clear();
        return credentialDirectoryError;
    }
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
