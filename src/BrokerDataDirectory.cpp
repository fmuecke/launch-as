// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerDataDirectory.h"

#include "Win32Support.h"

#include <Aclapi.h>
#include <ShlObj.h>
#include <array>
#include <string>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr wchar_t BrokerServiceAccountName[] = L"NT SERVICE\\launch-as-broker";

using LocalSecurityDescriptor = launch_as::LocalAllocation<PSECURITY_DESCRIPTOR>;
using LocalAcl = launch_as::LocalAllocation<PACL>;

[[nodiscard]] DWORD LookupBrokerServiceSid(std::vector<BYTE>& sid)
{
    sid.clear();
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE use = {};
    if (LookupAccountNameW(
            nullptr, BrokerServiceAccountName, nullptr, &sidSize, nullptr, &domainSize, &use))
    {
        return ERROR_INVALID_DATA;
    }
    const DWORD lookupError = GetLastError();
    if (lookupError == ERROR_NONE_MAPPED)
    {
        return ERROR_SUCCESS;
    }
    if (lookupError != ERROR_INSUFFICIENT_BUFFER || sidSize == 0)
    {
        return lookupError;
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
        const DWORD retryError = GetLastError();
        sid.clear();
        return retryError;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD CreateDirectorySecurityDescriptor(
    PSID serviceSid, LocalAcl& dacl, SECURITY_DESCRIPTOR& descriptor)
{
    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid {};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid {};
    DWORD systemSidSize = static_cast<DWORD>(systemSid.size());
    DWORD administratorsSidSize = static_cast<DWORD>(administratorsSid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidSize))
    {
        const DWORD systemSidError = GetLastError();
        return systemSidError;
    }
    if (!CreateWellKnownSid(
            WinBuiltinAdministratorsSid, nullptr, administratorsSid.data(), &administratorsSidSize))
    {
        const DWORD administratorsSidError = GetLastError();
        return administratorsSidError;
    }

    std::array<EXPLICIT_ACCESSW, 3> entries {};
    const std::array<PSID, 3> sids {systemSid.data(), administratorsSid.data(), serviceSid};
    const std::size_t entryCount = serviceSid == nullptr ? 2 : 3;
    for (std::size_t index = 0; index < entryCount; ++index)
    {
        entries[index].grfAccessPermissions = FILE_ALL_ACCESS;
        entries[index].grfAccessMode = GRANT_ACCESS;
        entries[index].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        entries[index].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entries[index].Trustee.ptstrName = reinterpret_cast<LPWSTR>(sids[index]);
    }
    const DWORD daclError =
        SetEntriesInAclW(static_cast<ULONG>(entryCount), entries.data(), nullptr, dacl.address());
    if (daclError != ERROR_SUCCESS)
    {
        return daclError;
    }
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }
    if (!SetSecurityDescriptorDacl(&descriptor, TRUE, dacl.get(), FALSE))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }
    if (!SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }
    return ERROR_SUCCESS;
}

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
    const std::wstring directoryPath(path);

    std::vector<BYTE> serviceSid;
    const DWORD serviceSidError = LookupBrokerServiceSid(serviceSid);
    if (serviceSidError != ERROR_SUCCESS)
    {
        return serviceSidError;
    }
    SECURITY_DESCRIPTOR securityDescriptor {};
    LocalAcl dacl;
    const DWORD descriptorError = CreateDirectorySecurityDescriptor(
        serviceSid.empty() ? nullptr : serviceSid.data(), dacl, securityDescriptor);
    if (descriptorError != ERROR_SUCCESS)
    {
        return descriptorError;
    }
    SECURITY_ATTRIBUTES securityAttributes {};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = &securityDescriptor;
    if (CreateDirectoryW(directoryPath.c_str(), &securityAttributes))
    {
        return ERROR_SUCCESS;
    }
    const DWORD createError = GetLastError();
    if (createError != ERROR_ALREADY_EXISTS)
    {
        return createError;
    }

    const DWORD attributes = GetFileAttributesW(directoryPath.c_str());
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
    const DWORD ownerError = VerifyTrustedOwner(directoryPath);
    if (ownerError != ERROR_SUCCESS)
    {
        return ownerError;
    }

    if (!SetFileSecurityW(directoryPath.c_str(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            &securityDescriptor))
    {
        const DWORD securityError = GetLastError();
        return securityError;
    }
    return ERROR_SUCCESS;
}

DWORD GetBrokerDataDirectoryPath(std::wstring& directory)
{
    directory.clear();
    PWSTR programData = nullptr;
    const HRESULT result =
        SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &programData);
    if (FAILED(result))
    {
        return HRESULT_CODE(result) == ERROR_SUCCESS ? ERROR_GEN_FAILURE : HRESULT_CODE(result);
    }
    directory = std::wstring(programData) + L"\\launch-as";
    CoTaskMemFree(programData);
    return ERROR_SUCCESS;
}

DWORD GetBrokerDataDirectory(std::wstring& directory)
{
    const DWORD directoryPathError = GetBrokerDataDirectoryPath(directory);
    if (directoryPathError != ERROR_SUCCESS)
    {
        return directoryPathError;
    }
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
