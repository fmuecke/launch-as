// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerServiceInstaller.h"

#include <Aclapi.h>
#include <ShlObj.h>
#include <array>
#include <sddl.h>
#include <string>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr wchar_t BrokerInstallDirectoryName[] = L"launch-as";
constexpr wchar_t BrokerExecutableName[] = L"launch-as-broker.exe";
constexpr wchar_t BrokerInstallDacl[] = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200A9;;;BU)";

class ServiceHandle final
{
  public:
    explicit ServiceHandle(SC_HANDLE value = nullptr) noexcept : value_(value) {}
    ~ServiceHandle()
    {
        if (value_ != nullptr)
        {
            CloseServiceHandle(value_);
        }
    }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }

  private:
    SC_HANDLE value_;
};

class LocalAcl final
{
  public:
    ~LocalAcl()
    {
        if (value_ != nullptr)
        {
            LocalFree(value_);
        }
    }

    [[nodiscard]] PACL* address() noexcept { return &value_; }
    [[nodiscard]] PACL get() const noexcept { return value_; }

  private:
    PACL value_ = nullptr;
};

class LocalSecurityDescriptor final
{
  public:
    ~LocalSecurityDescriptor()
    {
        if (value_ != nullptr)
        {
            LocalFree(value_);
        }
    }

    [[nodiscard]] PSECURITY_DESCRIPTOR* address() noexcept { return &value_; }
    [[nodiscard]] PSECURITY_DESCRIPTOR get() const noexcept { return value_; }

  private:
    PSECURITY_DESCRIPTOR value_ = nullptr;
};

[[nodiscard]] DWORD CreateBrokerInstallSecurityDescriptor(LocalSecurityDescriptor& descriptor)
{
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            BrokerInstallDacl, SDDL_REVISION_1, descriptor.address(), nullptr))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD SetBrokerInstallSecurity(std::wstring_view path)
{
    LocalSecurityDescriptor descriptor;
    const DWORD descriptorError = CreateBrokerInstallSecurityDescriptor(descriptor);
    if (descriptorError != ERROR_SUCCESS)
    {
        return descriptorError;
    }
    if (!SetFileSecurityW(path.data(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.get()))
    {
        const DWORD securityError = GetLastError();
        return securityError;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD CreateOrSecureBrokerInstallDirectory(std::wstring_view path)
{
    LocalSecurityDescriptor descriptor;
    const DWORD descriptorError = CreateBrokerInstallSecurityDescriptor(descriptor);
    if (descriptorError != ERROR_SUCCESS)
    {
        return descriptorError;
    }
    SECURITY_ATTRIBUTES securityAttributes {};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = descriptor.get();
    if (CreateDirectoryW(path.data(), &securityAttributes))
    {
        return ERROR_SUCCESS;
    }
    const DWORD createError = GetLastError();
    if (createError != ERROR_ALREADY_EXISTS)
    {
        return createError;
    }
    const DWORD attributes = GetFileAttributesW(path.data());
    const DWORD attributesError =
        attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        return attributesError;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return ERROR_DIRECTORY;
    }
    if (!SetFileSecurityW(path.data(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.get()))
    {
        const DWORD securityError = GetLastError();
        return securityError;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD GetCurrentExecutablePath(std::wstring& path)
{
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;)
    {
        const DWORD copiedCharacters =
            GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (copiedCharacters == 0)
        {
            const DWORD moduleError = GetLastError();
            return moduleError;
        }
        if (copiedCharacters < buffer.size() - 1)
        {
            path.assign(buffer.data(), copiedCharacters);
            return ERROR_SUCCESS;
        }
        if (buffer.size() >= 32'768)
        {
            return ERROR_BUFFER_OVERFLOW;
        }
        buffer.resize(buffer.size() * 2);
    }
}

[[nodiscard]] DWORD GetBrokerInstallDirectory(std::wstring& directory)
{
    PWSTR programFiles = nullptr;
    const HRESULT result =
        SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, nullptr, &programFiles);
    if (FAILED(result))
    {
        return HRESULT_CODE(result) == ERROR_SUCCESS ? ERROR_GEN_FAILURE : HRESULT_CODE(result);
    }
    directory = std::wstring(programFiles) + L"\\" + BrokerInstallDirectoryName;
    CoTaskMemFree(programFiles);
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD GetCallerSid(std::vector<BYTE>& sid)
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        const DWORD tokenError = GetLastError();
        return tokenError;
    }
    DWORD requiredBytes = 0;
    GetTokenInformation(rawToken, TokenUser, nullptr, 0, &requiredBytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || requiredBytes == 0)
    {
        CloseHandle(rawToken);
        return sizeError;
    }
    std::vector<BYTE> tokenUserBuffer(requiredBytes);
    if (!GetTokenInformation(
            rawToken, TokenUser, tokenUserBuffer.data(), requiredBytes, &requiredBytes))
    {
        const DWORD userError = GetLastError();
        CloseHandle(rawToken);
        return userError;
    }
    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenUserBuffer.data());
    if (!IsValidSid(tokenUser->User.Sid))
    {
        CloseHandle(rawToken);
        return ERROR_INVALID_SID;
    }
    const DWORD sidSize = GetLengthSid(tokenUser->User.Sid);
    sid.resize(sidSize);
    if (!CopySid(sidSize, sid.data(), tokenUser->User.Sid))
    {
        const DWORD copyError = GetLastError();
        CloseHandle(rawToken);
        return copyError;
    }
    CloseHandle(rawToken);
    return ERROR_SUCCESS;
}

} // namespace

DWORD InstallBrokerService()
{
    std::wstring sourcePath;
    const DWORD sourceError = GetCurrentExecutablePath(sourcePath);
    if (sourceError != ERROR_SUCCESS)
    {
        return sourceError;
    }
    std::wstring installDirectory;
    const DWORD directoryPathError = GetBrokerInstallDirectory(installDirectory);
    if (directoryPathError != ERROR_SUCCESS)
    {
        return directoryPathError;
    }
    const DWORD directoryError = CreateOrSecureBrokerInstallDirectory(installDirectory);
    if (directoryError != ERROR_SUCCESS)
    {
        return directoryError;
    }
    const std::wstring installedPath = installDirectory + L"\\" + BrokerExecutableName;
    if (CompareStringOrdinal(sourcePath.c_str(),
            static_cast<int>(sourcePath.size()),
            installedPath.c_str(),
            static_cast<int>(installedPath.size()),
            TRUE) != CSTR_EQUAL)
    {
        if (!CopyFileW(sourcePath.c_str(), installedPath.c_str(), FALSE))
        {
            const DWORD copyError = GetLastError();
            return copyError;
        }
    }
    const DWORD securityError = SetBrokerInstallSecurity(installedPath);
    if (securityError != ERROR_SUCCESS)
    {
        return securityError;
    }
    return InstallDemandStartBrokerService(L"launch-as-broker", installedPath);
}

DWORD InstallDemandStartBrokerService(
    std::wstring_view serviceName, std::wstring_view executablePath)
{
    if (serviceName.empty() || executablePath.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    const std::wstring name(serviceName);
    const std::wstring path(executablePath);
    const DWORD attributes = GetFileAttributesW(path.c_str());
    const DWORD attributeError =
        attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        return attributes == INVALID_FILE_ATTRIBUTES ? attributeError : ERROR_INVALID_PARAMETER;
    }

    std::vector<BYTE> callerSid;
    const DWORD callerError = GetCallerSid(callerSid);
    if (callerError != ERROR_SUCCESS)
    {
        return callerError;
    }
    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid {};
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid {};
    DWORD systemSidSize = static_cast<DWORD>(systemSid.size());
    DWORD administratorsSidSize = static_cast<DWORD>(administratorsSid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidSize))
    {
        const DWORD sidError = GetLastError();
        return sidError;
    }
    if (!CreateWellKnownSid(
            WinBuiltinAdministratorsSid, nullptr, administratorsSid.data(), &administratorsSidSize))
    {
        const DWORD sidError = GetLastError();
        return sidError;
    }

    std::array<EXPLICIT_ACCESSW, 3> entries {};
    const std::array<PSID, 3> sids {systemSid.data(), administratorsSid.data(), callerSid.data()};
    const std::array<DWORD, 3> rights {SERVICE_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_START};
    for (std::size_t index = 0; index < entries.size(); ++index)
    {
        entries[index].grfAccessPermissions = rights[index];
        entries[index].grfAccessMode = GRANT_ACCESS;
        entries[index].grfInheritance = NO_INHERITANCE;
        entries[index].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entries[index].Trustee.ptstrName = reinterpret_cast<LPWSTR>(sids[index]);
    }
    LocalAcl acl;
    const DWORD aclError = SetEntriesInAclW(
        static_cast<ULONG>(entries.size()), entries.data(), nullptr, acl.address());
    if (aclError != ERROR_SUCCESS)
    {
        return aclError;
    }
    SECURITY_DESCRIPTOR descriptor {};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }
    if (!SetSecurityDescriptorDacl(&descriptor, TRUE, acl.get(), FALSE))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }

    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!manager)
    {
        const DWORD managerError = GetLastError();
        return managerError;
    }
    const std::wstring commandLine = L"\"" + path + L"\"";
    SC_HANDLE rawService = CreateServiceW(manager.get(),
        name.c_str(),
        name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        commandLine.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);
    bool created = rawService != nullptr;
    if (rawService == nullptr)
    {
        const DWORD serviceError = GetLastError();
        if (serviceError != ERROR_SERVICE_EXISTS)
        {
            return serviceError;
        }
        rawService = OpenServiceW(manager.get(), name.c_str(), SERVICE_CHANGE_CONFIG | WRITE_DAC);
        if (rawService == nullptr)
        {
            const DWORD openError = GetLastError();
            return openError;
        }
    }
    ServiceHandle service(rawService);
    if (!created && !ChangeServiceConfigW(service.get(),
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_DEMAND_START,
                        SERVICE_ERROR_NORMAL,
                        commandLine.c_str(),
                        nullptr,
                        nullptr,
                        nullptr,
                        L"LocalSystem",
                        nullptr,
                        name.c_str()))
    {
        const DWORD configurationError = GetLastError();
        return configurationError;
    }
    if (!SetServiceObjectSecurity(service.get(), DACL_SECURITY_INFORMATION, &descriptor))
    {
        const DWORD securityError = GetLastError();
        if (created)
        {
            DeleteService(service.get());
        }
        return securityError;
    }
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
