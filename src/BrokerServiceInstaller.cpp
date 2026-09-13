// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerServiceInstaller.h"

#include "BrokerAudit.h"
#include "BrokerCallerPolicy.h"
#include "BrokerDataDirectory.h"
#include "Win32Support.h"

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
constexpr wchar_t BrokerConhostExecutableName[] = L"launch-as-conhost.exe";
constexpr wchar_t BrokerServiceDisplayName[] = L"launch-as Broker";
constexpr wchar_t BrokerServiceDescription[] =
    L"Launches managed accounts in isolated console sessions.";
constexpr wchar_t BrokerInstallDacl[] = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200A9;;;BU)";
constexpr wchar_t BrokerRequiredPrivileges[] =
    L"SeAssignPrimaryTokenPrivilege\0SeIncreaseQuotaPrivilege\0SeImpersonatePrivilege\0\0";
constexpr DWORD ServiceStopTimeoutMilliseconds = 10'000;

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

using LocalAcl = launch_as::LocalAllocation<PACL>;
using LocalSecurityDescriptor = launch_as::LocalAllocation<PSECURITY_DESCRIPTOR>;

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
    const std::wstring installPath(path);
    LocalSecurityDescriptor descriptor;
    const DWORD descriptorError = CreateBrokerInstallSecurityDescriptor(descriptor);
    if (descriptorError != ERROR_SUCCESS)
    {
        return descriptorError;
    }
    if (!SetFileSecurityW(installPath.c_str(),
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
    const std::wstring installPath(path);
    LocalSecurityDescriptor descriptor;
    const DWORD descriptorError = CreateBrokerInstallSecurityDescriptor(descriptor);
    if (descriptorError != ERROR_SUCCESS)
    {
        return descriptorError;
    }
    SECURITY_ATTRIBUTES securityAttributes {};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = descriptor.get();
    if (CreateDirectoryW(installPath.c_str(), &securityAttributes))
    {
        return ERROR_SUCCESS;
    }
    const DWORD createError = GetLastError();
    if (createError != ERROR_ALREADY_EXISTS)
    {
        return createError;
    }
    const DWORD attributes = GetFileAttributesW(installPath.c_str());
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
    if (!SetFileSecurityW(installPath.c_str(),
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

[[nodiscard]] DWORD GetSiblingExecutablePath(
    std::wstring_view executablePath, std::wstring_view siblingName, std::wstring& siblingPath)
{
    siblingPath.clear();
    const std::size_t separator = executablePath.find_last_of(L"\\/");
    if (separator == std::wstring_view::npos || siblingName.empty())
    {
        return ERROR_BAD_PATHNAME;
    }
    siblingPath = std::wstring(executablePath.substr(0, separator + 1));
    siblingPath += siblingName;
    const DWORD attributes = GetFileAttributesW(siblingPath.c_str());
    const DWORD attributeError =
        attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        siblingPath.clear();
        return attributes == INVALID_FILE_ATTRIBUTES ? attributeError : ERROR_FILE_NOT_FOUND;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD CopyAndSecureInstallFile(
    std::wstring_view sourcePath, std::wstring_view installedPath)
{
    const std::wstring source(sourcePath);
    const std::wstring installed(installedPath);
    if (CompareStringOrdinal(sourcePath.data(),
            static_cast<int>(sourcePath.size()),
            installedPath.data(),
            static_cast<int>(installedPath.size()),
            TRUE) != CSTR_EQUAL)
    {
        if (!CopyFileW(source.c_str(), installed.c_str(), FALSE))
        {
            const DWORD copyError = GetLastError();
            return copyError;
        }
    }
    return SetBrokerInstallSecurity(installed);
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

[[nodiscard]] DWORD StopServiceAndWait(SC_HANDLE service)
{
    SERVICE_STATUS status {};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
    {
        const DWORD stopError = GetLastError();
        if (stopError != ERROR_SERVICE_NOT_ACTIVE)
        {
            return stopError;
        }
    }
    const ULONGLONG deadline = GetTickCount64() + ServiceStopTimeoutMilliseconds;
    for (;;)
    {
        SERVICE_STATUS_PROCESS processStatus {};
        DWORD returnedBytes = 0;
        if (!QueryServiceStatusEx(service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&processStatus),
                sizeof(processStatus),
                &returnedBytes))
        {
            const DWORD statusError = GetLastError();
            return statusError;
        }
        if (processStatus.dwCurrentState == SERVICE_STOPPED)
        {
            return ERROR_SUCCESS;
        }
        if (GetTickCount64() >= deadline)
        {
            return ERROR_TIMEOUT;
        }
        Sleep(100);
    }
}

} // namespace

DWORD InstallBrokerService()
{
    const DWORD stopError = StopBrokerService();
    if (stopError != ERROR_SUCCESS)
    {
        return stopError;
    }
    std::vector<BYTE> callerSid;
    const DWORD callerError = GetCallerSid(callerSid);
    if (callerError != ERROR_SUCCESS)
    {
        return callerError;
    }
    std::wstring adminPath;
    const DWORD sourceError = GetCurrentExecutablePath(adminPath);
    if (sourceError != ERROR_SUCCESS)
    {
        return sourceError;
    }
    std::wstring sourceBrokerPath;
    const DWORD sourceBrokerError =
        GetSiblingExecutablePath(adminPath, BrokerExecutableName, sourceBrokerPath);
    if (sourceBrokerError != ERROR_SUCCESS)
    {
        return sourceBrokerError;
    }
    std::wstring sourceConhostPath;
    const DWORD sourceConhostError =
        GetSiblingExecutablePath(adminPath, BrokerConhostExecutableName, sourceConhostPath);
    if (sourceConhostError != ERROR_SUCCESS)
    {
        return sourceConhostError;
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
    const DWORD brokerCopyError = CopyAndSecureInstallFile(sourceBrokerPath, installedPath);
    if (brokerCopyError != ERROR_SUCCESS)
    {
        return brokerCopyError;
    }
    const std::wstring installedConhostPath =
        installDirectory + L"\\" + BrokerConhostExecutableName;
    const DWORD conhostCopyError =
        CopyAndSecureInstallFile(sourceConhostPath, installedConhostPath);
    if (conhostCopyError != ERROR_SUCCESS)
    {
        return conhostCopyError;
    }
    const DWORD serviceError = InstallDemandStartBrokerService(L"launch-as-broker", installedPath);
    if (serviceError != ERROR_SUCCESS)
    {
        return serviceError;
    }
    const DWORD eventSourceError = RegisterBrokerEventSource();
    if (eventSourceError != ERROR_SUCCESS)
    {
        return eventSourceError;
    }
    std::wstring dataDirectory;
    const DWORD dataDirectoryError = GetBrokerDataDirectory(dataDirectory);
    if (dataDirectoryError != ERROR_SUCCESS)
    {
        return dataDirectoryError;
    }
    return StoreAuthorizedCallerSid(GetAuthorizedCallerPolicyPath(dataDirectory), callerSid.data());
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
        BrokerServiceDisplayName,
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
                        BrokerServiceDisplayName))
    {
        const DWORD configurationError = GetLastError();
        return configurationError;
    }
    SERVICE_SID_INFO serviceSidInfo {};
    serviceSidInfo.dwServiceSidType = SERVICE_SID_TYPE_RESTRICTED;
    if (!ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_SERVICE_SID_INFO, &serviceSidInfo))
    {
        const DWORD serviceSidError = GetLastError();
        if (created)
        {
            DeleteService(service.get());
        }
        return serviceSidError;
    }
    SERVICE_REQUIRED_PRIVILEGES_INFOW requiredPrivileges {};
    requiredPrivileges.pmszRequiredPrivileges = const_cast<LPWSTR>(BrokerRequiredPrivileges);
    if (!ChangeServiceConfig2W(
            service.get(), SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &requiredPrivileges))
    {
        const DWORD privilegesError = GetLastError();
        if (created)
        {
            DeleteService(service.get());
        }
        return privilegesError;
    }
    SERVICE_DESCRIPTIONW description {};
    description.lpDescription = const_cast<LPWSTR>(BrokerServiceDescription);
    if (!ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, &description))
    {
        const DWORD descriptionError = GetLastError();
        if (created)
        {
            DeleteService(service.get());
        }
        return descriptionError;
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

DWORD UninstallBrokerService()
{
    const DWORD serviceError = UninstallDemandStartBrokerService(L"launch-as-broker");
    if (serviceError != ERROR_SUCCESS)
    {
        return serviceError;
    }
    const DWORD eventSourceError = UnregisterBrokerEventSource();
    if (eventSourceError != ERROR_SUCCESS)
    {
        return eventSourceError;
    }
    std::wstring installDirectory;
    const DWORD directoryError = GetBrokerInstallDirectory(installDirectory);
    if (directoryError != ERROR_SUCCESS)
    {
        return directoryError;
    }
    return RemoveBrokerInstallFiles(installDirectory);
}

DWORD StopBrokerService()
{
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager)
    {
        const DWORD managerError = GetLastError();
        return managerError;
    }
    ServiceHandle service(
        OpenServiceW(manager.get(), L"launch-as-broker", SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!service)
    {
        const DWORD serviceError = GetLastError();
        return serviceError == ERROR_SERVICE_DOES_NOT_EXIST ? ERROR_SUCCESS : serviceError;
    }
    return StopServiceAndWait(service.get());
}

DWORD RemoveBrokerInstallFiles(std::wstring_view installDirectory)
{
    if (installDirectory.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    const std::wstring directory(installDirectory);
    const DWORD attributes = GetFileAttributesW(directory.c_str());
    const DWORD attributesError =
        attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        return attributesError == ERROR_FILE_NOT_FOUND || attributesError == ERROR_PATH_NOT_FOUND
                   ? ERROR_SUCCESS
                   : attributesError;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return ERROR_DIRECTORY;
    }

    for (const wchar_t* fileName : {BrokerExecutableName, BrokerConhostExecutableName})
    {
        const std::wstring path = directory + L"\\" + fileName;
        if (!DeleteFileW(path.c_str()))
        {
            const DWORD deleteError = GetLastError();
            if (deleteError != ERROR_FILE_NOT_FOUND)
            {
                return deleteError;
            }
        }
    }
    if (RemoveDirectoryW(directory.c_str()))
    {
        return ERROR_SUCCESS;
    }
    const DWORD removeError = GetLastError();
    return removeError == ERROR_DIR_NOT_EMPTY || removeError == ERROR_PATH_NOT_FOUND ? ERROR_SUCCESS
                                                                                     : removeError;
}

DWORD UninstallDemandStartBrokerService(std::wstring_view serviceName)
{
    if (serviceName.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    const std::wstring name(serviceName);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager)
    {
        const DWORD managerError = GetLastError();
        return managerError;
    }
    ServiceHandle service(
        OpenServiceW(manager.get(), name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!service)
    {
        const DWORD serviceError = GetLastError();
        return serviceError == ERROR_SERVICE_DOES_NOT_EXIST ? ERROR_SUCCESS : serviceError;
    }
    const DWORD stopError = StopServiceAndWait(service.get());
    if (stopError != ERROR_SUCCESS)
    {
        return stopError;
    }
    if (!DeleteService(service.get()))
    {
        const DWORD deleteError = GetLastError();
        return deleteError == ERROR_SERVICE_MARKED_FOR_DELETE ? ERROR_SUCCESS : deleteError;
    }
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
