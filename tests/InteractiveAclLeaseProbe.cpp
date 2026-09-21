// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Aclapi.h>
#include <Sddl.h>
#include <Windows.h>
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

struct LeaseResult final
{
    DWORD readError = ERROR_INVALID_DATA;
    DWORD addError = ERROR_INVALID_DATA;
    DWORD verifyAddError = ERROR_INVALID_DATA;
    DWORD removeError = ERROR_INVALID_DATA;
    DWORD verifyRemoveError = ERROR_INVALID_DATA;
    bool added = false;
    bool removed = false;
    bool restored = false;
};

[[nodiscard]] DWORD ReadSecurityDescriptor(HANDLE object, std::vector<BYTE>& descriptor)
{
    descriptor.clear();
    DWORD required = 0;
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION;
    GetUserObjectSecurity(object, &information, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return sizeError == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR : sizeError;
    }
    descriptor.resize(required);
    if (!GetUserObjectSecurity(object, &information, descriptor.data(), required, &required))
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD GetDacl(std::vector<BYTE>& descriptor, PACL& dacl)
{
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor.data(), &present, &dacl, &defaulted))
    {
        return GetLastError();
    }
    return present && dacl != nullptr ? ERROR_SUCCESS : ERROR_INVALID_SECURITY_DESCR;
}

[[nodiscard]] DWORD WriteDacl(HANDLE object, PACL dacl)
{
    SECURITY_DESCRIPTOR descriptor {};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION))
    {
        return GetLastError();
    }
    if (!SetSecurityDescriptorDacl(&descriptor, TRUE, dacl, FALSE))
    {
        return GetLastError();
    }
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION;
    if (!SetUserObjectSecurity(object, &information, &descriptor))
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

using AceFingerprint = std::vector<BYTE>;

[[nodiscard]] DWORD FingerprintDacl(PACL dacl, std::vector<AceFingerprint>& fingerprints)
{
    fingerprints.clear();
    ACL_SIZE_INFORMATION size {};
    if (!GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation))
    {
        return GetLastError();
    }
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(dacl, index, &rawAce))
        {
            return GetLastError();
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        const auto* bytes = static_cast<const BYTE*>(rawAce);
        fingerprints.emplace_back(bytes, bytes + header->AceSize);
    }
    std::sort(fingerprints.begin(), fingerprints.end());
    return ERROR_SUCCESS;
}

[[nodiscard]] bool IsExactLeaseAce(const void* rawAce, PSID sid, ACCESS_MASK accessMask) noexcept
{
    const auto* header = static_cast<const ACE_HEADER*>(rawAce);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0)
    {
        return false;
    }
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(rawAce);
    auto* aceSid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
    return ace->Mask == accessMask && EqualSid(aceSid, sid) != FALSE;
}

[[nodiscard]] DWORD CountLeaseAces(PACL dacl, PSID sid, ACCESS_MASK accessMask, DWORD& count)
{
    count = 0;
    ACL_SIZE_INFORMATION size {};
    if (!GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation))
    {
        return GetLastError();
    }
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(dacl, index, &rawAce))
        {
            return GetLastError();
        }
        if (IsExactLeaseAce(rawAce, sid, accessMask))
        {
            ++count;
        }
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD BuildDaclWithoutLease(
    PACL current, PSID sid, ACCESS_MASK accessMask, std::vector<BYTE>& storage)
{
    ACL_SIZE_INFORMATION size {};
    if (!GetAclInformation(current, &size, sizeof(size), AclSizeInformation))
    {
        return GetLastError();
    }
    DWORD leaseCount = 0;
    DWORD leaseBytes = 0;
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(current, index, &rawAce))
        {
            return GetLastError();
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        if (IsExactLeaseAce(rawAce, sid, accessMask))
        {
            ++leaseCount;
            leaseBytes += header->AceSize;
        }
    }
    if (leaseCount != 1 || current->AclSize <= leaseBytes)
    {
        return ERROR_INVALID_DATA;
    }

    storage.assign(current->AclSize - leaseBytes, BYTE {});
    auto* replacement = reinterpret_cast<PACL>(storage.data());
    if (!InitializeAcl(replacement, static_cast<DWORD>(storage.size()), current->AclRevision))
    {
        return GetLastError();
    }
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(current, index, &rawAce))
        {
            return GetLastError();
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        if (!IsExactLeaseAce(rawAce, sid, accessMask) &&
            !AddAce(replacement, current->AclRevision, MAXDWORD, rawAce, header->AceSize))
        {
            return GetLastError();
        }
    }
    return ERROR_SUCCESS;
}

void ExerciseLease(HANDLE object, PSID sid, ACCESS_MASK accessMask, LeaseResult& result)
{
    std::vector<BYTE> originalDescriptor;
    result.readError = ReadSecurityDescriptor(object, originalDescriptor);
    PACL originalDacl = nullptr;
    if (result.readError != ERROR_SUCCESS ||
        (result.readError = GetDacl(originalDescriptor, originalDacl)) != ERROR_SUCCESS)
    {
        return;
    }
    std::vector<AceFingerprint> originalFingerprint;
    result.readError = FingerprintDacl(originalDacl, originalFingerprint);
    if (result.readError != ERROR_SUCCESS)
    {
        return;
    }

    EXPLICIT_ACCESSW access {};
    access.grfAccessPermissions = accessMask;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid);
    PACL updatedDacl = nullptr;
    result.addError = SetEntriesInAclW(1, &access, originalDacl, &updatedDacl);
    if (result.addError != ERROR_SUCCESS)
    {
        return;
    }
    result.addError = WriteDacl(object, updatedDacl);
    LocalFree(updatedDacl);
    if (result.addError != ERROR_SUCCESS)
    {
        return;
    }

    std::vector<BYTE> leasedDescriptor;
    result.verifyAddError = ReadSecurityDescriptor(object, leasedDescriptor);
    PACL leasedDacl = nullptr;
    DWORD leaseCount = 0;
    if (result.verifyAddError == ERROR_SUCCESS)
    {
        result.verifyAddError = GetDacl(leasedDescriptor, leasedDacl);
    }
    if (result.verifyAddError == ERROR_SUCCESS)
    {
        result.verifyAddError = CountLeaseAces(leasedDacl, sid, accessMask, leaseCount);
    }
    result.added = result.verifyAddError == ERROR_SUCCESS && leaseCount == 1;

    std::vector<BYTE> cleanupDescriptor;
    result.removeError = ReadSecurityDescriptor(object, cleanupDescriptor);
    PACL cleanupDacl = nullptr;
    if (result.removeError == ERROR_SUCCESS)
    {
        result.removeError = GetDacl(cleanupDescriptor, cleanupDacl);
    }
    std::vector<BYTE> withoutLease;
    if (result.removeError == ERROR_SUCCESS)
    {
        result.removeError = BuildDaclWithoutLease(cleanupDacl, sid, accessMask, withoutLease);
    }
    if (result.removeError == ERROR_SUCCESS)
    {
        result.removeError = WriteDacl(object, reinterpret_cast<PACL>(withoutLease.data()));
    }
    if (result.removeError != ERROR_SUCCESS)
    {
        return;
    }

    std::vector<BYTE> finalDescriptor;
    result.verifyRemoveError = ReadSecurityDescriptor(object, finalDescriptor);
    PACL finalDacl = nullptr;
    DWORD finalLeaseCount = 0;
    std::vector<AceFingerprint> finalFingerprint;
    if (result.verifyRemoveError == ERROR_SUCCESS)
    {
        result.verifyRemoveError = GetDacl(finalDescriptor, finalDacl);
    }
    if (result.verifyRemoveError == ERROR_SUCCESS)
    {
        result.verifyRemoveError = CountLeaseAces(finalDacl, sid, accessMask, finalLeaseCount);
    }
    if (result.verifyRemoveError == ERROR_SUCCESS)
    {
        result.verifyRemoveError = FingerprintDacl(finalDacl, finalFingerprint);
    }
    result.removed = result.verifyRemoveError == ERROR_SUCCESS && finalLeaseCount == 0;
    result.restored = result.removed && originalFingerprint == finalFingerprint;
}

[[nodiscard]] std::wstring ReadObjectName(HANDLE object)
{
    DWORD required = 0;
    GetUserObjectInformationW(object, UOI_NAME, nullptr, 0, &required);
    if (required == 0)
    {
        return {};
    }
    std::vector<wchar_t> name((required + sizeof(wchar_t) - 1) / sizeof(wchar_t));
    if (!GetUserObjectInformationW(object, UOI_NAME, name.data(), required, &required))
    {
        return {};
    }
    return name.data();
}

[[nodiscard]] std::wstring ReadTokenUserSid(HANDLE token, DWORD& error)
{
    DWORD required = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return {};
    }
    std::vector<BYTE> storage(required);
    if (!GetTokenInformation(token, TokenUser, storage.data(), required, &required))
    {
        error = GetLastError();
        return {};
    }
    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(storage.data());
    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidText))
    {
        error = GetLastError();
        return {};
    }
    std::wstring result(sidText);
    LocalFree(sidText);
    error = ERROR_SUCCESS;
    return result;
}

[[nodiscard]] std::string NarrowAscii(std::wstring_view value)
{
    std::string result;
    result.reserve(value.size());
    for (const wchar_t character : value)
    {
        result.push_back(character <= 0x7f ? static_cast<char>(character) : '?');
    }
    return result;
}

[[nodiscard]] bool LeaseSucceeded(const LeaseResult& result) noexcept
{
    return result.readError == ERROR_SUCCESS && result.addError == ERROR_SUCCESS &&
           result.verifyAddError == ERROR_SUCCESS && result.removeError == ERROR_SUCCESS &&
           result.verifyRemoveError == ERROR_SUCCESS && result.added && result.removed &&
           result.restored;
}

void WriteLease(std::ofstream& output, std::string_view name, const LeaseResult& result)
{
    output << name << "ReadError=" << result.readError << '\n';
    output << name << "AddError=" << result.addError << '\n';
    output << name << "VerifyAddError=" << result.verifyAddError << '\n';
    output << name << "RemoveError=" << result.removeError << '\n';
    output << name << "VerifyRemoveError=" << result.verifyRemoveError << '\n';
    output << name << "LeaseAdded=" << (result.added ? "true" : "false") << '\n';
    output << name << "LeaseRemoved=" << (result.removed ? "true" : "false") << '\n';
    output << name << "DaclSemanticallyRestored=" << (result.restored ? "true" : "false") << '\n';
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 2)
    {
        return ERROR_INVALID_PARAMETER;
    }

    DWORD processSessionId = MAXDWORD;
    const BOOL readSession = ProcessIdToSessionId(GetCurrentProcessId(), &processSessionId);
    const DWORD sessionError = readSession ? ERROR_SUCCESS : GetLastError();

    HANDLE rawToken = nullptr;
    const BOOL openedToken = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken);
    const DWORD tokenError = openedToken ? ERROR_SUCCESS : GetLastError();
    TOKEN_ELEVATION elevation {};
    DWORD elevationBytes = 0;
    DWORD elevationError = tokenError;
    DWORD tokenUserError = tokenError;
    std::wstring tokenUserSid;
    BOOL isAdministrator = FALSE;
    DWORD administratorError = tokenError;
    if (openedToken)
    {
        tokenUserSid = ReadTokenUserSid(rawToken, tokenUserError);
        const BOOL readElevation = GetTokenInformation(
            rawToken, TokenElevation, &elevation, sizeof(elevation), &elevationBytes);
        elevationError = readElevation ? ERROR_SUCCESS : GetLastError();
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        PSID administrators = nullptr;
        if (!AllocateAndInitializeSid(&ntAuthority,
                2,
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                0,
                0,
                0,
                0,
                0,
                0,
                &administrators))
        {
            administratorError = GetLastError();
        }
        else
        {
            const BOOL checked = CheckTokenMembership(nullptr, administrators, &isAdministrator);
            administratorError = checked ? ERROR_SUCCESS : GetLastError();
            FreeSid(administrators);
        }
        CloseHandle(rawToken);
    }

    HWINSTA processWindowStation = GetProcessWindowStation();
    const DWORD processWindowStationError =
        processWindowStation != nullptr ? ERROR_SUCCESS : GetLastError();
    const std::wstring processWindowStationName =
        processWindowStation != nullptr ? ReadObjectName(processWindowStation) : std::wstring {};

    constexpr ACCESS_MASK windowStationMask = WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES;
    constexpr ACCESS_MASK desktopMask = DESKTOP_ENUMERATE | DESKTOP_READOBJECTS;
    HWINSTA windowStation = OpenWindowStationW(L"WinSta0", FALSE, READ_CONTROL | WRITE_DAC);
    const DWORD openWindowStationError = windowStation != nullptr ? ERROR_SUCCESS : GetLastError();
    HDESK desktop = OpenDesktopW(L"Default",
        0,
        FALSE,
        READ_CONTROL | WRITE_DAC | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
    const DWORD openDesktopError = desktop != nullptr ? ERROR_SUCCESS : GetLastError();

    const DWORD tick = static_cast<DWORD>(GetTickCount64());
    const std::wstring leaseSidText = L"S-1-5-5-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                      std::to_wstring(tick == 0 ? 1 : tick);
    PSID leaseSid = nullptr;
    const BOOL convertedSid = ConvertStringSidToSidW(leaseSidText.c_str(), &leaseSid);
    const DWORD sidError = convertedSid ? ERROR_SUCCESS : GetLastError();

    LeaseResult windowStationLease;
    LeaseResult desktopLease;
    if (leaseSid != nullptr && windowStation != nullptr)
    {
        ExerciseLease(windowStation, leaseSid, windowStationMask, windowStationLease);
    }
    if (leaseSid != nullptr && desktop != nullptr)
    {
        ExerciseLease(desktop, leaseSid, desktopMask, desktopLease);
    }
    if (leaseSid != nullptr)
    {
        LocalFree(leaseSid);
    }
    if (desktop != nullptr)
    {
        CloseDesktop(desktop);
    }
    if (windowStation != nullptr)
    {
        CloseWindowStation(windowStation);
    }

    std::ofstream output(std::filesystem::path(arguments[1]), std::ios::binary | std::ios::trunc);
    if (!output)
    {
        return ERROR_OPEN_FAILED;
    }
    output << "processSessionId=" << processSessionId << '\n';
    output << "sessionError=" << sessionError << '\n';
    output << "processWindowStation=" << NarrowAscii(processWindowStationName) << '\n';
    output << "processWindowStationError=" << processWindowStationError << '\n';
    output << "tokenError=" << tokenError << '\n';
    output << "tokenUserError=" << tokenUserError << '\n';
    output << "callerSid=" << NarrowAscii(tokenUserSid) << '\n';
    output << "elevationError=" << elevationError << '\n';
    output << "administratorError=" << administratorError << '\n';
    output << "callerElevated=" << (elevation.TokenIsElevated != 0 ? "true" : "false") << '\n';
    output << "callerIsAdministrator=" << (isAdministrator ? "true" : "false") << '\n';
    output << "openWindowStationError=" << openWindowStationError << '\n';
    output << "openDesktopError=" << openDesktopError << '\n';
    output << "leaseSid=" << NarrowAscii(leaseSidText) << '\n';
    output << "sidError=" << sidError << '\n';
    WriteLease(output, "windowStation", windowStationLease);
    WriteLease(output, "desktop", desktopLease);
    const bool restored = windowStationLease.restored && desktopLease.restored;
    output << "daclSemanticallyRestored=" << (restored ? "true" : "false") << '\n';

    const bool success = sessionError == ERROR_SUCCESS && processSessionId != 0 &&
                         _wcsicmp(processWindowStationName.c_str(), L"WinSta0") == 0 &&
                         tokenError == ERROR_SUCCESS && tokenUserError == ERROR_SUCCESS &&
                         !tokenUserSid.empty() && elevationError == ERROR_SUCCESS &&
                         administratorError == ERROR_SUCCESS && elevation.TokenIsElevated == 0 &&
                         !isAdministrator && openWindowStationError == ERROR_SUCCESS &&
                         openDesktopError == ERROR_SUCCESS && sidError == ERROR_SUCCESS &&
                         LeaseSucceeded(windowStationLease) && LeaseSucceeded(desktopLease);
    output << "probeSucceeded=" << (success ? "true" : "false") << '\n';
    output.flush();
    const bool outputSucceeded = output.good();
    output.close();
    return outputSucceeded && success ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}
