// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "InteractiveDesktopAclLease.h"

#include <Sddl.h>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

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

[[nodiscard]] DWORD ReadDaclSddl(HANDLE object, std::wstring& value)
{
    value.clear();
    DWORD required = 0;
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION;
    GetUserObjectSecurity(object, &information, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return sizeError == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR : sizeError;
    }
    std::vector<BYTE> descriptor(required);
    if (!GetUserObjectSecurity(object, &information, descriptor.data(), required, &required))
    {
        return GetLastError();
    }
    LPWSTR rawSddl = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.data(), SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &rawSddl, nullptr))
    {
        return GetLastError();
    }
    value = rawSddl;
    LocalFree(rawSddl);
    return ERROR_SUCCESS;
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

[[nodiscard]] DWORD ReadLeaseMask(HANDLE object, PSID sid, ACCESS_MASK& mask)
{
    mask = 0;
    DWORD required = 0;
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION;
    GetUserObjectSecurity(object, &information, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return sizeError == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR : sizeError;
    }
    std::vector<BYTE> descriptor(required);
    if (!GetUserObjectSecurity(object, &information, descriptor.data(), required, &required))
    {
        return GetLastError();
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(descriptor.data(), &present, &dacl, &defaulted))
    {
        return GetLastError();
    }
    if (!present || dacl == nullptr)
    {
        return ERROR_INVALID_ACL;
    }
    DWORD matches = 0;
    for (DWORD index = 0; index < dacl->AceCount; ++index)
    {
        void* raw = nullptr;
        if (!GetAce(dacl, index, &raw))
        {
            return GetLastError();
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            EqualSid(const_cast<DWORD*>(&ace->SidStart), sid))
        {
            if (ace->Header.AceFlags != 0)
            {
                return ERROR_INVALID_DATA;
            }
            ++matches;
            mask = ace->Mask;
        }
    }
    return matches == 1 ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

[[nodiscard]] bool LeaseSucceeded(const launch_as::InteractiveObjectAclLeaseStatus& result) noexcept
{
    return result.openError == ERROR_SUCCESS && result.readError == ERROR_SUCCESS &&
           result.addError == ERROR_SUCCESS && result.verifyAddError == ERROR_SUCCESS &&
           result.removeError == ERROR_SUCCESS && result.verifyRemoveError == ERROR_SUCCESS &&
           result.added && result.removed && result.restored;
}

void WriteLease(std::ofstream& output, std::string_view name,
    const launch_as::InteractiveObjectAclLeaseStatus& result)
{
    output << "open" << name << "Error=" << result.openError << '\n';
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

    HWINSTA snapshotWindowStation = OpenWindowStationW(L"WinSta0", FALSE, READ_CONTROL);
    const DWORD snapshotWindowStationError =
        snapshotWindowStation != nullptr ? ERROR_SUCCESS : GetLastError();
    HDESK snapshotDesktop = OpenDesktopW(L"Default", 0, FALSE, READ_CONTROL);
    const DWORD snapshotDesktopError = snapshotDesktop != nullptr ? ERROR_SUCCESS : GetLastError();
    std::wstring originalWindowStationDacl;
    std::wstring originalDesktopDacl;
    const DWORD originalWindowStationDaclError =
        snapshotWindowStation != nullptr
            ? ReadDaclSddl(snapshotWindowStation, originalWindowStationDacl)
            : snapshotWindowStationError;
    const DWORD originalDesktopDaclError = snapshotDesktop != nullptr
                                               ? ReadDaclSddl(snapshotDesktop, originalDesktopDacl)
                                               : snapshotDesktopError;

    const DWORD tick = static_cast<DWORD>(GetTickCount64());
    const std::wstring leaseSidText = L"S-1-5-5-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                      std::to_wstring(tick == 0 ? 1 : tick);
    PSID leaseSid = nullptr;
    const BOOL convertedSid = ConvertStringSidToSidW(leaseSidText.c_str(), &leaseSid);
    const DWORD sidError = convertedSid ? ERROR_SUCCESS : GetLastError();

    launch_as::InteractiveDesktopAclLease lease;
    const DWORD acquireError = leaseSid != nullptr ? lease.Acquire(leaseSid) : ERROR_INVALID_SID;
    ACCESS_MASK windowStationMask = 0;
    ACCESS_MASK desktopMask = 0;
    const DWORD windowStationMaskError =
        acquireError == ERROR_SUCCESS
            ? ReadLeaseMask(snapshotWindowStation, leaseSid, windowStationMask)
            : acquireError;
    const DWORD desktopMaskError = acquireError == ERROR_SUCCESS
                                       ? ReadLeaseMask(snapshotDesktop, leaseSid, desktopMask)
                                       : acquireError;
    const bool masksMatch = windowStationMaskError == ERROR_SUCCESS &&
                            desktopMaskError == ERROR_SUCCESS && windowStationMask == 0x00020366 &&
                            desktopMask == 0x000200cf;
    const DWORD releaseError = acquireError == ERROR_SUCCESS ? lease.Release() : acquireError;
    std::wstring finalWindowStationDacl;
    std::wstring finalDesktopDacl;
    const DWORD finalWindowStationDaclError =
        snapshotWindowStation != nullptr
            ? ReadDaclSddl(snapshotWindowStation, finalWindowStationDacl)
            : snapshotWindowStationError;
    const DWORD finalDesktopDaclError = snapshotDesktop != nullptr
                                            ? ReadDaclSddl(snapshotDesktop, finalDesktopDacl)
                                            : snapshotDesktopError;
    if (snapshotDesktop != nullptr)
    {
        CloseDesktop(snapshotDesktop);
    }
    if (snapshotWindowStation != nullptr)
    {
        CloseWindowStation(snapshotWindowStation);
    }
    if (leaseSid != nullptr)
    {
        LocalFree(leaseSid);
    }

    const auto& windowStationLease = lease.windowStationStatus();
    const auto& desktopLease = lease.desktopStatus();
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
    output << "leaseSid=" << NarrowAscii(leaseSidText) << '\n';
    output << "sidError=" << sidError << '\n';
    output << "acquireError=" << acquireError << '\n';
    output << "windowStationMask=" << windowStationMask << '\n';
    output << "desktopMask=" << desktopMask << '\n';
    output << "leaseMasksMatch=" << (masksMatch ? "true" : "false") << '\n';
    output << "releaseError=" << releaseError << '\n';
    WriteLease(output, "windowStation", windowStationLease);
    WriteLease(output, "desktop", desktopLease);
    const bool restored = windowStationLease.restored && desktopLease.restored;
    output << "daclSemanticallyRestored=" << (restored ? "true" : "false") << '\n';
    const bool independentlyRestored = originalWindowStationDaclError == ERROR_SUCCESS &&
                                       originalDesktopDaclError == ERROR_SUCCESS &&
                                       finalWindowStationDaclError == ERROR_SUCCESS &&
                                       finalDesktopDaclError == ERROR_SUCCESS &&
                                       originalWindowStationDacl == finalWindowStationDacl &&
                                       originalDesktopDacl == finalDesktopDacl;
    output << "independentDaclSemanticallyRestored=" << (independentlyRestored ? "true" : "false")
           << '\n';

    const bool success =
        sessionError == ERROR_SUCCESS && processSessionId != 0 &&
        _wcsicmp(processWindowStationName.c_str(), L"WinSta0") == 0 &&
        tokenError == ERROR_SUCCESS && tokenUserError == ERROR_SUCCESS && !tokenUserSid.empty() &&
        elevationError == ERROR_SUCCESS && administratorError == ERROR_SUCCESS &&
        elevation.TokenIsElevated == 0 && !isAdministrator && sidError == ERROR_SUCCESS &&
        acquireError == ERROR_SUCCESS && releaseError == ERROR_SUCCESS && independentlyRestored &&
        masksMatch && LeaseSucceeded(windowStationLease) && LeaseSucceeded(desktopLease);
    output << "probeSucceeded=" << (success ? "true" : "false") << '\n';
    output.flush();
    const bool outputSucceeded = output.good();
    output.close();
    return outputSucceeded && success ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}
