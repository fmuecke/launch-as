// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"
#include "InteractiveDesktopLeaseClient.h"
#include "InteractiveDesktopLeaseCoordinator.h"

#include <Sddl.h>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] DWORD ReadDaclSddl(HANDLE object, std::wstring& value)
{
    value.clear();
    DWORD required = 0;
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION;
    GetUserObjectSecurity(object, &information, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return sizeError;
    }
    std::vector<BYTE> descriptor(required);
    if (!GetUserObjectSecurity(object, &information, descriptor.data(), required, &required))
    {
        const DWORD descriptorError = GetLastError();
        return descriptorError;
    }
    PWSTR rawSddl = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.data(), SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &rawSddl, nullptr))
    {
        const DWORD sddlError = GetLastError();
        return sddlError;
    }
    value = rawSddl;
    LocalFree(rawSddl);
    return ERROR_SUCCESS;
}

[[nodiscard]] bool IsCurrentUserLocalSystem(HANDLE token)
{
    DWORD required = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return false;
    }
    std::vector<BYTE> userBuffer(required);
    if (!GetTokenInformation(token, TokenUser, userBuffer.data(), required, &required))
    {
        return false;
    }
    std::vector<BYTE> systemSid(SECURITY_MAX_SID_SIZE);
    DWORD systemSidBytes = static_cast<DWORD>(systemSid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidBytes))
    {
        return false;
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    return IsValidSid(user->User.Sid) && EqualSid(user->User.Sid, systemSid.data()) != FALSE;
}

[[nodiscard]] DWORD RunCoordinator(std::wstring_view pipeName, std::wstring_view nonce,
    const std::filesystem::path& resultPath, const std::filesystem::path& readyPath)
{
    HWINSTA windowStation = OpenWindowStationW(L"WinSta0", FALSE, READ_CONTROL);
    const DWORD windowStationError = windowStation != nullptr ? ERROR_SUCCESS : GetLastError();
    HDESK desktop = OpenDesktopW(L"Default", 0, FALSE, READ_CONTROL);
    const DWORD desktopError = desktop != nullptr ? ERROR_SUCCESS : GetLastError();
    std::wstring originalWindowStationDacl;
    std::wstring originalDesktopDacl;
    const DWORD originalWindowStationDaclError =
        windowStation != nullptr ? ReadDaclSddl(windowStation, originalWindowStationDacl)
                                 : windowStationError;
    const DWORD originalDesktopDaclError =
        desktop != nullptr ? ReadDaclSddl(desktop, originalDesktopDacl) : desktopError;

    HANDLE pipe = nullptr;
    const DWORD createPipeError = launch_as::CreateInteractiveDesktopLeasePipe(pipeName, pipe);
    DWORD connectError = createPipeError;
    DWORD serveError = createPipeError;
    if (createPipeError == ERROR_SUCCESS)
    {
        std::ofstream ready(readyPath, std::ios::binary | std::ios::trunc);
        ready << "READY\n";
        ready.close();
        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (connected || connectError == ERROR_PIPE_CONNECTED)
        {
            connectError = ERROR_SUCCESS;
            serveError = launch_as::ServeInteractiveDesktopLease(pipe, nonce);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }

    std::wstring finalWindowStationDacl;
    std::wstring finalDesktopDacl;
    const DWORD finalWindowStationDaclError =
        windowStation != nullptr ? ReadDaclSddl(windowStation, finalWindowStationDacl)
                                 : windowStationError;
    const DWORD finalDesktopDaclError =
        desktop != nullptr ? ReadDaclSddl(desktop, finalDesktopDacl) : desktopError;
    if (desktop != nullptr)
    {
        CloseDesktop(desktop);
    }
    if (windowStation != nullptr)
    {
        CloseWindowStation(windowStation);
    }
    const bool restored = originalWindowStationDaclError == ERROR_SUCCESS &&
                          originalDesktopDaclError == ERROR_SUCCESS &&
                          finalWindowStationDaclError == ERROR_SUCCESS &&
                          finalDesktopDaclError == ERROR_SUCCESS &&
                          originalWindowStationDacl == finalWindowStationDacl &&
                          originalDesktopDacl == finalDesktopDacl;
    std::ofstream result(resultPath, std::ios::binary | std::ios::trunc);
    if (!result)
    {
        return ERROR_OPEN_FAILED;
    }
    result << "createPipeError=" << createPipeError << '\n';
    result << "connectError=" << connectError << '\n';
    result << "serveError=" << serveError << '\n';
    result << "independentDaclSemanticallyRestored=" << (restored ? "true" : "false") << '\n';
    const bool success = createPipeError == ERROR_SUCCESS && connectError == ERROR_SUCCESS &&
                         serveError == ERROR_SUCCESS && restored;
    result << "probeSucceeded=" << (success ? "true" : "false") << '\n';
    result.flush();
    return result.good() && success ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}

[[nodiscard]] DWORD RunBrokerClient(
    std::wstring_view pipeName, std::wstring_view nonce, const std::filesystem::path& resultPath)
{
    HANDLE token = nullptr;
    const BOOL openedToken = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    const DWORD tokenError = openedToken ? ERROR_SUCCESS : GetLastError();
    std::vector<BYTE> logonSid;
    const DWORD logonSidError =
        openedToken ? launch_as::broker::GetTokenLogonSid(token, logonSid) : tokenError;
    const bool isLocalSystem = openedToken && IsCurrentUserLocalSystem(token);
    if (token != nullptr)
    {
        CloseHandle(token);
    }
    launch_as::broker::InteractiveDesktopLeaseConnection connection;
    const DWORD acquireError = logonSidError == ERROR_SUCCESS
                                   ? launch_as::broker::AcquireInteractiveDesktopLease(
                                         pipeName, nonce, logonSid.data(), connection)
                                   : logonSidError;
    const bool connectionHeld = static_cast<bool>(connection);
    const DWORD releaseError = acquireError == ERROR_SUCCESS
                                   ? launch_as::broker::ReleaseInteractiveDesktopLease(connection)
                                   : acquireError;
    std::ofstream result(resultPath, std::ios::binary | std::ios::trunc);
    if (!result)
    {
        return ERROR_OPEN_FAILED;
    }
    result << "tokenError=" << tokenError << '\n';
    result << "logonSidError=" << logonSidError << '\n';
    result << "clientIsLocalSystem=" << (isLocalSystem ? "true" : "false") << '\n';
    result << "connectionHeldAfterAcquire=" << (connectionHeld ? "true" : "false") << '\n';
    result << "acquireError=" << acquireError << '\n';
    result << "releaseError=" << releaseError << '\n';
    const bool success = tokenError == ERROR_SUCCESS && logonSidError == ERROR_SUCCESS &&
                         isLocalSystem && connectionHeld && acquireError == ERROR_SUCCESS &&
                         releaseError == ERROR_SUCCESS;
    result << "probeSucceeded=" << (success ? "true" : "false") << '\n';
    result.flush();
    return result.good() && success ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount == 6 && std::wstring_view(arguments[1]) == L"--coordinator")
    {
        return static_cast<int>(
            RunCoordinator(arguments[2], arguments[3], arguments[4], arguments[5]));
    }
    if (argumentCount == 5 && std::wstring_view(arguments[1]) == L"--broker")
    {
        return static_cast<int>(RunBrokerClient(arguments[2], arguments[3], arguments[4]));
    }
    return ERROR_INVALID_PARAMETER;
}
