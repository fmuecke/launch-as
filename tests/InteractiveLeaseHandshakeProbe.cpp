// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerApplication.h"
#include "BrokerProcessLauncher.h"
#include "BrokerRegistration.h"
#include "InteractiveDesktopLeaseClient.h"
#include "InteractiveDesktopLeaseCoordinator.h"

#include <Lm.h>
#include <Sddl.h>
#include <Windows.h>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <thread>
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

[[nodiscard]] DWORD ReadTokenUserSid(HANDLE token, std::vector<BYTE>& userSid)
{
    userSid.clear();
    DWORD required = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return sizeError;
    }
    std::vector<BYTE> storage(required);
    if (!GetTokenInformation(token, TokenUser, storage.data(), required, &required))
    {
        return GetLastError();
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
    if (!IsValidSid(user->User.Sid))
    {
        return ERROR_INVALID_SID;
    }
    const DWORD sidBytes = GetLengthSid(user->User.Sid);
    userSid.resize(sidBytes);
    if (!CopySid(sidBytes, userSid.data(), user->User.Sid))
    {
        const DWORD copyError = GetLastError();
        userSid.clear();
        return copyError;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD SidToString(PSID sid, std::wstring& value)
{
    value.clear();
    if (!IsValidSid(sid))
    {
        return ERROR_INVALID_SID;
    }
    PWSTR rawValue = nullptr;
    if (!ConvertSidToStringSidW(sid, &rawValue))
    {
        const DWORD conversionError = GetLastError();
        return conversionError;
    }
    value = rawValue;
    LocalFree(rawValue);
    return ERROR_SUCCESS;
}

[[nodiscard]] std::string NarrowAscii(std::wstring_view value)
{
    std::string result;
    result.reserve(value.size());
    for (const wchar_t character : value)
    {
        result.push_back(static_cast<char>(character));
    }
    return result;
}

[[nodiscard]] DWORD ParseSid(std::wstring_view value, std::vector<BYTE>& sid)
{
    sid.clear();
    const std::wstring text(value);
    PSID rawSid = nullptr;
    if (!ConvertStringSidToSidW(text.c_str(), &rawSid))
    {
        const DWORD conversionError = GetLastError();
        return conversionError;
    }
    const DWORD bytes = GetLengthSid(rawSid);
    sid.resize(bytes);
    const BOOL copied = CopySid(bytes, sid.data(), rawSid);
    const DWORD copyError = copied ? ERROR_SUCCESS : GetLastError();
    LocalFree(rawSid);
    if (!copied)
    {
        sid.clear();
    }
    return copyError;
}

BOOL CALLBACK IsWindowWithTitleVisible(HWND window, LPARAM context)
{
    const auto title = reinterpret_cast<const std::wstring_view*>(context);
    if (!IsWindowVisible(window))
    {
        return TRUE;
    }
    const int characters = GetWindowTextLengthW(window);
    if (characters <= 0)
    {
        return TRUE;
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(characters) + 1);
    if (GetWindowTextW(window, buffer.data(), static_cast<int>(buffer.size())) == characters &&
        std::wstring_view(buffer.data(), static_cast<std::size_t>(characters)) == *title)
    {
        SetLastError(ERROR_SUCCESS);
        return FALSE;
    }
    return TRUE;
}

[[nodiscard]] bool CanSeeWindow(std::wstring_view title)
{
    SetLastError(ERROR_NOT_FOUND);
    const BOOL completed = EnumWindows(IsWindowWithTitleVisible, reinterpret_cast<LPARAM>(&title));
    return completed == FALSE && GetLastError() == ERROR_SUCCESS;
}

[[nodiscard]] std::map<std::string, std::string> ReadProbeResult(const std::filesystem::path& path)
{
    std::map<std::string, std::string> values;
    std::ifstream input(path, std::ios::binary);
    std::string line;
    while (std::getline(input, line))
    {
        const std::size_t separator = line.find('=');
        if (separator != std::string::npos)
        {
            values.emplace(line.substr(0, separator), line.substr(separator + 1));
        }
    }
    return values;
}

[[nodiscard]] DWORD RunCoordinator(std::wstring_view pipeName, std::wstring_view nonce,
    const std::filesystem::path& resultPath, const std::filesystem::path& readyPath,
    std::wstring_view targetWindowTitle = {})
{
    DWORD callerSessionId = 0;
    const bool sessionRead = ProcessIdToSessionId(GetCurrentProcessId(), &callerSessionId) != FALSE;
    const DWORD sessionError = sessionRead ? ERROR_SUCCESS : GetLastError();
    HANDLE callerToken = nullptr;
    const BOOL openedCallerToken = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &callerToken);
    const DWORD callerTokenError = openedCallerToken ? ERROR_SUCCESS : GetLastError();
    std::vector<BYTE> callerLogonSid;
    const DWORD callerLogonSidError =
        openedCallerToken ? launch_as::broker::GetTokenLogonSid(callerToken, callerLogonSid)
                          : callerTokenError;
    std::vector<BYTE> callerUserSid;
    const DWORD callerUserSidError =
        openedCallerToken ? ReadTokenUserSid(callerToken, callerUserSid) : callerTokenError;
    if (callerToken != nullptr)
    {
        CloseHandle(callerToken);
    }
    std::wstring callerLogonSidText;
    const DWORD callerLogonSidTextError =
        callerLogonSidError == ERROR_SUCCESS
            ? SidToString(callerLogonSid.data(), callerLogonSidText)
            : callerLogonSidError;
    std::wstring callerUserSidText;
    const DWORD callerUserSidTextError = callerUserSidError == ERROR_SUCCESS
                                             ? SidToString(callerUserSid.data(), callerUserSidText)
                                             : callerUserSidError;
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
    bool targetWindowVisible = targetWindowTitle.empty();
    if (createPipeError == ERROR_SUCCESS)
    {
        std::ofstream ready(readyPath, std::ios::binary | std::ios::trunc);
        ready << "READY\n";
        ready << "callerSessionId=" << callerSessionId << '\n';
        ready << "callerUserSid=" << NarrowAscii(callerUserSidText) << '\n';
        ready << "callerLogonSid=" << NarrowAscii(callerLogonSidText) << '\n';
        ready << "sessionError=" << sessionError << '\n';
        ready << "callerTokenError=" << callerTokenError << '\n';
        ready << "callerLogonSidError=" << callerLogonSidError << '\n';
        ready << "callerLogonSidTextError=" << callerLogonSidTextError << '\n';
        ready << "callerUserSidError=" << callerUserSidError << '\n';
        ready << "callerUserSidTextError=" << callerUserSidTextError << '\n';
        ready.close();
        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (connected || connectError == ERROR_PIPE_CONNECTED)
        {
            connectError = ERROR_SUCCESS;
            if (targetWindowTitle.empty())
            {
                serveError = launch_as::ServeInteractiveDesktopLease(pipe, nonce);
            }
            else
            {
                std::atomic<bool> serverFinished = false;
                std::thread server(
                    [&]()
                    {
                        serveError = launch_as::ServeInteractiveDesktopLease(pipe, nonce);
                        serverFinished.store(true);
                    });
                const ULONGLONG visibilityDeadline = GetTickCount64() + 15'000;
                while (!serverFinished.load() && GetTickCount64() < visibilityDeadline)
                {
                    if (CanSeeWindow(targetWindowTitle))
                    {
                        targetWindowVisible = true;
                        break;
                    }
                    Sleep(20);
                }
                server.join();
            }
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
    result << "targetWindowVisible=" << (targetWindowVisible ? "true" : "false") << '\n';
    result << "independentDaclSemanticallyRestored=" << (restored ? "true" : "false") << '\n';
    const bool identityReady =
        sessionRead && callerTokenError == ERROR_SUCCESS && callerLogonSidError == ERROR_SUCCESS &&
        callerLogonSidTextError == ERROR_SUCCESS && callerUserSidError == ERROR_SUCCESS &&
        callerUserSidTextError == ERROR_SUCCESS;
    const bool success = identityReady && createPipeError == ERROR_SUCCESS &&
                         connectError == ERROR_SUCCESS && serveError == ERROR_SUCCESS &&
                         targetWindowVisible && restored;
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

[[nodiscard]] DWORD RunBrokerTarget(std::wstring_view pipeName, std::wstring_view nonce,
    const std::filesystem::path& resultPath, DWORD callerSessionId,
    std::wstring_view callerLogonSidText, std::wstring_view callerUserSidText,
    const std::filesystem::path& targetExecutable, const std::filesystem::path& workingDirectory,
    const std::filesystem::path& targetResultPath, std::wstring_view targetWindowTitle)
{
    HANDLE processToken = nullptr;
    const BOOL openedProcessToken =
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken);
    const DWORD processTokenError = openedProcessToken ? ERROR_SUCCESS : GetLastError();
    const bool isLocalSystem = openedProcessToken && IsCurrentUserLocalSystem(processToken);
    if (processToken != nullptr)
    {
        CloseHandle(processToken);
    }

    std::vector<BYTE> callerLogonSid;
    const DWORD callerLogonSidError = ParseSid(callerLogonSidText, callerLogonSid);
    std::vector<BYTE> callerUserSid;
    const DWORD callerUserSidError = ParseSid(callerUserSidText, callerUserSid);
    const std::wstring accountName = L"LasGui" + std::to_wstring(GetCurrentProcessId());
    const std::filesystem::path enrollmentDirectory =
        workingDirectory / (L"interactive-enrollment-" + std::to_wstring(GetCurrentProcessId()));
    std::error_code directoryError;
    std::filesystem::create_directories(enrollmentDirectory, directoryError);
    launch_as::broker::RegistrationService registration(enrollmentDirectory.native());
    const DWORD enrollmentDirectoryError =
        directoryError ? static_cast<DWORD>(directoryError.value()) : ERROR_SUCCESS;
    const DWORD accountCreateError = enrollmentDirectoryError == ERROR_SUCCESS
                                         ? registration.Create(accountName)
                                         : enrollmentDirectoryError;
    const bool accountCreated = accountCreateError == ERROR_SUCCESS;

    std::vector<std::wstring> targetArguments {
        targetExecutable.native(),
        targetResultPath.native(),
        std::wstring(targetWindowTitle),
        L"4000"
    };
    launch_as::broker::BrokerChildProcess child;
    launch_as::broker::BrokerRequest request;
    request.operation = launch_as::broker::RequestOperation::InteractiveLaunch;
    request.requestId = nonce;
    request.profileId = accountName;
    request.arguments = targetArguments;
    request.workingDirectory = workingDirectory.native();
    request.interactive.leasePipe = pipeName;
    request.interactive.nonce = nonce;
    launch_as::broker::BrokerCallerIdentity caller;
    caller.userSid = callerUserSid;
    caller.logonSid = callerLogonSid;
    caller.sessionId = callerSessionId;
    caller.isElevated = false;

    DWORD launchError = accountCreateError;
    DWORD waitError = accountCreateError;
    DWORD releaseError = accountCreateError;
    DWORD unconfirmedReleaseError = accountCreateError;
    DWORD targetExitCode = ERROR_CANCELLED;
    bool jobTreeExitedBeforeRelease = false;
    {
        launch_as::broker::BrokerApplication application(
            enrollmentDirectory.native(), callerUserSid);
        if (accountCreated && callerLogonSidError == ERROR_SUCCESS &&
            callerUserSidError == ERROR_SUCCESS)
        {
            launchError = application.Launch(request, caller, child);
            waitError = launchError;
        }
        if (launchError == ERROR_SUCCESS)
        {
            unconfirmedReleaseError = application.FinishSession(request, false);
        }
        if (launchError == ERROR_SUCCESS)
        {
            const DWORD waitResult = WaitForSingleObject(child.process(), 15'000);
            if (waitResult == WAIT_OBJECT_0)
            {
                waitError = ERROR_SUCCESS;
                if (!GetExitCodeProcess(child.process(), &targetExitCode))
                {
                    waitError = GetLastError();
                }
            }
            else if (waitResult == WAIT_TIMEOUT)
            {
                waitError = ERROR_TIMEOUT;
            }
            else
            {
                waitError = GetLastError();
            }
        }
        jobTreeExitedBeforeRelease =
            waitError == ERROR_SUCCESS && child.WaitForProcessTreeExit(5'000);
        if (launchError == ERROR_SUCCESS)
        {
            releaseError = application.FinishSession(request, jobTreeExitedBeforeRelease);
        }
    }
    const bool connectionHeld = launchError == ERROR_SUCCESS;
    const bool childCleanupSucceeded = child.TerminateAndWaitForExit();

    const std::map<std::string, std::string> targetResult = ReadProbeResult(targetResultPath);
    const auto targetValue = [&](const char* key) -> std::string
    {
        const auto value = targetResult.find(key);
        return value == targetResult.end() ? std::string() : value->second;
    };
    const bool sessionIdMatchesCaller =
        targetValue("processSessionId") == std::to_string(callerSessionId);
    const bool windowStationIsWinSta0 = targetValue("processWindowStation") == "WinSta0";
    const bool desktopIsDefault = targetValue("threadDesktop") == "Default";
    std::vector<BYTE> targetLogonSid;
    std::wstring targetLogonSidText;
    for (const char character : targetValue("tokenLogonSid"))
    {
        targetLogonSidText.push_back(static_cast<unsigned char>(character));
    }
    const DWORD targetLogonSidError = ParseSid(targetLogonSidText, targetLogonSid);
    const DWORD targetLogonSidTextError = targetLogonSidError;
    const bool logonSidMatchesLease = targetLogonSidError == ERROR_SUCCESS;
    const bool windowCreated = targetValue("windowCreated") == "true";
    const bool targetProbeSucceeded = targetValue("probeSucceeded") == "true";

    const DWORD accountDeleteError =
        accountCreated ? registration.Delete(accountName) : accountCreateError;

    std::ofstream result(resultPath, std::ios::binary | std::ios::trunc);
    if (!result)
    {
        return ERROR_OPEN_FAILED;
    }
    result << "processTokenError=" << processTokenError << '\n';
    result << "clientIsLocalSystem=" << (isLocalSystem ? "true" : "false") << '\n';
    result << "callerSidError=" << callerLogonSidError << '\n';
    result << "callerUserSidError=" << callerUserSidError << '\n';
    result << "enrollmentDirectoryError=" << enrollmentDirectoryError << '\n';
    result << "accountCreateError=" << accountCreateError << '\n';
    result << "targetLogonSidError=" << targetLogonSidError << '\n';
    result << "targetLogonSidTextError=" << targetLogonSidTextError << '\n';
    result << "connectionHeldAfterAcquire=" << (connectionHeld ? "true" : "false") << '\n';
    result << "acquireError=" << launchError << '\n';
    result << "waitError=" << waitError << '\n';
    result << "targetExitCode=" << targetExitCode << '\n';
    result << "jobTreeExitedBeforeRelease=" << (jobTreeExitedBeforeRelease ? "true" : "false")
           << '\n';
    result << "releaseError=" << releaseError << '\n';
    result << "unconfirmedReleaseError=" << unconfirmedReleaseError << '\n';
    result << "childCleanupSucceeded=" << (childCleanupSucceeded ? "true" : "false") << '\n';
    result << "accountDeleteError=" << accountDeleteError << '\n';
    result << "sessionIdMatchesCaller=" << (sessionIdMatchesCaller ? "true" : "false") << '\n';
    result << "windowStationIsWinSta0=" << (windowStationIsWinSta0 ? "true" : "false") << '\n';
    result << "desktopIsDefault=" << (desktopIsDefault ? "true" : "false") << '\n';
    result << "logonSidMatchesLease=" << (logonSidMatchesLease ? "true" : "false") << '\n';
    result << "windowCreated=" << (windowCreated ? "true" : "false") << '\n';
    const bool success =
        processTokenError == ERROR_SUCCESS && isLocalSystem &&
        callerLogonSidError == ERROR_SUCCESS && callerUserSidError == ERROR_SUCCESS &&
        accountCreateError == ERROR_SUCCESS && targetLogonSidError == ERROR_SUCCESS &&
        targetLogonSidTextError == ERROR_SUCCESS && connectionHeld &&
        launchError == ERROR_SUCCESS && waitError == ERROR_SUCCESS &&
        targetExitCode == ERROR_SUCCESS && jobTreeExitedBeforeRelease &&
        unconfirmedReleaseError == ERROR_BUSY && releaseError == ERROR_SUCCESS &&
        childCleanupSucceeded && accountDeleteError == ERROR_SUCCESS && sessionIdMatchesCaller &&
        windowStationIsWinSta0 && desktopIsDefault && logonSidMatchesLease && windowCreated &&
        targetProbeSucceeded;
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
    if (argumentCount == 7 && std::wstring_view(arguments[1]) == L"--coordinator-target")
    {
        return static_cast<int>(
            RunCoordinator(arguments[2], arguments[3], arguments[4], arguments[5], arguments[6]));
    }
    if (argumentCount == 12 && std::wstring_view(arguments[1]) == L"--broker-target")
    {
        wchar_t* sessionEnd = nullptr;
        const unsigned long callerSessionId = wcstoul(arguments[5], &sessionEnd, 10);
        if (sessionEnd == arguments[5] || *sessionEnd != L'\0' || callerSessionId > MAXDWORD)
        {
            return ERROR_INVALID_PARAMETER;
        }
        return static_cast<int>(RunBrokerTarget(arguments[2],
            arguments[3],
            arguments[4],
            static_cast<DWORD>(callerSessionId),
            arguments[6],
            arguments[7],
            arguments[8],
            arguments[9],
            arguments[10],
            arguments[11]));
    }
    return ERROR_INVALID_PARAMETER;
}
