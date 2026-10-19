// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <bcrypt.h>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <sddl.h>
#include <vector>

using namespace launch_as;

namespace
{
bool WriteFileAt(const std::filesystem::path& path)
{
    UniqueHandle file(CreateFileW(path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!file)
    {
        return false;
    }
    const char value[] = "scope probe";
    DWORD written = 0;
    return WriteFile(file.get(), value, sizeof(value), &written, nullptr) &&
           written == sizeof(value);
}

bool CheckLongPathInspection(const std::filesystem::path& path)
{
    std::array<wchar_t, 32'768> name {};
    if (GetLongPathNameW(path.c_str(), name.data(), static_cast<DWORD>(name.size())) == 0)
    {
        const DWORD error = GetLastError();
        std::wcerr << L"Long-path inspection failed: " << path << L" (error " << error << L")\n";
        return false;
    }
    return true;
}

bool Run(const std::wstring& executable, const std::vector<std::wstring>& arguments)
{
    const auto command = BuildWindowsCommandLine(executable, arguments);
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process {};
    if (!CreateProcessW(executable.c_str(),
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startup,
            &process))
    {
        const DWORD error = GetLastError();
        std::wcerr << L"Probe child creation failed: " << error << L"\n";
        return false;
    }
    UniqueHandle child(process.hProcess);
    UniqueHandle thread(process.hThread);
    if (WaitForSingleObject(child.get(), 30'000) != WAIT_OBJECT_0)
    {
        TerminateProcess(child.get(), 1);
        WaitForSingleObject(child.get(), 5'000);
        return false;
    }
    DWORD exitCode = 1;
    const bool succeeded = GetExitCodeProcess(child.get(), &exitCode) && exitCode == 0;
    if (!succeeded)
    {
        std::wcerr << L"Probe child failed: " << executable << L" (exit " << exitCode << L")\n";
    }
    return succeeded;
}
} // namespace

int wmain(int count, wchar_t** arguments)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (count == 6 && std::wstring_view(arguments[5]) == L"hold")
    {
        FILE* stream = nullptr;
        const auto work = std::filesystem::path(arguments[1]);
        (void)_wfreopen_s(&stream, (work / L"probe.stdout.log").c_str(), L"w", stdout);
        (void)_wfreopen_s(&stream, (work / L"probe.stderr.log").c_str(), L"w", stderr);
    }
#ifdef LAUNCH_AS_INTERACTIVE_SCOPE_PROBE
    const HWND window = CreateWindowExW(0,
        L"STATIC",
        L"Read-scope probe",
        WS_POPUP,
        0,
        0,
        1,
        1,
        nullptr,
        nullptr,
        GetModuleHandleW(nullptr),
        nullptr);
    if (window == nullptr)
    {
        const DWORD error = GetLastError();
        std::wcerr << L"Read-restricted GUI initialization failed: " << error << L"\n";
        return 1;
    }
    DestroyWindow(window);
#endif
    if ((count != 5 && count != 6) ||
        (std::wstring_view(arguments[3]) != L"low" &&
            std::wstring_view(arguments[3]) != L"medium") ||
        (std::wstring_view(arguments[4]) != L"unrestricted" &&
            std::wstring_view(arguments[4]) != L"access"))
    {
        return 1;
    }
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        return 1;
    }
    UniqueHandle token(rawToken);
    const bool lowIntegrity = std::wstring_view(arguments[3]) == L"low";
    const bool restrictAccess = std::wstring_view(arguments[4]) == L"access";
    if (restrictAccess)
    {
        std::vector<BYTE> user;
        LocalAllocation<PWSTR> sid;
        if (QueryTokenInformation(token.get(), TokenUser, user) != ERROR_SUCCESS ||
            !ConvertSidToStringSidW(
                reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, sid.address()))
        {
            return 1;
        }
        std::wcout << L"Read-restricted user SID: " << sid.get() << L"\n";
        LUID traverse {};
        std::vector<BYTE> privileges;
        if (!LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &traverse) ||
            QueryTokenInformation(token.get(), TokenPrivileges, privileges) != ERROR_SUCCESS)
        {
            return 1;
        }
        const auto* values = reinterpret_cast<const TOKEN_PRIVILEGES*>(privileges.data());
        for (DWORD index = 0; index < values->PrivilegeCount; ++index)
        {
            if (values->Privileges[index].Luid.LowPart == traverse.LowPart &&
                values->Privileges[index].Luid.HighPart == traverse.HighPart)
            {
                std::wcerr << L"A read-restricted descendant retained traversal bypass.\n";
                return 1;
            }
        }
    }
    std::vector<BYTE> integrity;
    if (QueryTokenInformation(token.get(), TokenIntegrityLevel, integrity) != ERROR_SUCCESS ||
        !IsWellKnownSid(reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrity.data())->Label.Sid,
            lowIntegrity ? WinLowLabelSid : WinMediumLabelSid))
    {
        std::wcerr << L"Launched process integrity does not match the requested flag.\n";
        return 1;
    }
    if (lowIntegrity)
    {
        HANDLE rawAdjustable = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &rawAdjustable))
        {
            return 1;
        }
        UniqueHandle adjustable(rawAdjustable);
        std::array<BYTE, SECURITY_MAX_SID_SIZE> mediumSid {};
        DWORD mediumBytes = static_cast<DWORD>(mediumSid.size());
        if (!CreateWellKnownSid(WinMediumLabelSid, nullptr, mediumSid.data(), &mediumBytes))
        {
            return 1;
        }
        TOKEN_MANDATORY_LABEL medium {{mediumSid.data(), SE_GROUP_INTEGRITY}};
        const BOOL raised = SetTokenInformation(adjustable.get(),
            TokenIntegrityLevel,
            &medium,
            static_cast<DWORD>(sizeof(medium)) + mediumBytes);
        const DWORD raiseError = raised ? ERROR_SUCCESS : GetLastError();
        if ((raiseError != ERROR_ACCESS_DENIED && raiseError != ERROR_PRIVILEGE_NOT_HELD) ||
            QueryTokenInformation(token.get(), TokenIntegrityLevel, integrity) != ERROR_SUCCESS ||
            !IsWellKnownSid(reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrity.data())->Label.Sid,
                WinLowLabelSid))
        {
            std::wcerr << L"Raising integrity to Medium was not denied (error " << raiseError
                       << L").\n";
            return 1;
        }
    }
    std::vector<BYTE> restriction;
    if (QueryTokenInformation(token.get(), TokenRestrictedSids, restriction) != ERROR_SUCCESS)
    {
        return 1;
    }
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(restriction.data());
    bool everyone = false;
    for (DWORD index = 0; index < groups->GroupCount; ++index)
    {
        everyone = everyone || IsWellKnownSid(groups->Groups[index].Sid, WinWorldSid);
    }
    std::array<wchar_t, 32'768> profile {};
    const DWORD profileLength =
        GetEnvironmentVariableW(L"USERPROFILE", profile.data(), static_cast<DWORD>(profile.size()));
    std::array<BYTE, 32> random {};
    if (everyone != restrictAccess || (groups->GroupCount != 0) != restrictAccess ||
        profileLength == 0 || profileLength >= profile.size() ||
        BCryptGenRandom(nullptr,
            random.data(),
            static_cast<ULONG>(random.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0 ||
        !WriteFileAt(std::filesystem::path(profile.data()) / L"launch-as-write-scope-probe.txt") ||
        !WriteFileAt(std::filesystem::path(arguments[1]) / L"existing" / L"old.txt") ||
        !WriteFileAt(std::filesystem::path(arguments[1]) / L"new.txt") ||
        WriteFileAt(std::filesystem::path(arguments[2]) / L"outside.txt") !=
            (!lowIntegrity && !restrictAccess) ||
        (!restrictAccess &&
            WriteFileAt(std::filesystem::path(arguments[1]) / L"hardlink.txt") == lowIntegrity) ||
        WriteFileAt(std::filesystem::path(arguments[1]) / L"junction" / L"outside.txt") !=
            (!lowIntegrity && !restrictAccess))
    {
        std::wcerr << L"Write scope or cryptographic initialization failed.\n";
        return 1;
    }
    UniqueHandle readOutside(
        CreateFileW((std::filesystem::path(arguments[2]) / L"outside.txt").c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
    const DWORD readError = readOutside ? ERROR_SUCCESS : GetLastError();
    if (static_cast<bool>(readOutside) == restrictAccess ||
        (restrictAccess && readError != ERROR_ACCESS_DENIED))
    {
        return 1;
    }
    readOutside.reset();
    if (restrictAccess)
    {
        if (!CheckLongPathInspection(
                std::filesystem::path(profile.data()) / L"launch-as-write-scope-probe.txt") ||
            !CheckLongPathInspection(std::filesystem::path(arguments[1]) / L"new.txt"))
        {
            return 1;
        }
        UniqueHandle readAlias(CreateFileW(
            (std::filesystem::path(arguments[1]) / L"junction" / L"outside.txt").c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr));
        const DWORD aliasError = readAlias ? ERROR_SUCCESS : GetLastError();
        if (aliasError != ERROR_ACCESS_DENIED)
        {
            std::wcerr << L"A junction bypassed read restriction.\n";
            return 1;
        }
    }
    if (count == 6 && std::wstring_view(arguments[5]) == L"hold")
    {
        const auto work = std::filesystem::path(arguments[1]);
        if (!WriteFileAt(work / L"ready.txt"))
        {
            return 1;
        }
        const ULONGLONG deadline = GetTickCount64() + 60'000;
        while (GetFileAttributesW((work / L"release.txt").c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            if (GetTickCount64() >= deadline)
            {
                return 1;
            }
            Sleep(50);
        }
        return WriteFileAt(work / L"descendant-passed.txt") ? 0 : 1;
    }
    if (count == 5)
    {
        std::wstring executable;
        std::array<wchar_t, MAX_PATH> system {};
        if (GetCurrentExecutablePath(executable) != ERROR_SUCCESS ||
            GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size())) == 0 ||
            !Run((std::filesystem::path(system.data()) / L"whoami.exe").native(), {L"/all"}) ||
            !Run((std::filesystem::path(system.data()) / L"WindowsPowerShell" / L"v1.0" /
                     L"powershell.exe")
                     .native(),
                {L"-NoProfile",
                    L"-ExecutionPolicy",
                    L"Bypass",
                    L"-Command",
                    L"[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes((New-"
                    L"Object byte[] 16))"}) ||
            !Run(executable,
                {arguments[1], arguments[2], arguments[3], arguments[4], L"descendant"}))
        {
            return 1;
        }
        std::wcout << (restrictAccess
                           ? L"Read-scope installed launch and descendant probes passed\n"
                           : L"Write-scope installed launch and descendant probes passed\n");
    }
    else if (!WriteFileAt(std::filesystem::path(arguments[1]) / L"descendant-passed.txt"))
    {
        return 1;
    }
    return 0;
}
