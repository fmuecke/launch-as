// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TestSupport.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Aclapi.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <array>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <windns.h>

using namespace launch_as;

namespace
{
bool CanOpen(const std::filesystem::path& path, DWORD access, DWORD creation = OPEN_EXISTING,
    DWORD* error = nullptr)
{
    UniqueHandle file(CreateFileW(path.c_str(),
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        creation,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    const DWORD openError = file ? ERROR_SUCCESS : GetLastError();
    if (error)
    {
        *error = openError;
    }
    return static_cast<bool>(file);
}

bool HasMediumLabel(const std::filesystem::path& path)
{
    PACL label = nullptr;
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    if (GetNamedSecurityInfoW(path.c_str(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            nullptr,
            &label,
            descriptor.address()) != ERROR_SUCCESS)
    {
        return false;
    }
    if (label)
    {
        for (DWORD index = 0; index < label->AceCount; ++index)
        {
            void* raw = nullptr;
            if (!GetAce(label, index, &raw))
            {
                return false;
            }
            const auto* ace = static_cast<const SYSTEM_MANDATORY_LABEL_ACE*>(raw);
            if (ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
            {
                return IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinMediumLabelSid);
            }
        }
    }
    return true; // An unlabelled object defaults to Medium.
}
} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wstring_view(argv[1]) == L"--check-modify")
    {
        const auto open = [&](DWORD access)
        {
            return UniqueHandle(CreateFileW(argv[2],
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                nullptr));
        };
        if (!Expect(static_cast<bool>(
                        open(FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE)),
                L"The managed account does not have Modify access."))
        {
            return 1;
        }
        for (const DWORD access : std::array<DWORD, 2> {WRITE_DAC, WRITE_OWNER})
        {
            const auto handle = open(access);
            const DWORD error = handle ? ERROR_SUCCESS : GetLastError();
            if (!Expect(!handle && error == ERROR_ACCESS_DENIED,
                    L"The fixture unexpectedly grants metadata permissions."))
            {
                return 1;
            }
        }
        std::wcout << L"Managed account has Modify, without WRITE_DAC or WRITE_OWNER\n";
        return 0;
    }
    if (argc == 3 && (std::wstring_view(argv[1]) == L"--check-relaunch" ||
                         std::wstring_view(argv[1]) == L"--check-medium-create-denied"))
    {
        const std::filesystem::path work(argv[2]);
        HANDLE rawToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
        {
            return 1;
        }
        UniqueHandle token(rawToken);
        DWORD appContainer = 0, bytes = 0;
        if (!Expect(GetTokenInformation(token.get(),
                        TokenIsAppContainer,
                        &appContainer,
                        sizeof(appContainer),
                        &bytes) &&
                        appContainer == 1,
                L"Relaunch probe must run inside AppContainer."))
        {
            return 1;
        }
        if (std::wstring_view(argv[1]) == L"--check-medium-create-denied")
        {
            DWORD error = ERROR_SUCCESS;
            const bool created = CanOpen(work / L"new.txt", GENERIC_WRITE, CREATE_NEW, &error);
            if (!Expect(!created && error == ERROR_PRIVILEGE_NOT_HELD && HasMediumLabel(work),
                    L"Explicit inheritable Medium labels were not preserved."))
            {
                return 1;
            }
            std::wcout << L"Explicit inheritable Medium label preserved (create denied 1314)\n";
            return 0;
        }
        if (!Expect(CanOpen(work / L"late" / L"inherited.txt", GENERIC_READ | GENERIC_WRITE),
                L"New files did not inherit AppContainer access.") ||
            !Expect(CanOpen(work / L"managed-moved-in.txt", GENERIC_READ | GENERIC_WRITE),
                L"Relaunch did not propagate access to a managed-account-owned moved-in file.") ||
            !Expect(!CanOpen(work / L"moved-in.txt", GENERIC_READ),
                L"Relaunch unexpectedly granted access to a moved-in file."))
        {
            return 1;
        }
        std::wcout << L"AppContainer inheritance and relaunch propagation probes passed\n";
        return 0;
    }
    if (argc < 4)
    {
        return 2;
    }
    const std::filesystem::path work(argv[1]), outside(argv[2]);
    const DWORD expectedCapabilities = std::wstring_view(argv[3]) == L"capability" ? 1 : 0;
    UniqueHandle token;
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
    {
        return 1;
    }
    token.reset(raw);
    DWORD appContainer = 0, bytes = 0;
    std::vector<BYTE> capabilities, integrity;
    if (!Expect(
            GetTokenInformation(
                token.get(), TokenIsAppContainer, &appContainer, sizeof(appContainer), &bytes) &&
                appContainer == 1,
            L"Expected AppContainer token.") ||
        !Expect(QueryTokenInformation(token.get(), TokenCapabilities, capabilities) == 0 &&
                    reinterpret_cast<TOKEN_GROUPS*>(capabilities.data())->GroupCount ==
                        expectedCapabilities,
            L"Unexpected capabilities.") ||
        !Expect(QueryTokenInformation(token.get(), TokenIntegrityLevel, integrity) == 0 &&
                    IsWellKnownSid(
                        reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrity.data())->Label.Sid,
                        WinLowLabelSid),
            L"Expected Low integrity."))
    {
        return 1;
    }
    if (expectedCapabilities)
    {
        const auto* groups = reinterpret_cast<TOKEN_GROUPS*>(capabilities.data());
        if (!Expect(IsWellKnownSid(groups->Groups[0].Sid, WinCapabilityInternetClientSid),
                L"Capability name/SID did not resolve to internetClient."))
        {
            return 1;
        }
    }
    if (expectedCapabilities == 0)
    {
        const std::wstring name =
            L"launch-as-probe-" + std::to_wstring(GetTickCount64()) + L".example.com.";
        DNS_RECORDW* records = nullptr;
        const DNS_STATUS status = DnsQuery_W(
            name.c_str(), DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, nullptr, &records, nullptr);
        if (records)
        {
            DnsRecordListFree(records, DnsFreeRecordList);
        }
        DNS_QUERY_REQUEST request {};
        request.Version = DNS_QUERY_REQUEST_VERSION1;
        request.QueryName = name.c_str();
        request.QueryType = DNS_TYPE_A;
        request.QueryOptions = DNS_QUERY_BYPASS_CACHE;
        DNS_QUERY_RESULT result {};
        result.Version = DNS_QUERY_RESULTS_VERSION1;
        const DNS_STATUS extended = DnsQueryEx(&request, &result, nullptr);
        if (result.pQueryRecords)
        {
            DnsRecordListFree(result.pQueryRecords, DnsFreeRecordList);
        }
        if (!Expect(status == ERROR_ACCESS_DENIED && extended == ERROR_ACCESS_DENIED,
                L"Zero-capability DNS-service requests were not denied."))
        {
            return 1;
        }
    }
    if (!Expect(CanOpen(work / L"existing" / L"old.txt", GENERIC_READ | GENERIC_WRITE),
            L"Existing workspace file is not writable.") ||
        !Expect(HasMediumLabel(work) && HasMediumLabel(work / L"existing" / L"old.txt"),
            L"AppContainer preparation changed the Medium workspace labels.") ||
        !Expect(CanOpen(work / (expectedCapabilities ? L"new-capability.txt" : L"new-minimal.txt"),
                    GENERIC_WRITE,
                    CREATE_ALWAYS),
            L"Workspace create failed.") ||
        !Expect(!CanOpen(outside / L"outside.txt", GENERIC_READ), L"Outside read succeeded.") ||
        !Expect(!CanOpen(outside / L"outside.txt", GENERIC_WRITE), L"Outside write succeeded.") ||
        !Expect(!CanOpen(outside / L"outside.txt", WRITE_DAC), L"Outside ACL write succeeded.") ||
        !Expect(!CanOpen(outside / L"outside.txt", WRITE_OWNER),
            L"Outside ownership write succeeded.") ||
        !Expect(
            !CanOpen(work / L"protected.txt", GENERIC_READ), L"Protected child read succeeded.") ||
        !Expect(
            !CanOpen(work / L"junction" / L"outside.txt", GENERIC_READ), L"Junction escaped.") ||
        !Expect(!CanOpen(work / L"hardlink.txt", GENERIC_READ) &&
                    !CanOpen(outside / L"shared.txt", GENERIC_READ),
            L"A foreign-owned hard link was exposed without its owner's preparation."))
    {
        return 1;
    }
    std::wcout << L"Medium workspace writes passed without integrity relabelling\n";
    std::vector<wchar_t> profile(32'768);
    if (!GetEnvironmentVariableW(
            L"USERPROFILE", profile.data(), static_cast<DWORD>(profile.size())) ||
        !Expect(CanOpen(std::filesystem::path(profile.data()) / L"appcontainer-profile.txt",
                    GENERIC_WRITE,
                    CREATE_ALWAYS),
            L"Managed profile is not writable.") ||
        !Expect(CanOpen(std::filesystem::path(profile.data()) / L"appcontainer-existing" /
                            L"history.txt",
                    GENERIC_READ | GENERIC_WRITE),
            L"Existing managed-profile contents did not receive AppContainer access."))
    {
        return 1;
    }
    if (argc == 4)
    {
        UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        PROCESSENTRY32W entry {};
        entry.dwSize = sizeof(entry);
        DWORD parent = 0;
        if (snapshot && Process32FirstW(snapshot.get(), &entry))
        {
            do
            {
                if (entry.th32ProcessID == GetCurrentProcessId())
                {
                    parent = entry.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snapshot.get(), &entry));
        }
        if (!Expect(parent != 0, L"Could not identify the parent process."))
        {
            return 1;
        }
        for (const DWORD access : std::array<DWORD, 7> {
                 PROCESS_VM_READ,
                 PROCESS_VM_WRITE,
                 PROCESS_CREATE_THREAD,
                 PROCESS_DUP_HANDLE,
                 PROCESS_TERMINATE,
                 WRITE_DAC,
                 WRITE_OWNER
             })
        {
            UniqueHandle parentProcess(OpenProcess(access, FALSE, parent));
            const DWORD error = parentProcess ? ERROR_SUCCESS : GetLastError();
            if (!Expect(!parentProcess && error == ERROR_ACCESS_DENIED,
                    L"AppContainer can read or modify its parent process."))
            {
                return 1;
            }
        }
    }
    if (argc == 4)
    {
        std::wstring executable;
        if (GetCurrentExecutablePath(executable) != 0)
        {
            return 1;
        }
        const std::vector<std::wstring> arguments {
            work.native(), outside.native(), argv[3], L"descendant"
        };
        auto command = BuildWindowsCommandLine(executable, arguments);
        STARTUPINFOW startup {};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process {};
        if (!Expect(CreateProcessW(executable.c_str(),
                        command.data(),
                        nullptr,
                        nullptr,
                        FALSE,
                        0,
                        nullptr,
                        nullptr,
                        &startup,
                        &process),
                L"Could not start descendant."))
        {
            return 1;
        }
        UniqueHandle child(process.hProcess), thread(process.hThread);
        const DWORD wait = WaitForSingleObject(child.get(), 30'000);
        if (wait != WAIT_OBJECT_0)
        {
            TerminateProcess(child.get(), 1);
            return 1;
        }
        DWORD code = 1;
        if (!GetExitCodeProcess(child.get(), &code) ||
            !Expect(code == 0, L"Descendant restriction failed."))
        {
            return 1;
        }
    }
    std::wcout << L"AppContainer token, file, process and descendant probes passed\n";
    return 0;
}
