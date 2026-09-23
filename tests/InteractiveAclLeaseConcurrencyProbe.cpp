// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "InteractiveDesktopAclLease.h"

#include <Sddl.h>
#include <Windows.h>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr DWORD ProbeTimeoutMilliseconds = 10'000;
constexpr int ProbeRounds = 40;

struct Worker final
{
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
    HANDLE ready = nullptr;
    HANDLE start = nullptr;
    HANDLE acquired = nullptr;
    HANDLE release = nullptr;
    HANDLE done = nullptr;
    std::wstring sid;
};

void CloseWorker(Worker& worker)
{
    for (HANDLE handle :
        {worker.process,
            worker.thread,
            worker.ready,
            worker.start,
            worker.acquired,
            worker.release,
            worker.done})
    {
        if (handle != nullptr)
        {
            CloseHandle(handle);
        }
    }
}

[[nodiscard]] bool WaitForSignal(HANDLE signal, HANDLE process)
{
    const std::array handles {signal, process};
    return WaitForMultipleObjects(static_cast<DWORD>(handles.size()),
               handles.data(),
               FALSE,
               ProbeTimeoutMilliseconds) == WAIT_OBJECT_0;
}

[[nodiscard]] bool HasLeaseAce(HANDLE object, PSID sid, bool expected)
{
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION;
    DWORD required = 0;
    GetUserObjectSecurity(object, &information, nullptr, 0, &required);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return false;
    }
    std::vector<BYTE> descriptor(required);
    if (!GetUserObjectSecurity(object, &information, descriptor.data(), required, &required))
    {
        return false;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(descriptor.data(), &present, &dacl, &defaulted) || !present ||
        dacl == nullptr)
    {
        return false;
    }
    ACL_SIZE_INFORMATION size {};
    if (!GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation))
    {
        return false;
    }
    DWORD count = 0;
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(dacl, index, &rawAce))
        {
            return false;
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE)
        {
            const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(rawAce);
            auto* aceSid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
            if (EqualSid(aceSid, sid))
            {
                ++count;
            }
        }
    }
    return expected ? count == 1 : count == 0;
}

[[nodiscard]] bool CheckGrants(
    PSID firstSid, bool firstExpected, PSID secondSid, bool secondExpected)
{
    HWINSTA station = OpenWindowStationW(L"WinSta0", FALSE, READ_CONTROL);
    HDESK desktop = OpenDesktopW(L"Default", 0, FALSE, READ_CONTROL);
    const bool matches = station != nullptr && desktop != nullptr &&
                         HasLeaseAce(station, firstSid, firstExpected) &&
                         HasLeaseAce(station, secondSid, secondExpected) &&
                         HasLeaseAce(desktop, firstSid, firstExpected) &&
                         HasLeaseAce(desktop, secondSid, secondExpected);
    if (desktop != nullptr)
    {
        CloseDesktop(desktop);
    }
    if (station != nullptr)
    {
        CloseWindowStation(station);
    }
    return matches;
}

[[nodiscard]] HANDLE CreateProbeEvent(
    std::wstring_view prefix, std::wstring_view id, int workerIndex)
{
    const std::wstring name = L"Local\\launch-as-acl-probe-" + std::wstring(id) + L"-" +
                              std::to_wstring(workerIndex) + L"-" + std::wstring(prefix);
    return CreateEventW(nullptr, FALSE, FALSE, name.c_str());
}

[[nodiscard]] bool StartWorker(
    Worker& worker, std::wstring_view executable, std::wstring_view id, int index)
{
    worker.sid = L"S-1-5-5-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                 std::to_wstring(static_cast<DWORD>(GetTickCount64()) + index + 1);
    worker.ready = CreateProbeEvent(L"ready", id, index);
    worker.start = CreateProbeEvent(L"start", id, index);
    worker.acquired = CreateProbeEvent(L"acquired", id, index);
    worker.release = CreateProbeEvent(L"release", id, index);
    worker.done = CreateProbeEvent(L"done", id, index);
    if (worker.ready == nullptr || worker.start == nullptr || worker.acquired == nullptr ||
        worker.release == nullptr || worker.done == nullptr)
    {
        return false;
    }
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --worker " + std::wstring(id) +
                           L" " + std::to_wstring(index) + L" " + worker.sid;
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process {};
    if (!CreateProcessW(executable.data(),
            command.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startup,
            &process))
    {
        return false;
    }
    worker.process = process.hProcess;
    worker.thread = process.hThread;
    return WaitForSignal(worker.ready, worker.process);
}

[[nodiscard]] DWORD RunWorker(std::wstring_view id, int index, std::wstring_view sidText)
{
    Worker events;
    events.ready = CreateProbeEvent(L"ready", id, index);
    events.start = CreateProbeEvent(L"start", id, index);
    events.acquired = CreateProbeEvent(L"acquired", id, index);
    events.release = CreateProbeEvent(L"release", id, index);
    events.done = CreateProbeEvent(L"done", id, index);
    PSID sid = nullptr;
    const std::wstring sidString(sidText);
    if (events.ready == nullptr || events.start == nullptr || events.acquired == nullptr ||
        events.release == nullptr || events.done == nullptr ||
        !ConvertStringSidToSidW(sidString.c_str(), &sid))
    {
        CloseWorker(events);
        return ERROR_INVALID_PARAMETER;
    }
    SetEvent(events.ready);
    DWORD result = ERROR_SUCCESS;
    for (int round = 0; round < ProbeRounds; ++round)
    {
        if (WaitForSingleObject(events.start, ProbeTimeoutMilliseconds) != WAIT_OBJECT_0)
        {
            result = ERROR_TIMEOUT;
            break;
        }
        launch_as::InteractiveDesktopAclLease lease;
        result = lease.Acquire(sid);
        if (result != ERROR_SUCCESS)
        {
            break;
        }
        SetEvent(events.acquired);
        if (WaitForSingleObject(events.release, ProbeTimeoutMilliseconds) != WAIT_OBJECT_0)
        {
            result = ERROR_TIMEOUT;
            break;
        }
        result = lease.Release();
        if (result != ERROR_SUCCESS)
        {
            break;
        }
        SetEvent(events.done);
    }
    LocalFree(sid);
    CloseWorker(events);
    return result;
}

[[nodiscard]] DWORD RunParent(const std::filesystem::path& resultPath)
{
    wchar_t executable[MAX_PATH] {};
    const DWORD pathLength = GetModuleFileNameW(nullptr, executable, MAX_PATH);
    const std::wstring id =
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    Worker first;
    Worker second;
    bool succeeded = pathLength > 0 && pathLength < MAX_PATH &&
                     StartWorker(first, executable, id, 0) &&
                     StartWorker(second, executable, id, 1);
    PSID firstSid = nullptr;
    PSID secondSid = nullptr;
    if (succeeded)
    {
        succeeded = ConvertStringSidToSidW(first.sid.c_str(), &firstSid) &&
                    ConvertStringSidToSidW(second.sid.c_str(), &secondSid);
    }
    for (int round = 0; succeeded && round < ProbeRounds; ++round)
    {
        succeeded = SetEvent(first.start) && SetEvent(second.start) &&
                    WaitForSignal(first.acquired, first.process) &&
                    WaitForSignal(second.acquired, second.process) &&
                    CheckGrants(firstSid, true, secondSid, true) && SetEvent(first.release) &&
                    WaitForSignal(first.done, first.process) &&
                    CheckGrants(firstSid, false, secondSid, true) && SetEvent(second.release) &&
                    WaitForSignal(second.done, second.process) &&
                    CheckGrants(firstSid, false, secondSid, false);
    }
    if (first.start != nullptr)
    {
        SetEvent(first.start);
        SetEvent(first.release);
    }
    if (second.start != nullptr)
    {
        SetEvent(second.start);
        SetEvent(second.release);
    }
    if (first.process != nullptr &&
        WaitForSingleObject(first.process, ProbeTimeoutMilliseconds) != WAIT_OBJECT_0)
    {
        succeeded = false;
    }
    if (second.process != nullptr &&
        WaitForSingleObject(second.process, ProbeTimeoutMilliseconds) != WAIT_OBJECT_0)
    {
        succeeded = false;
    }
    DWORD firstExitCode = ERROR_CANCELLED;
    DWORD secondExitCode = ERROR_CANCELLED;
    if (first.process != nullptr)
    {
        GetExitCodeProcess(first.process, &firstExitCode);
    }
    if (second.process != nullptr)
    {
        GetExitCodeProcess(second.process, &secondExitCode);
    }
    succeeded = succeeded && firstExitCode == ERROR_SUCCESS && secondExitCode == ERROR_SUCCESS;
    if (firstSid != nullptr)
    {
        LocalFree(firstSid);
    }
    if (secondSid != nullptr)
    {
        LocalFree(secondSid);
    }
    CloseWorker(first);
    CloseWorker(second);
    std::ofstream result(resultPath, std::ios::binary | std::ios::trunc);
    result << "probeRounds=" << ProbeRounds << '\n';
    result << "firstWorkerExitCode=" << firstExitCode << '\n';
    result << "secondWorkerExitCode=" << secondExitCode << '\n';
    result << "probeSucceeded=" << (succeeded ? "true" : "false") << '\n';
    return result.good() && succeeded ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount == 5 && std::wstring_view(arguments[1]) == L"--worker")
    {
        return RunWorker(arguments[2], _wtoi(arguments[3]), arguments[4]);
    }
    return argumentCount == 2 ? RunParent(arguments[1]) : ERROR_INVALID_PARAMETER;
}
