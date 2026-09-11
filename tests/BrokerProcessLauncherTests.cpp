// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

namespace
{

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] bool TestJobTerminationConfirmsActiveProcessZero()
{
    launch_as::broker::BrokerChildProcess child;
    if (!Expect(launch_as::broker::CreateBrokerJob(child) == ERROR_SUCCESS,
            L"Could not create the broker termination-test job."))
    {
        return false;
    }

    wchar_t systemDirectory[MAX_PATH] {};
    const UINT directoryLength = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (!Expect(directoryLength > 0 && directoryLength < MAX_PATH,
            L"Could not resolve the system directory for the broker termination test."))
    {
        return false;
    }
    const std::wstring executable = std::wstring(systemDirectory) + L"\\cmd.exe";
    std::wstring commandLine = L"\"" + executable + L"\" /d /c timeout /t 30 /nobreak >nul";
    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo {};
    if (!Expect(CreateProcessW(executable.c_str(),
                    commandLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW | CREATE_SUSPENDED,
                    nullptr,
                    nullptr,
                    &startupInfo,
                    &processInfo),
            L"Could not create the broker termination-test process."))
    {
        return false;
    }

    const bool assigned = AssignProcessToJobObject(child.job(), processInfo.hProcess) != FALSE;
    HANDLE observedJob = nullptr;
    const bool duplicated = assigned && DuplicateHandle(GetCurrentProcess(),
                                            child.job(),
                                            GetCurrentProcess(),
                                            &observedJob,
                                            0,
                                            FALSE,
                                            DUPLICATE_SAME_ACCESS) != FALSE;
    const bool resumed = assigned && ResumeThread(processInfo.hThread) != static_cast<DWORD>(-1);
    const bool terminated = duplicated && resumed && child.TerminateAndWaitForExit();
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting {};
    const bool queried = terminated && QueryInformationJobObject(observedJob,
                                           JobObjectBasicAccountingInformation,
                                           &accounting,
                                           sizeof(accounting),
                                           nullptr) != FALSE;
    const bool processExited =
        terminated && WaitForSingleObject(processInfo.hProcess, 5'000) == WAIT_OBJECT_0;
    if (!terminated)
    {
        TerminateProcess(processInfo.hProcess, ERROR_CANCELLED);
        static_cast<void>(WaitForSingleObject(processInfo.hProcess, INFINITE));
    }
    if (observedJob != nullptr)
    {
        CloseHandle(observedJob);
    }
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    return Expect(assigned, L"Could not assign the termination-test process to the broker job.") &&
           Expect(duplicated, L"Could not retain the termination-test Job for inspection.") &&
           Expect(resumed, L"Could not resume the broker termination-test process.") &&
           Expect(terminated, L"The broker could not confirm that its Job process tree exited.") &&
           Expect(queried && accounting.ActiveProcesses == 0,
               L"The broker finished teardown while the Job still had active processes.") &&
           Expect(
               processExited, L"The process assigned to the terminated broker Job did not exit.");
}

} // namespace

int wmain()
{
    if (!TestJobTerminationConfirmsActiveProcessZero())
    {
        return 1;
    }
    launch_as::broker::BrokerChildProcess child;
    if (!Expect(launch_as::broker::CreateBrokerJob(child) == ERROR_SUCCESS,
            L"Could not create the broker job."))
    {
        return 1;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    if (!Expect(
            QueryInformationJobObject(
                child.job(), JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr),
            L"Could not query the broker job limits."))
    {
        return 1;
    }
    if (!Expect((limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0,
            L"The broker job does not kill children when it closes."))
    {
        return 1;
    }
    if (!Expect(child.Resume() == ERROR_INVALID_HANDLE,
            L"The broker resumed a child that was not created."))
    {
        return 1;
    }
    HANDLE token = nullptr;
    if (!Expect(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token),
            L"Could not open the current process token."))
    {
        return 1;
    }
    std::vector<BYTE> currentLogonSid;
    const DWORD logonSidError = launch_as::broker::GetTokenLogonSid(token, currentLogonSid);
    CloseHandle(token);
    if (!Expect(logonSidError == ERROR_SUCCESS, L"Could not read the current logon SID."))
    {
        return 1;
    }
    return Expect(launch_as::broker::ValidateChildLogonSid(GetCurrentProcess(), currentLogonSid) ==
                      ERROR_ACCESS_DENIED,
               L"The broker accepted a child sharing the caller logon SID.")
               ? 0
               : 1;
}
