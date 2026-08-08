// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"

#include <Windows.h>
#include <iostream>
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

} // namespace

int wmain()
{
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
