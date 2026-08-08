// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"

#include <Windows.h>
#include <iostream>

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
    return Expect(
               (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0,
               L"The broker job does not kill children when it closes.")
               ? 0
               : 1;
}
