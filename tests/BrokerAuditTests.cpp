// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAudit.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <string>

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
    const std::array<std::wstring, 4> fields {
        L"operation=launch",
        L"requestId=123e4567-e89b-12d3-a456-426614174000",
        L"result=allowed",
        L"win32Error=0",
    };
    const DWORD auditError = launch_as::broker::WriteBrokerAuditEvent(
        EVENTLOG_INFORMATION_TYPE, launch_as::broker::BrokerAuditEvent::LaunchAllowed, fields);
    return Expect(auditError == ERROR_SUCCESS,
               L"Could not write the broker audit event to the Windows Application log.")
               ? 0
               : 1;
}
