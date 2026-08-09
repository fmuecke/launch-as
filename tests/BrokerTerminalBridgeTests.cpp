// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TerminalBridge.h"

#include <Windows.h>
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
    launch_as::TerminalBridge terminalBridge;
    launch_as::TerminalPipeNames pipeNames;
    std::wstring error;
    if (!Expect(terminalBridge.InitializeForBroker(L"", pipeNames, error),
            L"Could not create broker terminal pipes."))
    {
        return 1;
    }

    const ULONGLONG started = GetTickCount64();
    const bool connected = terminalBridge.ConnectBrokerChild(error);
    const ULONGLONG elapsed = GetTickCount64() - started;
    return Expect(!connected, L"The broker terminal bridge accepted an absent host.") &&
                   Expect(elapsed < 7'000,
                       L"The broker terminal bridge did not time out when the host was absent.") &&
                   Expect(error.find(L"Timed out") != std::wstring::npos,
                       L"The broker terminal bridge did not report its connection timeout.")
               ? 0
               : 1;
}
