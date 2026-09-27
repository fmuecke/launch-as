// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TerminalBridge.h"
#include "TestSupport.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace
{

using launch_as::BuildWindowsCommandLine;
using launch_as::FormatWindowsError;
using launch_as::TerminalBridge;
using launch_as::TerminalPipeNames;
using launch_as::UniqueHandle;

constexpr DWORD ProcessTimeoutMilliseconds = 10'000;
constexpr DWORD ProbeReadyTimeoutMilliseconds = 5'000;

// Starts the pseudoconsole host against the bridge's named pipes. Its stdout carries the
// broker exit report, as in production; keep reportRead open until the host exits.
[[nodiscard]] bool StartHost(const std::filesystem::path& hostPath, const TerminalPipeNames& pipes,
    const std::vector<std::wstring>& target, UniqueHandle& process, UniqueHandle& reportRead)
{
    SECURITY_ATTRIBUTES inheritable {.nLength = sizeof(inheritable), .bInheritHandle = TRUE};
    HANDLE rawReportRead = nullptr;
    HANDLE rawReportWrite = nullptr;
    if (!CreatePipe(&rawReportRead, &rawReportWrite, &inheritable, 0))
    {
        const DWORD pipeError = GetLastError();
        std::wcerr << L"Could not create the host report pipe: " << FormatWindowsError(pipeError)
                   << L"\n";
        return false;
    }
    reportRead.reset(rawReportRead);
    UniqueHandle reportWrite(rawReportWrite);
    UniqueHandle hostInput(launch_as::test::OpenInheritableNul(GENERIC_READ));
    UniqueHandle hostError(launch_as::test::DuplicateInheritableStandardError());
    if (!SetHandleInformation(reportRead.get(), HANDLE_FLAG_INHERIT, 0) || !hostInput || !hostError)
    {
        const DWORD handleError = GetLastError();
        std::wcerr << L"Could not prepare the host standard handles: "
                   << FormatWindowsError(handleError) << L"\n";
        return false;
    }

    std::vector<std::wstring> arguments {
        L"--internal-pseudoconsole-host",
        L"--pipe-in",
        pipes.input,
        L"--pipe-out",
        pipes.output,
        L"--pipe-resize",
        pipes.resize,
        L"--"
    };
    arguments.insert(arguments.end(), target.begin(), target.end());
    std::wstring commandLine = BuildWindowsCommandLine(hostPath.native(), arguments);

    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);
    startupInformation.dwFlags = STARTF_USESTDHANDLES;
    startupInformation.hStdInput = hostInput.get();
    startupInformation.hStdOutput = reportWrite.get();
    startupInformation.hStdError = hostError.get();
    PROCESS_INFORMATION processInformation {};
    if (!CreateProcessW(hostPath.c_str(),
            commandLine.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInformation,
            &processInformation))
    {
        const DWORD processError = GetLastError();
        std::wcerr << L"Could not start the pseudoconsole host: "
                   << FormatWindowsError(processError) << L"\n";
        return false;
    }
    CloseHandle(processInformation.hThread);
    process.reset(processInformation.hProcess);
    return true;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 3)
    {
        std::wcerr << L"Expected the pseudoconsole host and terminal-size probe paths.\n";
        return 1;
    }

    const std::filesystem::path hostPath(arguments[1]);
    const std::filesystem::path terminalSizeProbe(arguments[2]);
    if (!hostPath.is_absolute() || !std::filesystem::is_regular_file(hostPath) ||
        !terminalSizeProbe.is_absolute() || !std::filesystem::is_regular_file(terminalSizeProbe))
    {
        std::wcerr << L"The pseudoconsole host or terminal-size probe path is invalid.\n";
        return 1;
    }
    TerminalBridge unopenedBridge;
    DWORD resizeError = ERROR_SUCCESS;
    if (unopenedBridge.SendResize(COORD {120, 30}, resizeError) ||
        resizeError != ERROR_INVALID_HANDLE)
    {
        std::wcerr << L"An unopened terminal bridge did not report its resize write error.\n";
        return 1;
    }

    const std::wstring readyEventName =
        L"Local\\launch-as-terminal-size-ready-" + std::to_wstring(GetCurrentProcessId());
    UniqueHandle readyEvent(CreateEventW(nullptr, TRUE, FALSE, readyEventName.c_str()));
    if (!readyEvent)
    {
        std::wcerr << L"Could not create the terminal-size probe readiness event.\n";
        return 1;
    }

    HANDLE rawTerminalInputRead = nullptr;
    HANDLE rawTerminalInputWrite = nullptr;
    if (!CreatePipe(&rawTerminalInputRead, &rawTerminalInputWrite, nullptr, 0))
    {
        const DWORD pipeError = GetLastError();
        std::wcerr << L"Could not create the simulated terminal input: "
                   << FormatWindowsError(pipeError) << L"\n";
        return 1;
    }
    UniqueHandle terminalInputRead(rawTerminalInputRead);
    UniqueHandle terminalInputWrite(rawTerminalInputWrite);

    const HANDLE originalInput = GetStdHandle(STD_INPUT_HANDLE);
    if (!SetStdHandle(STD_INPUT_HANDLE, terminalInputRead.get()))
    {
        const DWORD inputError = GetLastError();
        std::wcerr << L"Could not install the simulated terminal input: "
                   << FormatWindowsError(inputError) << L"\n";
        return 1;
    }
    TerminalBridge terminalBridge;
    TerminalPipeNames pipeNames;
    std::wstring terminalError;
    const bool terminalInitialized =
        terminalBridge.InitializeForBroker(L"", pipeNames, terminalError);
    if (!SetStdHandle(STD_INPUT_HANDLE, originalInput))
    {
        const DWORD inputError = GetLastError();
        std::wcerr << L"Could not restore the test process input: "
                   << FormatWindowsError(inputError) << L"\n";
        return 1;
    }
    if (!terminalInitialized)
    {
        std::wcerr << terminalError << L"\n";
        return 1;
    }

    UniqueHandle process;
    UniqueHandle reportRead;
    if (!StartHost(hostPath,
            pipeNames,
            {terminalSizeProbe.native(), L"91", L"27", readyEventName},
            process,
            reportRead))
    {
        return 1;
    }
    if (!terminalBridge.ConnectBrokerChild(terminalError) || !terminalBridge.Start(terminalError))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
        std::wcerr << terminalError << L"\n";
        return 1;
    }

    // Test a resize of an attached console, not a race with ConPTY/child initialization.
    const std::array<HANDLE, 2> readyHandles {readyEvent.get(), process.get()};
    if (WaitForMultipleObjects(static_cast<DWORD>(readyHandles.size()),
            readyHandles.data(),
            FALSE,
            ProbeReadyTimeoutMilliseconds) != WAIT_OBJECT_0 ||
        !terminalBridge.SendResize(COORD {91, 27}, resizeError))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
        terminalBridge.Stop();
        std::wcerr << L"The terminal-size probe did not become ready or receive its resize.\n";
        return 1;
    }

    const DWORD waitResult = WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
    DWORD exitCode = 0;
    const bool exitCodeRead =
        waitResult == WAIT_OBJECT_0 && GetExitCodeProcess(process.get(), &exitCode);
    if (waitResult != WAIT_OBJECT_0)
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
    }
    terminalBridge.Stop();

    if (waitResult != WAIT_OBJECT_0)
    {
        std::wcerr << L"The pseudoconsole host did not exit in time.\n";
        return 1;
    }
    if (!exitCodeRead || exitCode != 0)
    {
        std::wcerr << L"The pseudoconsole host returned " << exitCode << L"; expected 0.\n";
        return 1;
    }
    std::wcout << L"Hidden current-user ConPTY helper completed.\n";
    return 0;
}
