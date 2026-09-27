// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TerminalBridge.h"
#include "TestSupport.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
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
constexpr DWORD ExpectedChildExitCode = 7;

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 3)
    {
        std::wcerr << L"Expected the pseudoconsole host and exit-code probe paths.\n";
        return 1;
    }

    const std::filesystem::path hostPath(arguments[1]);
    const std::filesystem::path exitCodeProbe(arguments[2]);
    if (!hostPath.is_absolute() || !std::filesystem::is_regular_file(hostPath) ||
        !exitCodeProbe.is_absolute() || !std::filesystem::is_regular_file(exitCodeProbe))
    {
        std::wcerr << L"The pseudoconsole host or exit-code probe path is invalid.\n";
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
    const bool initialized = terminalBridge.InitializeForBroker(L"", pipeNames, terminalError);
    if (!SetStdHandle(STD_INPUT_HANDLE, originalInput))
    {
        const DWORD inputError = GetLastError();
        std::wcerr << L"Could not restore the test process input: "
                   << FormatWindowsError(inputError) << L"\n";
        return 1;
    }
    if (!initialized)
    {
        std::wcerr << terminalError << L"\n";
        return 1;
    }

    // The host's stdout carries the broker exit report; without it the host fails its report.
    SECURITY_ATTRIBUTES inheritable {.nLength = sizeof(inheritable), .bInheritHandle = TRUE};
    HANDLE rawReportRead = nullptr;
    HANDLE rawReportWrite = nullptr;
    if (!CreatePipe(&rawReportRead, &rawReportWrite, &inheritable, 0))
    {
        const DWORD pipeError = GetLastError();
        std::wcerr << L"Could not create the host report pipe: " << FormatWindowsError(pipeError)
                   << L"\n";
        return 1;
    }
    UniqueHandle reportRead(rawReportRead);
    UniqueHandle reportWrite(rawReportWrite);
    UniqueHandle hostInput(launch_as::test::OpenInheritableNul(GENERIC_READ));
    UniqueHandle hostError(launch_as::test::DuplicateInheritableStandardError());
    if (!SetHandleInformation(reportRead.get(), HANDLE_FLAG_INHERIT, 0) || !hostInput || !hostError)
    {
        const DWORD handleError = GetLastError();
        std::wcerr << L"Could not prepare the host standard handles: "
                   << FormatWindowsError(handleError) << L"\n";
        return 1;
    }

    const std::vector<std::wstring> hostArguments {
        L"--internal-pseudoconsole-host",
        L"--size",
        L"120",
        L"30",
        L"--pipe-in",
        pipeNames.input,
        L"--pipe-out",
        pipeNames.output,
        L"--pipe-resize",
        pipeNames.resize,
        L"--",
        exitCodeProbe.native(),
        L"1000",
        L"7"
    };
    std::wstring commandLine = BuildWindowsCommandLine(hostPath.native(), hostArguments);
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
        std::wcerr << L"Could not start the disconnect-test host: "
                   << FormatWindowsError(processError) << L"\n";
        return 1;
    }
    UniqueHandle process(processInformation.hProcess);
    UniqueHandle thread(processInformation.hThread);
    reportWrite.reset();

    if (!terminalBridge.ConnectBrokerChild(terminalError) || !terminalBridge.Start(terminalError))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
        std::wcerr << terminalError << L"\n";
        return 1;
    }

    if (WaitForSingleObject(process.get(), 250) != WAIT_TIMEOUT)
    {
        terminalBridge.Stop();
        std::wcerr << L"The helper exited before redirected input reached EOF.\n";
        return 1;
    }

    terminalInputWrite.reset();
    const DWORD waitResult = WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
    if (waitResult != WAIT_OBJECT_0)
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
    }
    terminalBridge.Stop();

    if (waitResult != WAIT_OBJECT_0)
    {
        std::wcerr << L"The helper did not exit after redirected input reached EOF.\n";
        return 1;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(process.get(), &exitCode))
    {
        const DWORD exitCodeError = GetLastError();
        std::wcerr << L"Could not read the disconnect-test host exit code: "
                   << FormatWindowsError(exitCodeError) << L"\n";
        return 1;
    }
    if (exitCode != ExpectedChildExitCode)
    {
        std::wcerr << L"The host returned " << exitCode << L"; expected " << ExpectedChildExitCode
                   << L".\n";
        return 1;
    }

    std::wcout << L"Redirected stdin EOF preserved the helper exit code.\n";
    return 0;
}
