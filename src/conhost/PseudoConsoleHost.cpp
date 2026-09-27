// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "PseudoConsoleHost.h"

#include "PseudoConsoleHostInvocation.h"
#include "PseudoConsoleHostReport.h"
#include "PseudoConsoleSession.h"
#include "TerminalIO.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <io.h>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as
{
namespace
{

constexpr DWORD ProcessTerminationTimeoutMilliseconds = 5'000;

[[nodiscard]] bool OpenPipeClient(
    std::wstring_view pipeName, DWORD access, UniqueHandle& pipe, std::wstring& error)
{
    const std::wstring nullTerminatedPipeName(pipeName);
    HANDLE rawPipe = CreateFileW(nullTerminatedPipeName.c_str(),
        access,
        0,
        nullptr,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
        nullptr);
    if (rawPipe == INVALID_HANDLE_VALUE)
    {
        const DWORD pipeError = GetLastError();
        error = L"Could not open the broker terminal pipe: " + FormatWindowsError(pipeError);
        return false;
    }
    pipe.reset(rawPipe);
    return true;
}

} // namespace

ExitCode RunPseudoConsoleHost(std::span<wchar_t*> arguments)
{
    PseudoConsoleHostInvocation invocation;
    if (!ParsePseudoConsoleHostInvocation(arguments, invocation))
    {
        std::wcerr << L"Invalid internal pseudoconsole-host invocation.\n";
        return ExitUsage;
    }

    if (_setmode(_fileno(stderr), _O_U8TEXT) == -1)
    {
        std::wcerr << L"Could not configure pseudoconsole host diagnostics for UTF-8.\n";
        return ExitFailure;
    }
    UniqueHandle parentInput;
    UniqueHandle parentOutput;
    UniqueHandle resizeInput;
    std::wstring pipeError;
    if (!OpenPipeClient(invocation.pipeIn, GENERIC_READ, parentInput, pipeError) ||
        !OpenPipeClient(invocation.pipeOut, GENERIC_WRITE, parentOutput, pipeError) ||
        !OpenPipeClient(invocation.pipeResize, GENERIC_READ, resizeInput, pipeError))
    {
        std::wcerr << pipeError << L"\n";
        return ExitFailure;
    }
    if (!ReadTerminalSize(resizeInput.get(), invocation.terminalSize))
    {
        std::wcerr << L"Could not read the initial broker terminal size.\n";
        return ExitFailure;
    }

    std::error_code pathError;
    if (!invocation.executable.is_absolute() ||
        !std::filesystem::is_regular_file(invocation.executable, pathError))
    {
        std::wcerr << L"Pseudoconsole target is not an existing absolute file.\n";
        return ExitFailure;
    }

    PseudoConsoleSession pseudoConsole;
    std::wstring terminalError;
    if (!pseudoConsole.Initialize(invocation.terminalSize,
            invocation.inheritCursor,
            parentInput.get(),
            parentOutput.get(),
            resizeInput.get(),
            terminalError))
    {
        std::wcerr << terminalError << L"\n";
        return ExitFailure;
    }
    if (!pseudoConsole.StartRelays(terminalError))
    {
        std::wcerr << terminalError << L"\n";
        return ExitFailure;
    }

    std::wstring commandLine =
        BuildWindowsCommandLine(invocation.executable.native(), invocation.processArguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    PROCESS_INFORMATION processInformation {};
    if (!CreateProcessW(invocation.executable.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
            nullptr,
            nullptr,
            pseudoConsole.startupInfo(),
            &processInformation))
    {
        const DWORD processError = GetLastError();
        std::wcerr << L"Could not start the pseudoconsole child: "
                   << FormatWindowsError(processError) << L"\n";
        return ExitFailure;
    }
    UniqueHandle process(processInformation.hProcess);
    UniqueHandle thread(processInformation.hThread);

    const DWORD suspendedCount = ResumeThread(thread.get());
    const DWORD resumeError = suspendedCount == static_cast<DWORD>(-1)
                                  ? GetLastError()
                                  : (suspendedCount == 1 ? ERROR_SUCCESS : ERROR_INVALID_STATE);
    if (resumeError != ERROR_SUCCESS)
    {
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), ProcessTerminationTimeoutMilliseconds);
        std::wcerr << L"Could not resume the pseudoconsole child: "
                   << FormatWindowsError(resumeError) << L"\n";
        return ExitFailure;
    }

    const std::array<HANDLE, 2> waitHandles {process.get(), pseudoConsole.inputRelayFailedEvent()};
    const DWORD waitResult = WaitForMultipleObjects(
        static_cast<DWORD>(waitHandles.size()), waitHandles.data(), FALSE, INFINITE);
    if (waitResult == WAIT_OBJECT_0 + 1)
    {
        const BOOL terminated = TerminateProcess(process.get(), ExitCancelled);
        const DWORD terminationError = terminated ? ERROR_SUCCESS : GetLastError();
        const DWORD terminationWait =
            WaitForSingleObject(process.get(), ProcessTerminationTimeoutMilliseconds);
        pseudoConsole.StopRelays();
        if (terminationWait != WAIT_OBJECT_0)
        {
            if (!terminated)
            {
                std::wcerr << L"Could not terminate the pseudoconsole child after input relay "
                              L"failure: "
                           << FormatWindowsError(terminationError) << L"\n";
            }
            else
            {
                std::wcerr << L"The pseudoconsole child did not terminate after input relay "
                              L"failure.\n";
            }
            return ExitFailure;
        }
        return ExitCancelled;
    }
    if (waitResult != WAIT_OBJECT_0)
    {
        const DWORD waitError = waitResult == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
        pseudoConsole.StopRelays();
        if (waitResult == WAIT_FAILED)
        {
            std::wcerr << L"Could not wait for the pseudoconsole child: "
                       << FormatWindowsError(waitError) << L"\n";
        }
        else
        {
            std::wcerr << L"Unexpected pseudoconsole child wait result: " << waitResult << L"\n";
        }
        return ExitFailure;
    }
    pseudoConsole.StopRelays();

    DWORD childExitCode = 0;
    if (!GetExitCodeProcess(process.get(), &childExitCode))
    {
        const DWORD exitCodeError = GetLastError();
        std::wcerr << L"Could not read the pseudoconsole child exit code: "
                   << FormatWindowsError(exitCodeError) << L"\n";
        return ExitFailure;
    }
    const PseudoConsoleHostExitReport report {.childExitCode = childExitCode};
    DWORD bytesWritten = 0;
    const HANDLE reportPipe = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD reportError = reportPipe == INVALID_HANDLE_VALUE || reportPipe == nullptr ? GetLastError()
                                                                                    : ERROR_SUCCESS;
    if (reportError == ERROR_SUCCESS &&
        !WriteFile(reportPipe, &report, sizeof(report), &bytesWritten, nullptr))
    {
        reportError = GetLastError();
    }
    if (reportError != ERROR_SUCCESS || bytesWritten != sizeof(report))
    {
        if (reportError == ERROR_SUCCESS)
        {
            reportError = ERROR_WRITE_FAULT;
        }
        std::wcerr << L"Could not report the pseudoconsole child exit code: "
                   << FormatWindowsError(reportError) << L"\n";
        return ExitFailure;
    }
    return childExitCode;
}

} // namespace launch_as
