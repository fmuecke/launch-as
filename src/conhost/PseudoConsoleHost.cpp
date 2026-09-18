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

[[nodiscard]] bool PrepareResizeInput(HANDLE source, HANDLE output, bool redirectDiagnostics,
    UniqueHandle& resizeInput, std::wstring& error)
{
    if (!IsUsableHandle(source) || !IsUsableHandle(output))
    {
        error = L"The pseudoconsole host did not receive usable output and resize handles.";
        return false;
    }

    // STARTUPINFO's stderr slot transports the resize pipe. Retain it before _dup2
    // redirects CRT stderr to stdout, because _dup2 closes the old descriptor.
    HANDLE rawResizeInput = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &rawResizeInput,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS))
    {
        const DWORD duplicateError = GetLastError();
        error = L"Could not retain the pseudoconsole resize handle: " +
                FormatWindowsError(duplicateError);
        return false;
    }
    resizeInput.reset(rawResizeInput);

    if (!redirectDiagnostics)
    {
        return true;
    }
    if (_dup2(_fileno(stdout), _fileno(stderr)) != 0)
    {
        error = L"Could not redirect pseudoconsole host diagnostics.";
        return false;
    }
    if (!SetStdHandle(STD_ERROR_HANDLE, output))
    {
        const DWORD redirectError = GetLastError();
        error = L"Could not redirect the pseudoconsole host error handle: " +
                FormatWindowsError(redirectError);
        return false;
    }
    if (_setmode(_fileno(stderr), _O_U8TEXT) == -1)
    {
        error = L"Could not configure pseudoconsole host diagnostics for UTF-8.";
        return false;
    }
    return true;
}

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

    UniqueHandle brokerInput;
    UniqueHandle brokerOutput;
    UniqueHandle brokerResize;
    const bool brokerPipes = !invocation.pipeIn.empty();
    if (brokerPipes && _setmode(_fileno(stderr), _O_U8TEXT) == -1)
    {
        std::wcerr << L"Could not configure pseudoconsole host diagnostics for UTF-8.\n";
        return ExitFailure;
    }
    std::wstring pipeError;
    if (brokerPipes &&
        (!OpenPipeClient(invocation.pipeIn, GENERIC_READ, brokerInput, pipeError) ||
            !OpenPipeClient(invocation.pipeOut, GENERIC_WRITE, brokerOutput, pipeError) ||
            !OpenPipeClient(invocation.pipeResize, GENERIC_READ, brokerResize, pipeError)))
    {
        std::wcerr << pipeError << L"\n";
        return ExitFailure;
    }
    const HANDLE parentInput = brokerPipes ? brokerInput.get() : GetStdHandle(STD_INPUT_HANDLE);
    const HANDLE parentOutput = brokerPipes ? brokerOutput.get() : GetStdHandle(STD_OUTPUT_HANDLE);
    const HANDLE resizeSource = brokerPipes ? brokerResize.get() : GetStdHandle(STD_ERROR_HANDLE);
    UniqueHandle resizeInput;
    std::wstring streamError;
    if (!PrepareResizeInput(resizeSource, parentOutput, !brokerPipes, resizeInput, streamError))
    {
        std::wcerr << streamError << L"\n";
        return ExitFailure;
    }
    if (brokerPipes && !ReadTerminalSize(resizeInput.get(), invocation.terminalSize))
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
            parentInput,
            parentOutput,
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
    if (brokerPipes)
    {
        const PseudoConsoleHostExitReport report {.childExitCode = childExitCode};
        DWORD bytesWritten = 0;
        const HANDLE reportPipe = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD reportError = reportPipe == INVALID_HANDLE_VALUE || reportPipe == nullptr
                                ? GetLastError()
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
    }
    return childExitCode;
}

} // namespace launch_as
