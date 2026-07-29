// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TerminalBridge.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace
{

using launch_as::BuildWindowsCommandLine;
using launch_as::FormatWindowsError;
using launch_as::TerminalBridge;
using launch_as::UniqueHandle;

constexpr DWORD ProcessTimeoutMilliseconds = 10'000;
constexpr auto BridgeStopTimeout = std::chrono::seconds(2);

[[nodiscard]] bool VerifyTargetReceivesOnlyPipeClients()
{
    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);

    TerminalBridge bridge;
    std::wstring error;
    if (!bridge.Initialize(startupInformation, error))
    {
        std::wcerr << error << L"\n";
        return false;
    }

    const std::array<HANDLE, 3> targetHandles {
        startupInformation.hStdInput, startupInformation.hStdOutput, startupInformation.hStdError
    };
    for (const HANDLE handle : targetHandles)
    {
        DWORD flags = 0;
        if (!GetNamedPipeInfo(handle, &flags, nullptr, nullptr, nullptr))
        {
            const DWORD pipeInfoError = GetLastError();
            std::wcerr << L"Could not inspect a target terminal-pipe endpoint: "
                       << FormatWindowsError(pipeInfoError) << L"\n";
            return false;
        }
        if ((flags & PIPE_SERVER_END) != 0)
        {
            std::wcerr << L"The target received a terminal-pipe server endpoint.\n";
            return false;
        }
        if (ImpersonateNamedPipeClient(handle))
        {
            RevertToSelf();
            std::wcerr << L"A target terminal-pipe endpoint could impersonate its peer.\n";
            return false;
        }

        DWORD handleFlags = 0;
        if (!GetHandleInformation(handle, &handleFlags) || (handleFlags & HANDLE_FLAG_INHERIT) != 0)
        {
            std::wcerr << L"A target terminal-pipe client was inheritable outside the "
                          L"process-creation window.\n";
            return false;
        }
    }

    if (!bridge.PrepareChildProcessCreation(error))
    {
        std::wcerr << error << L"\n";
        return false;
    }
    for (const HANDLE handle : targetHandles)
    {
        DWORD handleFlags = 0;
        if (!GetHandleInformation(handle, &handleFlags) || (handleFlags & HANDLE_FLAG_INHERIT) == 0)
        {
            std::wcerr << L"A terminal-pipe client was not inheritable during process "
                          L"creation.\n";
            return false;
        }
    }
    if (!bridge.CompleteChildProcessCreation(false, error))
    {
        std::wcerr << error << L"\n";
        return false;
    }
    for (const HANDLE handle : targetHandles)
    {
        DWORD handleFlags = 0;
        if (!GetHandleInformation(handle, &handleFlags) || (handleFlags & HANDLE_FLAG_INHERIT) != 0)
        {
            std::wcerr << L"A terminal-pipe client remained inheritable after a failed "
                          L"process creation.\n";
            return false;
        }
    }
    return true;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 3)
    {
        std::wcerr << L"Expected the launcher and terminal-size probe paths.\n";
        return 1;
    }

    const std::filesystem::path launcherPath(arguments[1]);
    const std::filesystem::path terminalSizeProbe(arguments[2]);
    if (!launcherPath.is_absolute() || !std::filesystem::is_regular_file(launcherPath) ||
        !terminalSizeProbe.is_absolute() || !std::filesystem::is_regular_file(terminalSizeProbe))
    {
        std::wcerr << L"The launcher or terminal-size probe path is invalid.\n";
        return 1;
    }
    if (!VerifyTargetReceivesOnlyPipeClients())
    {
        return 1;
    }

    const std::vector<std::wstring> helperArguments {
        L"--internal-pseudoconsole-host",
        L"--size",
        L"120",
        L"30",
        L"--",
        terminalSizeProbe.native(),
        L"91",
        L"27"
    };
    std::wstring commandLine = BuildWindowsCommandLine(launcherPath.native(), helperArguments);

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

    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);
    TerminalBridge terminalBridge;
    std::wstring terminalError;
    const bool terminalInitialized = terminalBridge.Initialize(startupInformation, terminalError);
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

    HANDLE rawRetainedOutputClient = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(),
            startupInformation.hStdOutput,
            GetCurrentProcess(),
            &rawRetainedOutputClient,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS))
    {
        const DWORD duplicateError = GetLastError();
        std::wcerr << L"Could not retain a test output client: "
                   << FormatWindowsError(duplicateError) << L"\n";
        return 1;
    }
    UniqueHandle retainedOutputClient(rawRetainedOutputClient);

    PROCESS_INFORMATION processInformation {};
    if (!terminalBridge.PrepareChildProcessCreation(terminalError))
    {
        std::wcerr << terminalError << L"\n";
        return 1;
    }
    if (!CreateProcessW(launcherPath.c_str(),
            commandLine.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInformation,
            &processInformation))
    {
        const DWORD processError = GetLastError();
        if (!terminalBridge.CompleteChildProcessCreation(false, terminalError))
        {
            std::wcerr << terminalError << L"\n";
            return 1;
        }
        std::wcerr << L"Could not start the current-user ConPTY helper: "
                   << FormatWindowsError(processError) << L"\n";
        return 1;
    }
    if (!terminalBridge.CompleteChildProcessCreation(true, terminalError))
    {
        TerminateProcess(processInformation.hProcess, 1);
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        std::wcerr << terminalError << L"\n";
        return 1;
    }
    DWORD inheritedHandleFlags = 0;
    if (GetHandleInformation(startupInformation.hStdInput, &inheritedHandleFlags) ||
        GetHandleInformation(startupInformation.hStdOutput, &inheritedHandleFlags) ||
        GetHandleInformation(startupInformation.hStdError, &inheritedHandleFlags))
    {
        TerminateProcess(processInformation.hProcess, 1);
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        std::wcerr << L"The parent retained a target terminal-pipe client after process "
                      L"creation.\n";
        return 1;
    }
    UniqueHandle process(processInformation.hProcess);
    UniqueHandle thread(processInformation.hThread);
    if (!terminalBridge.Start(terminalError))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
        std::wcerr << terminalError << L"\n";
        return 1;
    }
    if (!terminalBridge.SendResize(COORD {91, 27}))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
        terminalBridge.Stop();
        std::wcerr << L"Could not send the test terminal size.\n";
        return 1;
    }

    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
    {
        const DWORD resumeError = GetLastError();
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), ProcessTimeoutMilliseconds);
        terminalBridge.Stop();
        std::wcerr << L"Could not resume the current-user ConPTY helper: "
                   << FormatWindowsError(resumeError) << L"\n";
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
    const auto stopStarted = std::chrono::steady_clock::now();
    terminalBridge.Stop();
    if (std::chrono::steady_clock::now() - stopStarted > BridgeStopTimeout)
    {
        std::wcerr << L"The terminal bridge waited indefinitely for a retained output client.\n";
        return 1;
    }

    if (waitResult != WAIT_OBJECT_0)
    {
        std::wcerr << L"The current-user ConPTY helper did not exit in time.\n";
        return 1;
    }
    if (!exitCodeRead || exitCode != 0)
    {
        std::wcerr << L"The current-user ConPTY helper returned " << exitCode << L"; expected 0.\n";
        return 1;
    }
    std::wcout << L"Hidden current-user ConPTY helper completed.\n";
    return 0;
}
