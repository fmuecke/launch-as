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

[[nodiscard]] std::filesystem::path GetCommandPromptPath()
{
    std::array<wchar_t, MAX_PATH> systemDirectory {};
    const UINT characters =
        GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size()));
    if (characters == 0 || characters >= systemDirectory.size())
    {
        return {};
    }
    return std::filesystem::path(std::wstring(systemDirectory.data(), characters)) / L"cmd.exe";
}

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

    const std::array<HANDLE, 2> targetHandles {
        startupInformation.hStdInput, startupInformation.hStdOutput
    };
    for (const HANDLE handle : targetHandles)
    {
        DWORD flags = 0;
        if (!GetNamedPipeInfo(handle, &flags, nullptr, nullptr, nullptr))
        {
            std::wcerr << L"Could not inspect a target terminal-pipe endpoint: "
                       << FormatWindowsError(GetLastError()) << L"\n";
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
    if (argumentCount != 2)
    {
        std::wcerr << L"Expected the launcher path.\n";
        return 1;
    }

    const std::filesystem::path launcherPath(arguments[1]);
    const std::filesystem::path commandPrompt = GetCommandPromptPath();
    if (!launcherPath.is_absolute() || !std::filesystem::is_regular_file(launcherPath) ||
        commandPrompt.empty())
    {
        std::wcerr << L"The launcher or cmd.exe path is invalid.\n";
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
        commandPrompt.native(),
        L"/d",
        L"/c",
        L"(for /L %i in (1,1,256) do @echo conpty-smoke-%i)"
    };
    std::wstring commandLine = BuildWindowsCommandLine(launcherPath.native(), helperArguments);

    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);
    TerminalBridge terminalBridge;
    std::wstring terminalError;
    if (!terminalBridge.Initialize(startupInformation, terminalError))
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
        std::wcerr << L"Could not retain a test output client: "
                   << FormatWindowsError(GetLastError()) << L"\n";
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
        GetHandleInformation(startupInformation.hStdOutput, &inheritedHandleFlags))
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
