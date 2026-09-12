// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TerminalBridge.h"
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

constexpr int SkipNoConsoleAttached = 77;
constexpr DWORD StopWithConsoleStdinTimeoutMilliseconds = 2'000;
constexpr ULONGLONG BrokerConnectionTimeoutBoundMilliseconds = 1'000;

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] bool VerifyHostWaitsForInitialResize(const std::filesystem::path& launcherPath)
{
    launch_as::TerminalBridge terminalBridge;
    launch_as::TerminalPipeNames pipeNames;
    std::wstring error;
    if (!terminalBridge.InitializeForBroker(L"", pipeNames, error))
    {
        std::wcerr << error << L"\n";
        return false;
    }

    std::array<wchar_t, MAX_PATH> systemDirectory {};
    if (GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size())) == 0)
    {
        std::wcerr << L"Could not find the Windows system directory.\n";
        return false;
    }
    const std::filesystem::path commandProcessor =
        std::filesystem::path(systemDirectory.data()) / L"cmd.exe";
    const std::vector<std::wstring> arguments {
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
        commandProcessor.native(),
        L"/d",
        L"/c",
        L"exit 0",
    };
    std::wstring commandLine = launch_as::BuildWindowsCommandLine(launcherPath.native(), arguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);
    PROCESS_INFORMATION processInformation {};
    if (!CreateProcessW(launcherPath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInformation,
            &processInformation))
    {
        const DWORD processError = GetLastError();
        std::wcerr << L"Could not start the broker pseudoconsole host: "
                   << launch_as::FormatWindowsError(processError) << L"\n";
        return false;
    }
    launch_as::UniqueHandle process(processInformation.hProcess);
    launch_as::UniqueHandle thread(processInformation.hThread);

    if (!terminalBridge.ConnectBrokerChild(error))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), 5'000);
        std::wcerr << error << L"\n";
        return false;
    }
    if (WaitForSingleObject(process.get(), 250) != WAIT_TIMEOUT)
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), 5'000);
        std::wcerr << L"The broker pseudoconsole host did not wait for the initial resize.\n";
        return false;
    }
    if (!terminalBridge.Start(error))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), 5'000);
        std::wcerr << error << L"\n";
        return false;
    }
    const DWORD hostWait = WaitForSingleObject(process.get(), 5'000);
    terminalBridge.Stop();
    return Expect(hostWait == WAIT_OBJECT_0,
        L"The broker pseudoconsole host did not finish after receiving its initial resize.");
}

// C4 regression: CancelSynchronousIo does not unblock a pending console ReadFile, so Stop()
// used to hang until the next keystroke whenever stdin was a real console handle. Opens CONIN$,
// runs a real broker terminal session against it, and asserts Stop() still returns promptly with
// no console input pending.
[[nodiscard]] bool VerifyStopReturnsPromptlyWithConsoleStdin(
    const std::filesystem::path& launcherPath, bool& skipped)
{
    skipped = false;
    HANDLE rawConsoleInput = CreateFileW(L"CONIN$",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (rawConsoleInput == INVALID_HANDLE_VALUE)
    {
        skipped = true;
        return true;
    }
    launch_as::UniqueHandle consoleInput(rawConsoleInput);

    const HANDLE originalStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (!SetStdHandle(STD_INPUT_HANDLE, consoleInput.get()))
    {
        const DWORD overrideError = GetLastError();
        std::wcerr << L"Could not install the console stdin override: "
                   << launch_as::FormatWindowsError(overrideError) << L"\n";
        return false;
    }

    launch_as::TerminalBridge terminalBridge;
    launch_as::TerminalPipeNames pipeNames;
    std::wstring error;
    const bool initialized = terminalBridge.InitializeForBroker(L"", pipeNames, error);
    SetStdHandle(STD_INPUT_HANDLE, originalStdin);
    if (!initialized)
    {
        std::wcerr << error << L"\n";
        return false;
    }

    std::array<wchar_t, MAX_PATH> systemDirectory {};
    if (GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size())) == 0)
    {
        std::wcerr << L"Could not find the Windows system directory.\n";
        return false;
    }
    const std::filesystem::path commandProcessor =
        std::filesystem::path(systemDirectory.data()) / L"cmd.exe";
    const std::vector<std::wstring> arguments {
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
        commandProcessor.native(),
        L"/d",
        L"/c",
        L"exit 0",
    };
    std::wstring commandLine = launch_as::BuildWindowsCommandLine(launcherPath.native(), arguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);
    PROCESS_INFORMATION processInformation {};
    if (!CreateProcessW(launcherPath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInformation,
            &processInformation))
    {
        const DWORD processError = GetLastError();
        std::wcerr << L"Could not start the broker pseudoconsole host: "
                   << launch_as::FormatWindowsError(processError) << L"\n";
        return false;
    }
    launch_as::UniqueHandle process(processInformation.hProcess);
    launch_as::UniqueHandle thread(processInformation.hThread);

    if (!terminalBridge.ConnectBrokerChild(error))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), 5'000);
        std::wcerr << error << L"\n";
        return false;
    }
    if (!terminalBridge.Start(error))
    {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), 5'000);
        std::wcerr << error << L"\n";
        return false;
    }

    const ULONGLONG started = GetTickCount64();
    terminalBridge.Stop();
    const ULONGLONG elapsed = GetTickCount64() - started;

    TerminateProcess(process.get(), 1);
    WaitForSingleObject(process.get(), 5'000);

    return Expect(elapsed < StopWithConsoleStdinTimeoutMilliseconds,
        L"TerminalBridge::Stop() did not return promptly with console stdin.");
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
    if (!launcherPath.is_absolute() || !std::filesystem::is_regular_file(launcherPath))
    {
        std::wcerr << L"The launcher path is invalid.\n";
        return 1;
    }
    launch_as::TerminalBridge terminalBridge;
    launch_as::TerminalPipeNames pipeNames;
    std::wstring error;
    if (!Expect(terminalBridge.InitializeForBroker(L"S-1-5-32-545", pipeNames, error),
            L"Could not create broker terminal pipes."))
    {
        return 1;
    }

    launch_as::TerminalBridge invalidSidBridge;
    launch_as::TerminalPipeNames invalidSidPipeNames;
    std::wstring invalidSidError;
    const bool invalidSidRejected =
        !invalidSidBridge.InitializeForBroker(L"not-a-sid", invalidSidPipeNames, invalidSidError);

    const ULONGLONG started = GetTickCount64();
    const bool connected = terminalBridge.ConnectBrokerChild(error);
    const ULONGLONG elapsed = GetTickCount64() - started;

    bool skipConsoleStdinTest = false;
    const bool consoleStdinTestPassed =
        VerifyStopReturnsPromptlyWithConsoleStdin(launcherPath, skipConsoleStdinTest);
    if (skipConsoleStdinTest)
    {
        std::wcout << L"Skipped: no console is attached to exercise the console-stdin input "
                      L"relay.\n";
        return SkipNoConsoleAttached;
    }

    return Expect(
               invalidSidRejected, L"The broker terminal bridge accepted an invalid child SID.") &&
                   Expect(!connected, L"The broker terminal bridge accepted an absent host.") &&
                   Expect(elapsed < BrokerConnectionTimeoutBoundMilliseconds,
                       L"The broker terminal bridge did not time out when the host was absent.") &&
                   Expect(error.find(L"Timed out") != std::wstring::npos,
                       L"The broker terminal bridge did not report its connection timeout.") &&
                   VerifyHostWaitsForInitialResize(launcherPath) && consoleStdinTestPassed
               ? 0
               : 1;
}
