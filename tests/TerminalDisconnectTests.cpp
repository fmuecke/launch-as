// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LauncherOptions.h"
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

using launch_as::BuildWindowsCommandLine;
using launch_as::ExitCancelled;
using launch_as::FormatWindowsError;
using launch_as::TerminalBridge;
using launch_as::UniqueHandle;

constexpr DWORD ProcessTimeoutMilliseconds = 10'000;

class StandardInputOverride final
{
  public:
    explicit StandardInputOverride(HANDLE replacement) noexcept
        : original_(GetStdHandle(STD_INPUT_HANDLE))
    {
        active_ = SetStdHandle(STD_INPUT_HANDLE, replacement) != FALSE;
        if (!active_)
        {
            error_ = GetLastError();
        }
    }

    ~StandardInputOverride()
    {
        if (active_)
        {
            SetStdHandle(STD_INPUT_HANDLE, original_);
        }
    }

    StandardInputOverride(const StandardInputOverride&) = delete;
    StandardInputOverride& operator=(const StandardInputOverride&) = delete;

    [[nodiscard]] bool active() const noexcept { return active_; }
    [[nodiscard]] DWORD error() const noexcept { return error_; }

    [[nodiscard]] bool Restore() noexcept
    {
        if (!active_)
        {
            return true;
        }
        if (!SetStdHandle(STD_INPUT_HANDLE, original_))
        {
            error_ = GetLastError();
            return false;
        }
        active_ = false;
        return true;
    }

  private:
    HANDLE original_ = nullptr;
    DWORD error_ = ERROR_SUCCESS;
    bool active_ = false;
};

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

    StandardInputOverride inputOverride(terminalInputRead.get());
    if (!inputOverride.active())
    {
        std::wcerr << L"Could not install the simulated terminal input: "
                   << FormatWindowsError(inputOverride.error()) << L"\n";
        return 1;
    }

    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);
    TerminalBridge terminalBridge;
    std::wstring terminalError;
    const bool initialized = terminalBridge.Initialize(startupInformation, terminalError);
    if (!inputOverride.Restore())
    {
        std::wcerr << L"Could not restore the test process input: "
                   << FormatWindowsError(inputOverride.error()) << L"\n";
        return 1;
    }
    if (!initialized)
    {
        std::wcerr << terminalError << L"\n";
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
        L"/q"
    };
    std::wstring commandLine = BuildWindowsCommandLine(launcherPath.native(), helperArguments);

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
        std::wcerr << L"Could not start the disconnect-test helper: "
                   << FormatWindowsError(processError) << L"\n";
        return 1;
    }
    UniqueHandle process(processInformation.hProcess);
    UniqueHandle thread(processInformation.hThread);
    if (!terminalBridge.CompleteChildProcessCreation(true, terminalError))
    {
        TerminateProcess(process.get(), 1);
        std::wcerr << terminalError << L"\n";
        return 1;
    }
    if (!terminalBridge.Start(terminalError))
    {
        TerminateProcess(process.get(), 1);
        std::wcerr << terminalError << L"\n";
        return 1;
    }
    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
    {
        const DWORD resumeError = GetLastError();
        TerminateProcess(process.get(), 1);
        terminalBridge.Stop();
        std::wcerr << L"Could not resume the disconnect-test helper: "
                   << FormatWindowsError(resumeError) << L"\n";
        return 1;
    }

    if (WaitForSingleObject(process.get(), 250) != WAIT_TIMEOUT)
    {
        terminalBridge.Stop();
        std::wcerr << L"The interactive helper exited before its terminal was disconnected.\n";
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
        std::wcerr << L"The helper remained alive after its terminal input was closed.\n";
        return 1;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(process.get(), &exitCode))
    {
        const DWORD exitCodeError = GetLastError();
        std::wcerr << L"Could not read the disconnect-test helper exit code: "
                   << FormatWindowsError(exitCodeError) << L"\n";
        return 1;
    }
    if (exitCode != ExitCancelled)
    {
        std::wcerr << L"The disconnected helper returned " << exitCode << L"; expected "
                   << ExitCancelled << L".\n";
        return 1;
    }

    std::wcout << L"Terminal disconnect stopped the interactive helper.\n";
    return 0;
}
