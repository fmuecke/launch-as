// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "PseudoConsoleHost.h"

#include "LaunchProcess.h"
#include "PseudoConsoleSession.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <cstddef>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as
{
namespace
{

constexpr std::wstring_view HostArgument = L"--internal-pseudoconsole-host";
constexpr std::wstring_view SizeArgument = L"--size";
constexpr std::wstring_view InheritCursorArgument = L"--inherit-cursor";
constexpr DWORD ProcessTerminationTimeoutMilliseconds = 5'000;

[[nodiscard]] bool ParseDimension(const wchar_t* text, SHORT& value) noexcept
{
    wchar_t* end = nullptr;
    const long parsed = std::wcstol(text, &end, 10);
    if (end == text || *end != L'\0' || parsed <= 0 || parsed > std::numeric_limits<SHORT>::max())
    {
        return false;
    }
    value = static_cast<SHORT>(parsed);
    return true;
}

[[nodiscard]] bool ParseHostArguments(std::span<wchar_t*> arguments, COORD& terminalSize,
    bool& inheritCursor, std::filesystem::path& executable,
    std::vector<std::wstring>& processArguments)
{
    if (arguments.size() < 7 || std::wstring_view(arguments[1]) != HostArgument ||
        std::wstring_view(arguments[2]) != SizeArgument ||
        !ParseDimension(arguments[3], terminalSize.X) ||
        !ParseDimension(arguments[4], terminalSize.Y))
    {
        return false;
    }

    std::size_t separatorIndex = 5;
    inheritCursor = std::wstring_view(arguments[separatorIndex]) == InheritCursorArgument;
    if (inheritCursor)
    {
        ++separatorIndex;
    }
    if (arguments.size() <= separatorIndex + 1 ||
        std::wstring_view(arguments[separatorIndex]) != L"--")
    {
        return false;
    }

    executable = arguments[separatorIndex + 1];
    for (std::size_t index = separatorIndex + 2; index < arguments.size(); ++index)
    {
        processArguments.emplace_back(arguments[index]);
    }
    return true;
}

} // namespace

bool IsPseudoConsoleHostInvocation(std::span<wchar_t*> arguments) noexcept
{
    return arguments.size() >= 2 && std::wstring_view(arguments[1]) == HostArgument;
}

ExitCode RunPseudoConsoleHost(std::span<wchar_t*> arguments)
{
    COORD terminalSize {};
    bool inheritCursor = false;
    std::filesystem::path executable;
    std::vector<std::wstring> processArguments;
    if (!ParseHostArguments(arguments, terminalSize, inheritCursor, executable, processArguments))
    {
        std::wcerr << L"Invalid internal pseudoconsole-host invocation.\n";
        return ExitUsage;
    }

    Options options {
        .command = Command::Run, .executablePath = executable, .processArguments = processArguments
    };
    if (!ValidateRunPaths(options))
    {
        return ExitFailure;
    }

    PseudoConsoleSession pseudoConsole;
    std::wstring terminalError;
    if (!pseudoConsole.Initialize(terminalSize, inheritCursor, terminalError))
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
        BuildWindowsCommandLine(options.executablePath.native(), options.processArguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    PROCESS_INFORMATION processInformation {};
    if (!CreateProcessW(options.executablePath.c_str(),
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
        std::wcerr << L"Could not start the pseudoconsole child: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return ExitFailure;
    }
    UniqueHandle process(processInformation.hProcess);
    UniqueHandle thread(processInformation.hThread);

    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
    {
        const DWORD resumeError = GetLastError();
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), ProcessTerminationTimeoutMilliseconds);
        std::wcerr << L"Could not resume the pseudoconsole child: "
                   << FormatWindowsError(resumeError) << L"\n";
        return ExitFailure;
    }

    const DWORD waitResult = WaitForSingleObject(process.get(), INFINITE);
    if (waitResult != WAIT_OBJECT_0)
    {
        pseudoConsole.StopRelays();
        std::wcerr << L"Could not wait for the pseudoconsole child: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return ExitFailure;
    }
    pseudoConsole.StopRelays();

    DWORD childExitCode = 0;
    if (!GetExitCodeProcess(process.get(), &childExitCode))
    {
        std::wcerr << L"Could not read the pseudoconsole child exit code: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return ExitFailure;
    }
    return childExitCode;
}

std::filesystem::path GetLauncherExecutablePath(std::wstring& error)
{
    std::vector<wchar_t> path(512);
    for (;;)
    {
        const DWORD characters =
            GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (characters == 0)
        {
            error = L"Could not resolve the launcher path: " + FormatWindowsError(GetLastError());
            return {};
        }
        if (characters < path.size())
        {
            return std::filesystem::path(std::wstring(path.data(), characters));
        }
        path.resize(path.size() * 2);
    }
}

std::vector<std::wstring> BuildPseudoConsoleHostArguments(
    const Options& options, COORD terminalSize, bool inheritCursor)
{
    std::vector<std::wstring> arguments;
    arguments.reserve(options.processArguments.size() + 7);
    arguments.emplace_back(HostArgument);
    arguments.emplace_back(SizeArgument);
    arguments.emplace_back(std::to_wstring(terminalSize.X));
    arguments.emplace_back(std::to_wstring(terminalSize.Y));
    if (inheritCursor)
    {
        arguments.emplace_back(InheritCursorArgument);
    }
    arguments.emplace_back(L"--");
    arguments.emplace_back(options.executablePath.native());
    arguments.insert(
        arguments.end(), options.processArguments.begin(), options.processArguments.end());
    return arguments;
}

} // namespace launch_as
