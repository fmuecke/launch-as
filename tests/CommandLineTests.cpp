// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#include "CommandLineTestArguments.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr DWORD ProbeTimeoutMilliseconds = 10'000;

class UniqueHandle
{
  public:
    explicit UniqueHandle(HANDLE value = nullptr) noexcept : value_(value) {}

    ~UniqueHandle()
    {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(value_);
        }
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return value_; }

  private:
    HANDLE value_;
};

[[nodiscard]] bool ExpectEqual(
    std::wstring_view actual, std::wstring_view expected, std::wstring_view name)
{
    if (actual == expected)
    {
        return true;
    }
    std::wcerr << name << L" failed.\n"
               << L"Expected: " << expected << L"\n"
               << L"Actual:   " << actual << L"\n";
    return false;
}

} // namespace

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 2)
    {
        std::wcerr << L"Usage: CommandLineTests.exe <ArgvProbe.exe>\n";
        return 1;
    }

    if (!ExpectEqual(
            sandbox_launcher::QuoteWindowsCommandLineArgument(L""), L"\"\"", L"empty argument") ||
        !ExpectEqual(sandbox_launcher::QuoteWindowsCommandLineArgument(L"plain"),
            L"plain",
            L"plain argument") ||
        !ExpectEqual(sandbox_launcher::QuoteWindowsCommandLineArgument(L"with space"),
            L"\"with space\"",
            L"spaced argument") ||
        !ExpectEqual(sandbox_launcher::QuoteWindowsCommandLineArgument(L"quote\"inside"),
            L"\"quote\\\"inside\"",
            L"embedded quote") ||
        !ExpectEqual(sandbox_launcher::QuoteWindowsCommandLineArgument(L"trailing slash\\"),
            L"\"trailing slash\\\\\"",
            L"trailing backslash"))
    {
        return 1;
    }

    const std::filesystem::path probePath(argv[1]);
    if (!probePath.is_absolute() || !std::filesystem::is_regular_file(probePath))
    {
        std::wcerr << L"Argv probe not found: " << probePath.c_str() << L"\n";
        return 1;
    }

    std::vector<std::wstring> arguments;
    arguments.reserve(CommandLineTestArguments.size());
    for (const std::wstring_view argument : CommandLineTestArguments)
    {
        arguments.emplace_back(argument);
    }
    std::wstring commandLine =
        sandbox_launcher::BuildWindowsCommandLine(probePath.native(), arguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo {};
    if (!CreateProcessW(probePath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo))
    {
        std::wcerr << L"Could not start argv probe: " << GetLastError() << L"\n";
        return 1;
    }

    UniqueHandle process(processInfo.hProcess);
    UniqueHandle thread(processInfo.hThread);
    const DWORD waitResult = WaitForSingleObject(process.get(), ProbeTimeoutMilliseconds);
    if (waitResult == WAIT_TIMEOUT)
    {
        TerminateProcess(process.get(), 1);
        std::wcerr << L"Argv probe timed out.\n";
        return 1;
    }
    if (waitResult != WAIT_OBJECT_0)
    {
        std::wcerr << L"Could not wait for argv probe: " << GetLastError() << L"\n";
        return 1;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(process.get(), &exitCode))
    {
        std::wcerr << L"Could not read argv probe exit code: " << GetLastError() << L"\n";
        return 1;
    }
    if (exitCode != 0)
    {
        std::wcerr << L"Argv probe returned " << exitCode << L".\n";
        return 1;
    }
    return 0;
}
