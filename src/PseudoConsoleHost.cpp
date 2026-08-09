// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "PseudoConsoleHost.h"

#include "PseudoConsoleSession.h"
#include "TerminalIO.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cwchar>
#include <fcntl.h>
#include <filesystem>
#include <io.h>
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
constexpr std::wstring_view PipeInArgument = L"--pipe-in";
constexpr std::wstring_view PipeOutArgument = L"--pipe-out";
constexpr std::wstring_view PipeResizeArgument = L"--pipe-resize";
constexpr DWORD ProcessTerminationTimeoutMilliseconds = 5'000;

struct HostInvocation
{
    COORD terminalSize {};
    bool inheritCursor = false;
    std::filesystem::path executable;
    std::vector<std::wstring> processArguments;
    std::wstring pipeIn;
    std::wstring pipeOut;
    std::wstring pipeResize;
};

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

[[nodiscard]] bool ParseHostArguments(std::span<wchar_t*> arguments, HostInvocation& invocation)
{
    if (arguments.size() < 7 || std::wstring_view(arguments[1]) != HostArgument ||
        std::wstring_view(arguments[2]) != SizeArgument ||
        !ParseDimension(arguments[3], invocation.terminalSize.X) ||
        !ParseDimension(arguments[4], invocation.terminalSize.Y))
    {
        return false;
    }

    std::size_t separatorIndex = 5;
    invocation.inheritCursor =
        std::wstring_view(arguments[separatorIndex]) == InheritCursorArgument;
    if (invocation.inheritCursor)
    {
        ++separatorIndex;
    }
    for (;
        separatorIndex < arguments.size() && std::wstring_view(arguments[separatorIndex]) != L"--";
        separatorIndex += 2)
    {
        if (separatorIndex + 1 >= arguments.size())
        {
            return false;
        }
        const std::wstring_view name(arguments[separatorIndex]);
        const std::wstring_view value(arguments[separatorIndex + 1]);
        if (value.empty())
        {
            return false;
        }
        if (name == PipeInArgument && invocation.pipeIn.empty())
        {
            invocation.pipeIn = value;
        }
        else if (name == PipeOutArgument && invocation.pipeOut.empty())
        {
            invocation.pipeOut = value;
        }
        else if (name == PipeResizeArgument && invocation.pipeResize.empty())
        {
            invocation.pipeResize = value;
        }
        else
        {
            return false;
        }
    }
    if (arguments.size() <= separatorIndex + 1 ||
        std::wstring_view(arguments[separatorIndex]) != L"--")
    {
        return false;
    }

    invocation.executable = arguments[separatorIndex + 1];
    for (std::size_t index = separatorIndex + 2; index < arguments.size(); ++index)
    {
        invocation.processArguments.emplace_back(arguments[index]);
    }
    return (invocation.pipeIn.empty() && invocation.pipeOut.empty() &&
               invocation.pipeResize.empty()) ||
           (!invocation.pipeIn.empty() && !invocation.pipeOut.empty() &&
               !invocation.pipeResize.empty());
}

[[nodiscard]] bool OpenPipeClient(
    std::wstring_view pipeName, DWORD access, UniqueHandle& pipe, std::wstring& error)
{
    HANDLE rawPipe = CreateFileW(pipeName.data(),
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

bool IsPseudoConsoleHostInvocation(std::span<wchar_t*> arguments) noexcept
{
    return arguments.size() >= 2 && std::wstring_view(arguments[1]) == HostArgument;
}

ExitCode RunPseudoConsoleHost(std::span<wchar_t*> arguments)
{
    HostInvocation invocation;
    if (!ParseHostArguments(arguments, invocation))
    {
        std::wcerr << L"Invalid internal pseudoconsole-host invocation.\n";
        return ExitUsage;
    }

    UniqueHandle brokerInput;
    UniqueHandle brokerOutput;
    UniqueHandle brokerResize;
    const bool brokerPipes = !invocation.pipeIn.empty();
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
        std::wcout << streamError << L"\n";
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
        std::wcerr << L"Pseudoconsole target is not an existing absolute file: "
                   << invocation.executable.c_str() << L"\n";
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

    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
    {
        const DWORD resumeError = GetLastError();
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), ProcessTerminationTimeoutMilliseconds);
        std::wcerr << L"Could not resume the pseudoconsole child: "
                   << FormatWindowsError(resumeError) << L"\n";
        return ExitFailure;
    }

    const std::array<HANDLE, 2> waitHandles {
        process.get(), pseudoConsole.inputRelayCompleteEvent()
    };
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
                std::wcerr << L"Could not terminate the disconnected pseudoconsole child: "
                           << FormatWindowsError(terminationError) << L"\n";
            }
            else
            {
                std::wcerr << L"The disconnected pseudoconsole child did not terminate in time.\n";
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
            const DWORD pathError = GetLastError();
            error = L"Could not resolve the launcher path: " + FormatWindowsError(pathError);
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
