// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

// Regression test for resize garbling: a terminal that reflows on its own must not receive a
// full-viewport repaint from the inner pseudoconsole. The test runs a writer through the real
// terminal bridge and launch-as-conhost inside a hidden console, narrows that console, and checks
// that no earlier output was painted a second time.

#include "TerminalBridge.h"
#include "TestSupport.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr int SkipNoConsole = 77;
constexpr SHORT InitialWidth = 120;
constexpr SHORT NarrowWidth = 80;
constexpr DWORD SettleMilliseconds = 1'000;

[[nodiscard]] COORD WindowSize(HANDLE output)
{
    CONSOLE_SCREEN_BUFFER_INFO information {};
    if (!GetConsoleScreenBufferInfo(output, &information))
    {
        return {};
    }
    return {
        static_cast<SHORT>(information.srWindow.Right - information.srWindow.Left + 1),
        static_cast<SHORT>(information.srWindow.Bottom - information.srWindow.Top + 1)
    };
}

void Write(HANDLE output, std::string_view text)
{
    DWORD written = 0;
    static_cast<void>(
        WriteFile(output, text.data(), static_cast<DWORD>(text.size()), &written, nullptr));
}

// Prints marker lines and a full-width frame, then reports the size observed after a resize.
// The writer leaves the frame alone so any repaint comes from the pseudoconsole.
int RunWriter()
{
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(output, &mode))
    {
        SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    for (int line = 0; line < 5; ++line)
    {
        Write(output, "marker-" + std::to_string(line) + "\r\n");
    }
    const auto frame = [](SHORT width)
    {
        std::string text;
        for (int row = 0; row < 4; ++row)
        {
            std::string line = "frame-" + std::to_string(row) + " ";
            line.resize(static_cast<std::size_t>(width), '=');
            text += "\x1b[42m" + line + "\x1b[0m";
            if (row < 3)
            {
                text += "\r\n";
            }
        }
        return text;
    };
    const COORD initial = WindowSize(output);
    Write(output, frame(initial.X));
    const ULONGLONG deadline = GetTickCount64() + 10'000;
    while (GetTickCount64() < deadline)
    {
        Sleep(20);
        const COORD current = WindowSize(output);
        if (current.X != initial.X)
        {
            Write(
                output, "\r\nwriter-resized-" + std::to_string(current.X) + "\r\nwriter-done\r\n");
            return 0;
        }
    }
    Write(output, "\r\nwriter-no-resize\r\n");
    return 1;
}

[[nodiscard]] bool SetConsoleWidth(HANDLE output, SHORT width)
{
    CONSOLE_SCREEN_BUFFER_INFOEX information {};
    information.cbSize = sizeof(information);
    if (!GetConsoleScreenBufferInfoEx(output, &information))
    {
        return false;
    }
    const SHORT height =
        static_cast<SHORT>(information.srWindow.Bottom - information.srWindow.Top + 1);
    information.dwSize.X = width;
    // SetConsoleScreenBufferInfoEx treats Right and Bottom as exclusive, unlike
    // GetConsoleScreenBufferInfoEx, so this sets a window exactly width x height.
    information.srWindow = {0, 0, width, height};
    return SetConsoleScreenBufferInfoEx(output, &information) != FALSE;
}

[[nodiscard]] std::vector<std::wstring> ReadConsoleRows(HANDLE output)
{
    CONSOLE_SCREEN_BUFFER_INFO information {};
    std::vector<std::wstring> rows;
    if (!GetConsoleScreenBufferInfo(output, &information))
    {
        return rows;
    }
    for (SHORT row = 0; row <= information.dwCursorPosition.Y; ++row)
    {
        std::wstring text(static_cast<std::size_t>(information.dwSize.X), L' ');
        DWORD read = 0;
        if (!ReadConsoleOutputCharacterW(
                output, text.data(), static_cast<DWORD>(text.size()), {0, row}, &read))
        {
            break;
        }
        text.erase(text.find_last_not_of(L' ') + 1);
        rows.push_back(std::move(text));
    }
    return rows;
}

[[nodiscard]] bool StartProcess(const std::filesystem::path& executable,
    const std::vector<std::wstring>& arguments, DWORD creationFlags, WORD showWindow,
    launch_as::UniqueHandle& process)
{
    std::wstring commandLine = launch_as::BuildWindowsCommandLine(executable.native(), arguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);
    startupInformation.dwFlags = STARTF_USESHOWWINDOW;
    startupInformation.wShowWindow = showWindow;
    PROCESS_INFORMATION processInformation {};
    if (!CreateProcessW(executable.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            creationFlags,
            nullptr,
            nullptr,
            &startupInformation,
            &processInformation))
    {
        return false;
    }
    CloseHandle(processInformation.hThread);
    process.reset(processInformation.hProcess);
    return true;
}

// Runs inside the hidden console: bridges the writer through launch-as-conhost, narrows the
// console, and records the outcome in resultPath.
[[nodiscard]] bool RunInConsole(
    const std::filesystem::path& conhostPath, const std::filesystem::path& resultPath)
{
    std::wofstream result(resultPath);
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!SetConsoleWidth(output, InitialWidth))
    {
        result << L"Could not set the initial console width.\n";
        return false;
    }

    launch_as::TerminalBridge bridge;
    launch_as::TerminalPipeNames pipeNames;
    std::wstring error;
    if (!bridge.InitializeForBroker(L"", pipeNames, error))
    {
        result << error << L"\n";
        return false;
    }
    std::wstring selfPath;
    if (launch_as::GetCurrentExecutablePath(selfPath) != ERROR_SUCCESS)
    {
        result << L"Could not find the test executable.\n";
        return false;
    }
    launch_as::UniqueHandle host;
    if (!StartProcess(conhostPath,
            {L"--internal-pseudoconsole-host",
                L"--inherit-cursor",
                L"--pipe-in",
                pipeNames.input,
                L"--pipe-out",
                pipeNames.output,
                L"--pipe-resize",
                pipeNames.resize,
                L"--",
                selfPath,
                L"--writer"},
            CREATE_NO_WINDOW,
            SW_HIDE,
            host) ||
        !bridge.ConnectBrokerChild(error) || !bridge.Start(error))
    {
        result << L"Could not start the bridged writer: " << error << L"\n";
        if (host)
        {
            TerminateProcess(host.get(), 1);
        }
        return false;
    }

    Sleep(SettleMilliseconds);
    const bool narrowed = SetConsoleWidth(output, NarrowWidth);
    const bool hostExited = WaitForSingleObject(host.get(), 15'000) == WAIT_OBJECT_0;
    if (!hostExited)
    {
        TerminateProcess(host.get(), 1);
        WaitForSingleObject(host.get(), 5'000);
    }
    bridge.Stop();
    if (!hostExited)
    {
        result << L"The pseudoconsole host did not exit within 15 seconds.\n";
        return false;
    }

    const std::vector<std::wstring> rows = ReadConsoleRows(output);
    int markerRows = 0;
    bool writerDone = false;
    bool writerResized = false;
    std::array<int, 4> frameRows {};
    for (const std::wstring& row : rows)
    {
        markerRows += row == L"marker-0" ? 1 : 0;
        writerDone = writerDone || row == L"writer-done";
        writerResized = writerResized || row == L"writer-resized-" + std::to_wstring(NarrowWidth);
        for (int frame = 0; frame < static_cast<int>(frameRows.size()); ++frame)
        {
            frameRows[frame] += row.starts_with(L"frame-" + std::to_wstring(frame) + L" ") ? 1 : 0;
        }
    }
    bool framesOnce = true;
    for (const int count : frameRows)
    {
        framesOnce = framesOnce && count == 1;
    }
    const bool passed =
        narrowed && hostExited && writerDone && writerResized && markerRows == 1 && framesOnce;
    result << (passed ? L"PASS" : L"FAIL") << L" narrowed=" << narrowed << L" hostExited="
           << hostExited << L" writerDone=" << writerDone << L" writerResized=" << writerResized
           << L" marker0Rows=" << markerRows << L" framesOnce=" << framesOnce << L"\n";
    for (const std::wstring& row : rows)
    {
        result << L"|" << row << L"\n";
    }
    return passed;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount == 2 && std::wstring_view(arguments[1]) == L"--writer")
    {
        return RunWriter();
    }
    if (argumentCount == 4 && std::wstring_view(arguments[1]) == L"--in-console")
    {
        return RunInConsole(arguments[2], arguments[3]) ? 0 : 1;
    }
    if (argumentCount != 2)
    {
        std::wcerr << L"Usage: LauncherTerminalResizeTests <launch-as-conhost.exe>\n";
        return 2;
    }

    launch_as::test::TemporaryDirectory directory;
    std::wstring selfPath;
    if (!directory.created() || launch_as::GetCurrentExecutablePath(selfPath) != ERROR_SUCCESS)
    {
        std::wcerr << L"Could not prepare the resize test.\n";
        return 1;
    }
    const std::filesystem::path resultPath = directory.path() / L"result.txt";
    launch_as::UniqueHandle child;
    if (!StartProcess(selfPath,
            {L"--in-console", arguments[1], resultPath.native()},
            CREATE_NEW_CONSOLE,
            SW_HIDE,
            child))
    {
        std::wcerr << L"Could not create a hidden console; skipping.\n";
        return SkipNoConsole;
    }
    DWORD exitCode = 1;
    if (WaitForSingleObject(child.get(), 30'000) != WAIT_OBJECT_0)
    {
        TerminateProcess(child.get(), 1);
        WaitForSingleObject(child.get(), 5'000);
        std::wcerr << L"The hidden-console resize run timed out.\n";
    }
    else
    {
        GetExitCodeProcess(child.get(), &exitCode);
    }
    std::wifstream result(resultPath);
    std::wstring line;
    while (std::getline(result, line))
    {
        std::wcout << line << L"\n";
    }
    return Expect(exitCode == 0, L"Resizing re-painted earlier terminal output.") ? 0 : 1;
}
