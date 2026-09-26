// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <chrono>
#include <cwchar>
#include <iostream>
#include <limits>
#include <thread>

namespace
{

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

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    COORD expectedSize {};
    if (argumentCount != 4 || !ParseDimension(arguments[1], expectedSize.X) ||
        !ParseDimension(arguments[2], expectedSize.Y))
    {
        std::wcerr << L"Expected terminal width, height, and readiness event.\n";
        return 1;
    }

    HANDLE readyEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, arguments[3]);
    if (readyEvent == nullptr)
    {
        std::wcerr << L"Could not open the terminal-size readiness event.\n";
        return 1;
    }
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    COORD observedSize {};
    while (std::chrono::steady_clock::now() < deadline)
    {
        CONSOLE_SCREEN_BUFFER_INFO information {};
        if (GetConsoleScreenBufferInfo(output, &information))
        {
            if (readyEvent != nullptr)
            {
                const BOOL signalled = SetEvent(readyEvent);
                CloseHandle(readyEvent);
                readyEvent = nullptr;
                if (!signalled)
                {
                    std::wcerr << L"Could not signal terminal-size readiness.\n";
                    return 1;
                }
            }
            observedSize.X = information.srWindow.Right - information.srWindow.Left + 1;
            observedSize.Y = information.srWindow.Bottom - information.srWindow.Top + 1;
            if (observedSize.X == expectedSize.X && observedSize.Y == expectedSize.Y)
            {
                for (int line = 1; line <= 256; ++line)
                {
                    std::wcout << L"conpty-smoke-" << line << L"\n";
                }
                return 0;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    if (readyEvent != nullptr)
    {
        CloseHandle(readyEvent);
    }
    std::wcerr << L"Observed terminal size " << observedSize.X << L"x" << observedSize.Y
               << L"; expected " << expectedSize.X << L"x" << expectedSize.Y << L".\n";
    return 1;
}
