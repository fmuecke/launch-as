// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TerminalIO.h"

#include "Win32Support.h"

#include <array>
#include <cstddef>

namespace launch_as
{
namespace
{

[[nodiscard]] bool WriteAll(HANDLE destination, const std::byte* data, DWORD bytes) noexcept
{
    DWORD bytesWritten = 0;
    while (bytesWritten < bytes)
    {
        DWORD written = 0;
        if (!WriteFile(destination, data + bytesWritten, bytes - bytesWritten, &written, nullptr) ||
            written == 0)
        {
            return false;
        }
        bytesWritten += written;
    }
    return true;
}

} // namespace

bool IsUsableHandle(HANDLE handle) noexcept
{
    return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

void RelayInput(HANDLE source, HANDLE destination) noexcept
{
    std::array<std::byte, RelayBufferBytes> buffer {};
    for (;;)
    {
        DWORD bytesRead = 0;
        if (!ReadFile(
                source, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) ||
            bytesRead == 0)
        {
            return;
        }
        if (!WriteAll(destination, buffer.data(), bytesRead))
        {
            return;
        }
    }
}

void RelayOutput(HANDLE source, HANDLE destination, std::stop_token stopToken) noexcept
{
    std::array<std::byte, RelayBufferBytes> buffer {};
    bool destinationAvailable = true;
    while (!stopToken.stop_requested())
    {
        DWORD bytesRead = 0;
        if (!ReadFile(
                source, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) ||
            bytesRead == 0)
        {
            return;
        }
        if (destinationAvailable)
        {
            destinationAvailable = WriteAll(destination, buffer.data(), bytesRead);
        }
    }
}

COORD CurrentTerminalSize(HANDLE output) noexcept
{
    CONSOLE_SCREEN_BUFFER_INFO information {};
    if (!IsUsableHandle(output) || !GetConsoleScreenBufferInfo(output, &information))
    {
        return DefaultTerminalSize;
    }

    const SHORT width = information.srWindow.Right - information.srWindow.Left + 1;
    const SHORT height = information.srWindow.Bottom - information.srWindow.Top + 1;
    if (width <= 0 || height <= 0)
    {
        return DefaultTerminalSize;
    }
    return COORD {width, height};
}

bool SupportsTerminalCursorInheritance(HANDLE input, HANDLE output) noexcept
{
    DWORD inputMode = 0;
    DWORD outputMode = 0;
    return IsUsableHandle(input) && IsUsableHandle(output) && GetConsoleMode(input, &inputMode) &&
           GetConsoleMode(output, &outputMode);
}

TerminalMode::~TerminalMode() { Restore(); }

bool TerminalMode::Configure(HANDLE input, HANDLE output, std::wstring& error)
{
    input_ = input;
    output_ = output;

    if (GetConsoleMode(input_, &originalInputMode_))
    {
        const DWORD inputMode = (originalInputMode_ & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT |
                                                          ENABLE_PROCESSED_INPUT)) |
                                ENABLE_VIRTUAL_TERMINAL_INPUT;
        if (!SetConsoleMode(input_, inputMode))
        {
            const DWORD modeError = GetLastError();
            error = L"Could not configure terminal input: " + FormatWindowsError(modeError);
            return false;
        }
        inputModeChanged_ = true;

        originalInputCodePage_ = GetConsoleCP();
        if (originalInputCodePage_ != 0 && originalInputCodePage_ != CP_UTF8)
        {
            if (!SetConsoleCP(CP_UTF8))
            {
                const DWORD codePageError = GetLastError();
                error = L"Could not configure UTF-8 terminal input: " +
                        FormatWindowsError(codePageError);
                Restore();
                return false;
            }
            inputCodePageChanged_ = true;
        }
    }

    if (GetConsoleMode(output_, &originalOutputMode_))
    {
        if (!SetConsoleMode(output_, originalOutputMode_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        {
            const DWORD modeError = GetLastError();
            error = L"Could not configure terminal output: " + FormatWindowsError(modeError);
            Restore();
            return false;
        }
        outputModeChanged_ = true;

        originalOutputCodePage_ = GetConsoleOutputCP();
        if (originalOutputCodePage_ != 0 && originalOutputCodePage_ != CP_UTF8)
        {
            if (!SetConsoleOutputCP(CP_UTF8))
            {
                const DWORD codePageError = GetLastError();
                error = L"Could not configure UTF-8 terminal output: " +
                        FormatWindowsError(codePageError);
                Restore();
                return false;
            }
            outputCodePageChanged_ = true;
        }
    }
    return true;
}

void TerminalMode::Restore() noexcept
{
    if (outputCodePageChanged_)
    {
        SetConsoleOutputCP(originalOutputCodePage_);
        outputCodePageChanged_ = false;
    }
    if (inputCodePageChanged_)
    {
        SetConsoleCP(originalInputCodePage_);
        inputCodePageChanged_ = false;
    }
    if (outputModeChanged_)
    {
        SetConsoleMode(output_, originalOutputMode_);
        outputModeChanged_ = false;
    }
    if (inputModeChanged_)
    {
        SetConsoleMode(input_, originalInputMode_);
        inputModeChanged_ = false;
    }
}

} // namespace launch_as
