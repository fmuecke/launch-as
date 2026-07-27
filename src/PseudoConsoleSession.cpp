// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#include "PseudoConsoleSession.h"

#include <Windows.h>
#include <array>
#include <chrono>
#include <exception>
#include <string>
#include <utility>

namespace sandbox_launcher
{
namespace
{

constexpr COORD DefaultTerminalSize {120, 30};
constexpr DWORD RelayBufferBytes = 16 * 1024;
constexpr DWORD OutputDrainGraceMilliseconds = 250;

[[nodiscard]] bool IsUsableHandle(HANDLE handle) noexcept
{
    return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

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

void RelayOutput(HANDLE source, HANDLE destination) noexcept
{
    std::array<std::byte, RelayBufferBytes> buffer {};
    bool destinationAvailable = true;
    for (;;)
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

} // namespace

PseudoConsoleSession::~PseudoConsoleSession()
{
    StopRelays();
    if (startupInfo_.lpAttributeList != nullptr)
    {
        DeleteProcThreadAttributeList(startupInfo_.lpAttributeList);
        startupInfo_.lpAttributeList = nullptr;
    }
    ClosePseudoConsole();
}

bool PseudoConsoleSession::Initialize(COORD terminalSize, bool inheritCursor, std::wstring& error)
{
    if (!LoadApi(error))
    {
        return false;
    }

    parentInput_ = GetStdHandle(STD_INPUT_HANDLE);
    parentOutput_ = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!IsUsableHandle(parentInput_) || !IsUsableHandle(parentOutput_))
    {
        error = L"Terminal mode requires usable standard input and output handles.";
        return false;
    }

    outputCompleteEvent_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!outputCompleteEvent_)
    {
        error = L"Could not create the pseudoconsole output completion event: " +
                FormatWindowsError(GetLastError());
        return false;
    }

    CONSOLE_SCREEN_BUFFER_INFO terminalInformation {};
    resizeSupported_ = GetConsoleScreenBufferInfo(parentOutput_, &terminalInformation) != FALSE;

    HANDLE rawPseudoInput = nullptr;
    HANDLE rawInputWrite = nullptr;
    if (!CreatePipe(&rawPseudoInput, &rawInputWrite, nullptr, 0))
    {
        error =
            L"Could not create the pseudoconsole input pipe: " + FormatWindowsError(GetLastError());
        return false;
    }
    UniqueHandle pseudoInput(rawPseudoInput);
    inputWrite_.reset(rawInputWrite);

    HANDLE rawOutputRead = nullptr;
    HANDLE rawPseudoOutput = nullptr;
    if (!CreatePipe(&rawOutputRead, &rawPseudoOutput, nullptr, 0))
    {
        error = L"Could not create the pseudoconsole output pipe: " +
                FormatWindowsError(GetLastError());
        return false;
    }
    outputRead_.reset(rawOutputRead);
    UniqueHandle pseudoOutput(rawPseudoOutput);

    const DWORD flags = inheritCursor ? PSEUDOCONSOLE_INHERIT_CURSOR : 0;
    const HRESULT createResult =
        api_.create(terminalSize, pseudoInput.get(), pseudoOutput.get(), flags, &pseudoConsole_);
    if (FAILED(createResult))
    {
        error = L"Could not create the Windows pseudoconsole: " +
                FormatWindowsError(HRESULT_CODE(createResult));
        return false;
    }

    SIZE_T attributeListBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListBytes);
    if (attributeListBytes == 0)
    {
        error = L"Could not size the pseudoconsole process attributes: " +
                FormatWindowsError(GetLastError());
        return false;
    }

    attributeListStorage_.resize(attributeListBytes);
    startupInfo_.StartupInfo.cb = sizeof(startupInfo_);
    startupInfo_.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo_.StartupInfo.hStdInput = nullptr;
    startupInfo_.StartupInfo.hStdOutput = nullptr;
    startupInfo_.StartupInfo.hStdError = nullptr;
    startupInfo_.lpAttributeList =
        reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributeListStorage_.data());
    if (!InitializeProcThreadAttributeList(startupInfo_.lpAttributeList, 1, 0, &attributeListBytes))
    {
        error = L"Could not initialize the pseudoconsole process attributes: " +
                FormatWindowsError(GetLastError());
        startupInfo_.lpAttributeList = nullptr;
        return false;
    }
    if (!UpdateProcThreadAttribute(startupInfo_.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            pseudoConsole_,
            sizeof(pseudoConsole_),
            nullptr,
            nullptr))
    {
        error = L"Could not attach the pseudoconsole process attribute: " +
                FormatWindowsError(GetLastError());
        return false;
    }
    return true;
}

STARTUPINFOW* PseudoConsoleSession::startupInfo() noexcept { return &startupInfo_.StartupInfo; }

bool PseudoConsoleSession::StartRelays(std::wstring& error)
{
    if (pseudoConsole_ == nullptr || !inputWrite_ || !outputRead_)
    {
        error = L"The pseudoconsole session is not initialized.";
        return false;
    }
    if (!ConfigureTerminal(error))
    {
        return false;
    }

    HANDLE rawInputRelayWrite = nullptr;
    const HANDLE currentProcess = GetCurrentProcess();
    if (!DuplicateHandle(currentProcess,
            inputWrite_.get(),
            currentProcess,
            &rawInputRelayWrite,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS))
    {
        error = L"Could not duplicate the pseudoconsole input pipe: " +
                FormatWindowsError(GetLastError());
        RestoreTerminal();
        return false;
    }
    UniqueHandle inputRelayWrite(rawInputRelayWrite);

    relaysStarted_ = true;
    try
    {
        inputRelay_ = std::jthread(
            [source = parentInput_, destination = std::move(inputRelayWrite)]() noexcept
            { RelayInput(source, destination.get()); });

        UniqueHandle outputRead(std::exchange(outputRead_, {}));
        outputRelay_ = std::jthread(
            [source = std::move(outputRead),
                destination = parentOutput_,
                completionEvent = outputCompleteEvent_.get()]() noexcept
            {
                RelayOutput(source.get(), destination);
                SetEvent(completionEvent);
            });

        if (resizeSupported_)
        {
            resizeRelay_ = std::jthread(
                [this](std::stop_token stopToken) noexcept
                {
                    COORD previousSize = CurrentTerminalSize();
                    while (!stopToken.stop_requested())
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(200));
                        const COORD size = CurrentTerminalSize();
                        if (size.X != previousSize.X || size.Y != previousSize.Y)
                        {
                            api_.resize(pseudoConsole_, size);
                            previousSize = size;
                        }
                    }
                });
        }
    }
    catch (const std::exception&)
    {
        error = L"Could not start the pseudoconsole relay threads.";
        StopRelays();
        return false;
    }
    return true;
}

void PseudoConsoleSession::StopRelays() noexcept
{
    if (!relaysStarted_)
    {
        return;
    }

    resizeRelay_.request_stop();
    if (resizeRelay_.joinable())
    {
        resizeRelay_.join();
    }

    // A short-lived client can exit before ConPTY has emitted its final frame.
    // Prefer natural output completion, but bound the wait so attached descendants
    // cannot keep the launcher alive indefinitely.
    WaitForSingleObject(outputCompleteEvent_.get(), OutputDrainGraceMilliseconds);

    if (inputRelay_.joinable())
    {
        CancelSynchronousIo(inputRelay_.native_handle());
        inputRelay_.join();
    }
    inputWrite_.reset();

    ClosePseudoConsole();
    if (outputRelay_.joinable())
    {
        outputRelay_.join();
    }

    RestoreTerminal();
    relaysStarted_ = false;
}

bool PseudoConsoleSession::LoadApi(std::wstring& error)
{
    const HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (kernel == nullptr)
    {
        error =
            L"Could not load the Windows pseudoconsole API: " + FormatWindowsError(GetLastError());
        return false;
    }

    api_.create = reinterpret_cast<CreatePseudoConsoleFunction>(
        GetProcAddress(kernel, "CreatePseudoConsole"));
    api_.resize = reinterpret_cast<ResizePseudoConsoleFunction>(
        GetProcAddress(kernel, "ResizePseudoConsole"));
    api_.close =
        reinterpret_cast<ClosePseudoConsoleFunction>(GetProcAddress(kernel, "ClosePseudoConsole"));
    if (api_.create == nullptr || api_.resize == nullptr || api_.close == nullptr)
    {
        error = L"Terminal mode requires Windows pseudoconsole support (Windows 10 version 1809 or "
                L"newer).";
        return false;
    }
    return true;
}

COORD PseudoConsoleSession::CurrentTerminalSize() const noexcept
{
    CONSOLE_SCREEN_BUFFER_INFO information {};
    if (!IsUsableHandle(parentOutput_) || !GetConsoleScreenBufferInfo(parentOutput_, &information))
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

bool PseudoConsoleSession::ConfigureTerminal(std::wstring& error)
{
    if (GetConsoleMode(parentInput_, &originalInputMode_))
    {
        const DWORD inputMode = (originalInputMode_ & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT |
                                                          ENABLE_PROCESSED_INPUT)) |
                                ENABLE_VIRTUAL_TERMINAL_INPUT;
        if (!SetConsoleMode(parentInput_, inputMode))
        {
            error = L"Could not configure terminal input: " + FormatWindowsError(GetLastError());
            return false;
        }
        inputModeChanged_ = true;

        originalInputCodePage_ = GetConsoleCP();
        if (originalInputCodePage_ != 0 && originalInputCodePage_ != CP_UTF8)
        {
            if (!SetConsoleCP(CP_UTF8))
            {
                error = L"Could not configure UTF-8 terminal input: " +
                        FormatWindowsError(GetLastError());
                RestoreTerminal();
                return false;
            }
            inputCodePageChanged_ = true;
        }
    }

    if (GetConsoleMode(parentOutput_, &originalOutputMode_))
    {
        if (!SetConsoleMode(
                parentOutput_, originalOutputMode_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        {
            error = L"Could not configure terminal output: " + FormatWindowsError(GetLastError());
            RestoreTerminal();
            return false;
        }
        outputModeChanged_ = true;

        originalOutputCodePage_ = GetConsoleOutputCP();
        if (originalOutputCodePage_ != 0 && originalOutputCodePage_ != CP_UTF8)
        {
            if (!SetConsoleOutputCP(CP_UTF8))
            {
                error = L"Could not configure UTF-8 terminal output: " +
                        FormatWindowsError(GetLastError());
                RestoreTerminal();
                return false;
            }
            outputCodePageChanged_ = true;
        }
    }
    return true;
}

void PseudoConsoleSession::RestoreTerminal() noexcept
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
        SetConsoleMode(parentOutput_, originalOutputMode_);
        outputModeChanged_ = false;
    }
    if (inputModeChanged_)
    {
        SetConsoleMode(parentInput_, originalInputMode_);
        inputModeChanged_ = false;
    }
}

void PseudoConsoleSession::ClosePseudoConsole() noexcept
{
    if (pseudoConsole_ != nullptr)
    {
        api_.close(pseudoConsole_);
        pseudoConsole_ = nullptr;
    }
}

} // namespace sandbox_launcher
