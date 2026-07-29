// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "PseudoConsoleSession.h"

#include <Windows.h>
#include <chrono>
#include <exception>
#include <string>
#include <utility>

namespace launch_as
{

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

    inputRelayCompleteEvent_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!inputRelayCompleteEvent_)
    {
        const DWORD eventError = GetLastError();
        error = L"Could not create the pseudoconsole input completion event: " +
                FormatWindowsError(eventError);
        return false;
    }

    outputCompleteEvent_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!outputCompleteEvent_)
    {
        const DWORD eventError = GetLastError();
        error = L"Could not create the pseudoconsole output completion event: " +
                FormatWindowsError(eventError);
        return false;
    }

    CONSOLE_SCREEN_BUFFER_INFO terminalInformation {};
    resizeSupported_ = GetConsoleScreenBufferInfo(parentOutput_, &terminalInformation) != FALSE;

    HANDLE rawPseudoInput = nullptr;
    HANDLE rawInputWrite = nullptr;
    if (!CreatePipe(&rawPseudoInput, &rawInputWrite, nullptr, 0))
    {
        const DWORD pipeError = GetLastError();
        error = L"Could not create the pseudoconsole input pipe: " + FormatWindowsError(pipeError);
        return false;
    }
    UniqueHandle pseudoInput(rawPseudoInput);
    inputWrite_.reset(rawInputWrite);

    HANDLE rawOutputRead = nullptr;
    HANDLE rawPseudoOutput = nullptr;
    if (!CreatePipe(&rawOutputRead, &rawPseudoOutput, nullptr, 0))
    {
        const DWORD pipeError = GetLastError();
        error = L"Could not create the pseudoconsole output pipe: " + FormatWindowsError(pipeError);
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
    const DWORD attributeListSizeError = GetLastError();
    if (attributeListBytes == 0)
    {
        error = L"Could not size the pseudoconsole process attributes: " +
                FormatWindowsError(attributeListSizeError);
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
        const DWORD attributeListError = GetLastError();
        error = L"Could not initialize the pseudoconsole process attributes: " +
                FormatWindowsError(attributeListError);
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
        const DWORD attributeError = GetLastError();
        error = L"Could not attach the pseudoconsole process attribute: " +
                FormatWindowsError(attributeError);
        return false;
    }
    return true;
}

STARTUPINFOW* PseudoConsoleSession::startupInfo() noexcept { return &startupInfo_.StartupInfo; }

HANDLE PseudoConsoleSession::inputRelayCompleteEvent() const noexcept
{
    return inputRelayCompleteEvent_.get();
}

bool PseudoConsoleSession::StartRelays(std::wstring& error)
{
    if (pseudoConsole_ == nullptr || !inputWrite_ || !outputRead_)
    {
        error = L"The pseudoconsole session is not initialized.";
        return false;
    }
    if (!terminalMode_.Configure(parentInput_, parentOutput_, error))
    {
        return false;
    }

    UniqueHandle inputRelayWrite(std::exchange(inputWrite_, {}));

    relaysStarted_ = true;
    try
    {
        inputRelay_ = std::jthread(
            [source = parentInput_,
                destination = std::move(inputRelayWrite),
                completionEvent = inputRelayCompleteEvent_.get()]() noexcept
            {
                RelayInput(source, destination.get());
                SetEvent(completionEvent);
            });

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
                    COORD previousSize = CurrentTerminalSize(parentOutput_);
                    while (!stopToken.stop_requested())
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(200));
                        const COORD size = CurrentTerminalSize(parentOutput_);
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

    terminalMode_.Restore();
    relaysStarted_ = false;
}

bool PseudoConsoleSession::LoadApi(std::wstring& error)
{
    const HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (kernel == nullptr)
    {
        const DWORD moduleError = GetLastError();
        error = L"Could not load the Windows pseudoconsole API: " + FormatWindowsError(moduleError);
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

void PseudoConsoleSession::ClosePseudoConsole() noexcept
{
    if (pseudoConsole_ != nullptr)
    {
        api_.close(pseudoConsole_);
        pseudoConsole_ = nullptr;
    }
}

} // namespace launch_as
