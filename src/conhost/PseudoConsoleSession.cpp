// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "PseudoConsoleSession.h"

#include <Windows.h>
#include <exception>
#include <filesystem>
#include <iostream>
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

bool PseudoConsoleSession::Initialize(COORD terminalSize, bool inheritCursor, HANDLE parentInput,
    HANDLE parentOutput, HANDLE resizeInput, std::wstring& error)
{
    if (!LoadApi(error))
    {
        return false;
    }

    parentInput_ = parentInput;
    parentOutput_ = parentOutput;
    resizeInput_ = resizeInput;
    if (!IsUsableHandle(parentInput_) || !IsUsableHandle(parentOutput_) ||
        !IsUsableHandle(resizeInput_))
    {
        error = L"Terminal mode requires usable input, output, and resize handles.";
        return false;
    }

    inputRelayFailedEvent_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!inputRelayFailedEvent_)
    {
        const DWORD eventError = GetLastError();
        error = L"Could not create the pseudoconsole input failure event: " +
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

    nullInput_.reset(CreateFileW(L"NUL",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr));
    if (!nullInput_)
    {
        const DWORD nullInputError = GetLastError();
        error =
            L"Could not open the pseudoconsole null input: " + FormatWindowsError(nullInputError);
        return false;
    }
    nullOutput_.reset(CreateFileW(L"NUL",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr));
    if (!nullOutput_)
    {
        const DWORD nullOutputError = GetLastError();
        error =
            L"Could not open the pseudoconsole null output: " + FormatWindowsError(nullOutputError);
        return false;
    }

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
    startupInfo_.StartupInfo.hStdInput = nullInput_.get();
    startupInfo_.StartupInfo.hStdOutput = nullOutput_.get();
    startupInfo_.StartupInfo.hStdError = nullOutput_.get();
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

HANDLE PseudoConsoleSession::inputRelayFailedEvent() const noexcept
{
    return inputRelayFailedEvent_.get();
}

bool PseudoConsoleSession::StartRelays(std::wstring& error)
{
    if (pseudoConsole_ == nullptr || !inputWrite_ || !outputRead_ || !IsUsableHandle(resizeInput_))
    {
        error = L"The pseudoconsole session is not initialized.";
        return false;
    }
    if (!terminalMode_.Configure(parentInput_, parentOutput_, error))
    {
        return false;
    }

    relaysStarted_ = true;
    try
    {
        inputRelay_ = std::jthread(
            [this, source = parentInput_, failureEvent = inputRelayFailedEvent_.get()](
                std::stop_token stopToken) noexcept
            {
                // ConPTY treats a closed input endpoint as Ctrl+C, so EOF only stops the relay.
                // The session owner closes the endpoint after the child has exited or disconnected.
                if (RelayInput(source, inputWrite_.get(), stopToken) == InputRelayResult::Error)
                {
                    SetEvent(failureEvent);
                }
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

        resizeRelay_ = std::jthread(
            [this]() noexcept
            {
                COORD size {};
                while (ReadTerminalSize(resizeInput_, size))
                {
                    const HRESULT resizeResult = api_.resize(pseudoConsole_, size);
                    if (FAILED(resizeResult))
                    {
                        std::wcerr << L"Could not resize the Windows pseudoconsole: "
                                   << FormatWindowsError(HRESULT_CODE(resizeResult)) << L"\n";
                        return;
                    }
                }
            });
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

    if (resizeRelay_.joinable())
    {
        CancelSynchronousIo(resizeRelay_.native_handle());
        resizeRelay_.join();
    }

    // A short-lived client can exit before ConPTY has emitted its final frame.
    // Prefer natural output completion, but bound the wait so attached descendants
    // cannot keep the launcher alive indefinitely.
    WaitForSingleObject(outputCompleteEvent_.get(), OutputDrainGraceMilliseconds);

    inputRelay_.request_stop();
    if (inputRelay_.joinable())
    {
        // CancelSynchronousIo unblocks a piped stdin read; for a console handle the relay's
        // own readiness poll (RelayInput) is what observes the stop request instead.
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
    // Load the bundled ConPTY rather than the inbox one: the inbox host repaints its whole
    // viewport on resize, which garbles output inside a terminal that reflows on its own.
    // conpty.dll starts the OpenConsole.exe beside it. Both come only from this executable's
    // protected install directory, and conpty.dll's own dependencies only from System32.
    std::wstring executablePath;
    const DWORD pathError = GetCurrentExecutablePath(executablePath);
    if (pathError != ERROR_SUCCESS)
    {
        error = L"Could not locate the bundled pseudoconsole: " + FormatWindowsError(pathError);
        return false;
    }
    const std::wstring conptyPath =
        (std::filesystem::path(executablePath).parent_path() / L"conpty.dll").native();
    const HMODULE conpty =
        LoadLibraryExW(conptyPath.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (conpty == nullptr)
    {
        const DWORD loadError = GetLastError();
        error = L"Could not load the bundled pseudoconsole " + conptyPath + L": " +
                FormatWindowsError(loadError);
        return false;
    }

    // The module stays loaded for the rest of this short-lived host process.
    api_.create = reinterpret_cast<CreatePseudoConsoleFunction>(
        GetProcAddress(conpty, "ConptyCreatePseudoConsole"));
    api_.resize = reinterpret_cast<ResizePseudoConsoleFunction>(
        GetProcAddress(conpty, "ConptyResizePseudoConsole"));
    api_.close = reinterpret_cast<ClosePseudoConsoleFunction>(
        GetProcAddress(conpty, "ConptyClosePseudoConsole"));
    if (api_.create == nullptr || api_.resize == nullptr || api_.close == nullptr)
    {
        error = L"The bundled pseudoconsole " + conptyPath + L" is missing required exports.";
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
