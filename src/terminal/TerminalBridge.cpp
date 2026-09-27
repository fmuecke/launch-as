// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TerminalBridge.h"

#include "Win32Support.h"

#include <Aclapi.h>
#include <Windows.h>
#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <iostream>
#include <objbase.h>
#include <sddl.h>
#include <string>
#include <utility>
#include <vector>

namespace launch_as
{
namespace
{

constexpr DWORD PipeMode =
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
#ifdef LAUNCH_AS_TESTING
constexpr DWORD BrokerPipeConnectionTimeoutMilliseconds = 250;
#else
constexpr DWORD BrokerPipeConnectionTimeoutMilliseconds = 5'000;
#endif
constexpr auto ResizePollInterval = std::chrono::milliseconds(50);

using UniqueLocalMemory = LocalAllocation<void*>;

struct PipeSecurityDescriptor final
{
    SECURITY_DESCRIPTOR value {};
    UniqueLocalMemory dacl;

    [[nodiscard]] PSECURITY_DESCRIPTOR get() noexcept { return &value; }
};

enum class PipeDirection
{
    ParentWrites,
    ParentReads
};

[[nodiscard]] bool CreatePipeSecurityDescriptor(
    std::wstring_view childSid, PipeSecurityDescriptor& descriptor, std::wstring& error)
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        const DWORD tokenError = GetLastError();
        error = L"Could not open the launcher token for terminal-pipe security: " +
                FormatWindowsError(tokenError);
        return false;
    }
    UniqueHandle token(rawToken);

    std::vector<BYTE> tokenStorage;
    const DWORD tokenReadError = QueryTokenInformation(token.get(), TokenUser, tokenStorage);
    if (tokenReadError != ERROR_SUCCESS)
    {
        error = L"Could not read the launcher identity for terminal-pipe security: " +
                FormatWindowsError(tokenReadError);
        return false;
    }

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenStorage.data());
    if (!IsValidSid(tokenUser->User.Sid))
    {
        error = L"The launcher token contains an invalid SID.";
        return false;
    }

    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid {};
    DWORD systemSidBytes = static_cast<DWORD>(systemSid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidBytes))
    {
        const DWORD systemSidError = GetLastError();
        error = L"Could not create the SYSTEM identity for terminal-pipe security: " +
                FormatWindowsError(systemSidError);
        return false;
    }

    UniqueLocalMemory childSidStorage;
    PSID childSidValue = nullptr;
    if (!childSid.empty())
    {
        const std::wstring childSidText(childSid);
        const BOOL convertedChildSid = ConvertStringSidToSidW(childSidText.c_str(), &childSidValue);
        const DWORD childSidError = convertedChildSid ? ERROR_SUCCESS : GetLastError();
        if (!convertedChildSid)
        {
            error = L"The broker child identity is not a valid SID: " +
                    FormatWindowsError(childSidError);
            return false;
        }
        childSidStorage.reset(childSidValue);
        if (!IsValidSid(childSidValue))
        {
            error = L"The broker child identity is not a valid SID.";
            return false;
        }
    }

    std::array<EXPLICIT_ACCESSW, 3> accessEntries {};
    const auto grantAccess = [](EXPLICIT_ACCESSW& entry, PSID sid, DWORD access)
    {
        entry.grfAccessPermissions = access;
        entry.grfAccessMode = GRANT_ACCESS;
        entry.grfInheritance = NO_INHERITANCE;
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
        entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid);
    };
    grantAccess(accessEntries[0], systemSid.data(), GENERIC_ALL);
    grantAccess(accessEntries[1], tokenUser->User.Sid, GENERIC_ALL);
    ULONG entryCount = 2;
    if (childSidValue != nullptr)
    {
        grantAccess(accessEntries[entryCount], childSidValue, GENERIC_READ | GENERIC_WRITE);
        ++entryCount;
    }

    PACL rawDacl = nullptr;
    const DWORD aclError = SetEntriesInAclW(entryCount, accessEntries.data(), nullptr, &rawDacl);
    if (aclError != ERROR_SUCCESS)
    {
        error = L"Could not create terminal-pipe ACL: " + FormatWindowsError(aclError);
        return false;
    }
    UniqueLocalMemory dacl(rawDacl);
    if (!InitializeSecurityDescriptor(descriptor.get(), SECURITY_DESCRIPTOR_REVISION))
    {
        const DWORD descriptorError = GetLastError();
        error =
            L"Could not initialize terminal-pipe security: " + FormatWindowsError(descriptorError);
        return false;
    }
    if (!SetSecurityDescriptorDacl(descriptor.get(), TRUE, rawDacl, FALSE))
    {
        const DWORD descriptorError = GetLastError();
        error =
            L"Could not configure terminal-pipe security: " + FormatWindowsError(descriptorError);
        return false;
    }
    if (!SetSecurityDescriptorControl(descriptor.get(), SE_DACL_PROTECTED, SE_DACL_PROTECTED))
    {
        const DWORD descriptorError = GetLastError();
        error = L"Could not protect terminal-pipe security: " + FormatWindowsError(descriptorError);
        return false;
    }
    descriptor.dacl = std::move(dacl);
    return true;
}

[[nodiscard]] bool CreatePipeName(
    std::wstring_view purpose, std::wstring& pipeName, std::wstring& error)
{
    GUID identifier {};
    const HRESULT createResult = CoCreateGuid(&identifier);
    if (FAILED(createResult))
    {
        error = L"Could not create a unique terminal-pipe name.";
        return false;
    }

    std::array<wchar_t, 40> identifierText {};
    if (StringFromGUID2(
            identifier, identifierText.data(), static_cast<int>(identifierText.size())) == 0)
    {
        error = L"Could not format a unique terminal-pipe name.";
        return false;
    }

    pipeName = L"\\\\.\\pipe\\launch-as-";
    pipeName += identifierText.data();
    pipeName += L"-";
    pipeName += purpose;
    return true;
}

[[nodiscard]] bool CreateTerminalPipeServer(std::wstring_view purpose, PipeDirection direction,
    PSECURITY_DESCRIPTOR descriptor, UniqueHandle& parentEndpoint, std::wstring& childPipeName,
    std::wstring& error)
{
    if (!CreatePipeName(purpose, childPipeName, error))
    {
        return false;
    }
    SECURITY_ATTRIBUTES serverSecurity {
        .nLength = sizeof(serverSecurity),
        .lpSecurityDescriptor = descriptor,
        .bInheritHandle = FALSE
    };
    const DWORD serverAccess =
        direction == PipeDirection::ParentWrites ? PIPE_ACCESS_OUTBOUND : PIPE_ACCESS_INBOUND;
    HANDLE rawServer = CreateNamedPipeW(childPipeName.c_str(),
        serverAccess | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
        PipeMode,
        1,
        RelayBufferBytes,
        RelayBufferBytes,
        0,
        &serverSecurity);
    if (rawServer == INVALID_HANDLE_VALUE)
    {
        const DWORD serverError = GetLastError();
        error = L"Could not create the broker terminal " + std::wstring(purpose) + L" server: " +
                FormatWindowsError(serverError);
        return false;
    }
    parentEndpoint.reset(rawServer);
    return true;
}

[[nodiscard]] bool ConnectTerminalPipeServer(
    HANDLE server, std::wstring_view purpose, std::wstring& error)
{
    UniqueHandle operationEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!operationEvent)
    {
        const DWORD eventError = GetLastError();
        error = L"Could not create the broker terminal " + std::wstring(purpose) +
                L" connection event: " + FormatWindowsError(eventError);
        return false;
    }
    OVERLAPPED overlapped {};
    overlapped.hEvent = operationEvent.get();
    if (ConnectNamedPipe(server, &overlapped))
    {
        return true;
    }
    const DWORD connectError = GetLastError();
    if (connectError == ERROR_PIPE_CONNECTED)
    {
        return true;
    }
    if (connectError != ERROR_IO_PENDING)
    {
        error = L"Could not connect the broker terminal " + std::wstring(purpose) + L" server: " +
                FormatWindowsError(connectError);
        return false;
    }

    const DWORD wait =
        WaitForSingleObject(operationEvent.get(), BrokerPipeConnectionTimeoutMilliseconds);
    if (wait != WAIT_OBJECT_0)
    {
        const DWORD waitError = wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
        CancelIoEx(server, &overlapped);
        DWORD ignored = 0;
        static_cast<void>(GetOverlappedResult(server, &overlapped, &ignored, TRUE));
        if (wait == WAIT_TIMEOUT)
        {
            error = L"Timed out waiting for the broker terminal " + std::wstring(purpose) +
                    L" client to connect.";
        }
        else
        {
            error = L"Could not wait for the broker terminal " + std::wstring(purpose) +
                    L" client: " + FormatWindowsError(waitError);
        }
        return false;
    }

    DWORD ignored = 0;
    if (GetOverlappedResult(server, &overlapped, &ignored, FALSE))
    {
        return true;
    }
    const DWORD completionError = GetLastError();
    error = L"Could not connect the broker terminal " + std::wstring(purpose) + L" server: " +
            FormatWindowsError(completionError);
    return false;
}

} // namespace

TerminalBridge::~TerminalBridge() { Stop(); }

bool TerminalBridge::InitializeForBroker(
    std::wstring_view childSid, TerminalPipeNames& pipeNames, std::wstring& error)
{
    pipeNames = {};
    parentInput_ = GetStdHandle(STD_INPUT_HANDLE);
    parentOutput_ = GetStdHandle(STD_OUTPUT_HANDLE);
    const HANDLE parentError = GetStdHandle(STD_ERROR_HANDLE);
    if (!IsUsableHandle(parentInput_) || !IsUsableHandle(parentOutput_) ||
        !IsUsableHandle(parentError))
    {
        error = L"Terminal mode requires usable standard input, output, and error handles.";
        return false;
    }
    outputCompleteEvent_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!outputCompleteEvent_)
    {
        const DWORD eventError = GetLastError();
        error = L"Could not create the terminal output completion event: " +
                FormatWindowsError(eventError);
        return false;
    }
    PipeSecurityDescriptor pipeSecurity;
    if (!CreatePipeSecurityDescriptor(childSid, pipeSecurity, error))
    {
        return false;
    }
    if (!CreateTerminalPipeServer(L"input",
            PipeDirection::ParentWrites,
            pipeSecurity.get(),
            inputWrite_,
            pipeNames.input,
            error) ||
        !CreateTerminalPipeServer(L"output",
            PipeDirection::ParentReads,
            pipeSecurity.get(),
            outputRead_,
            pipeNames.output,
            error) ||
        !CreateTerminalPipeServer(L"resize",
            PipeDirection::ParentWrites,
            pipeSecurity.get(),
            resizeWrite_,
            pipeNames.resize,
            error))
    {
        return false;
    }
    return true;
}

bool TerminalBridge::ConnectBrokerChild(std::wstring& error)
{
    if (childConnected_ || !inputWrite_ || !outputRead_ || !resizeWrite_)
    {
        error = L"The terminal bridge is not ready for a broker child connection.";
        return false;
    }
    if (!ConnectTerminalPipeServer(inputWrite_.get(), L"input", error) ||
        !ConnectTerminalPipeServer(outputRead_.get(), L"output", error) ||
        !ConnectTerminalPipeServer(resizeWrite_.get(), L"resize", error))
    {
        return false;
    }
    childConnected_ = true;
    return true;
}

bool TerminalBridge::Start(std::wstring& error)
{
    if (!childConnected_ || !inputWrite_ || !outputRead_ || !resizeWrite_)
    {
        error = L"The terminal bridge is not initialized.";
        return false;
    }
    if (!terminalMode_.Configure(parentInput_, parentOutput_, error))
    {
        return false;
    }

    const COORD initialSize = terminalSize();
    DWORD resizeError = ERROR_SUCCESS;
    if (!SendResize(initialSize, resizeError))
    {
        terminalMode_.Restore();
        error = L"Could not send the initial terminal size to the pseudoconsole host: " +
                FormatWindowsError(resizeError);
        return false;
    }

    started_ = true;
    try
    {
        inputRelay_ = std::jthread(
            [this, source = parentInput_](std::stop_token stopToken) noexcept
            {
                // Keep ConPTY input open after stdin EOF; closing it injects Ctrl+C into the child.
                static_cast<void>(RelayInput(source, inputWrite_.get(), stopToken));
            });

        outputRelay_ = std::jthread(
            [source = outputRead_.get(),
                destination = parentOutput_,
                completionEvent = outputCompleteEvent_.get()](std::stop_token stopToken) noexcept
            {
                RelayOutput(source, destination, stopToken);
                SetEvent(completionEvent);
            });

        resizeRelay_ = std::jthread(
            [this, previousSize = initialSize](std::stop_token stopToken) mutable noexcept
            {
                while (!stopToken.stop_requested())
                {
                    std::this_thread::sleep_for(ResizePollInterval);
                    const COORD size = terminalSize();
                    DWORD resizeError = ERROR_SUCCESS;
                    if ((size.X != previousSize.X || size.Y != previousSize.Y) &&
                        !SendResize(size, resizeError))
                    {
                        std::wcerr << L"Could not send the terminal resize to the pseudoconsole "
                                      L"host: "
                                   << FormatWindowsError(resizeError) << L"\n";
                        return;
                    }
                    previousSize = size;
                }
            });
    }
    catch (const std::exception&)
    {
        error = L"Could not start the terminal bridge threads.";
        Stop();
        return false;
    }
    return true;
}

DWORD TerminalBridge::WaitForOutput(DWORD& waitError) const noexcept
{
    if (!outputCompleteEvent_)
    {
        waitError = ERROR_INVALID_HANDLE;
        return WAIT_FAILED;
    }
    const DWORD waitResult = WaitForSingleObject(outputCompleteEvent_.get(), INFINITE);
    waitError = waitResult == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
    return waitResult;
}

void TerminalBridge::Stop() noexcept
{
    if (!started_)
    {
        return;
    }

    resizeRelay_.request_stop();
    if (resizeRelay_.joinable())
    {
        CancelSynchronousIo(resizeRelay_.native_handle());
        resizeRelay_.join();
    }
    resizeWrite_.reset();

    inputRelay_.request_stop();
    if (inputRelay_.joinable())
    {
        // CancelSynchronousIo unblocks a piped stdin read; for a console handle the relay's
        // own readiness poll (RelayInput) is what observes the stop request instead.
        CancelSynchronousIo(inputRelay_.native_handle());
        inputRelay_.join();
    }
    inputWrite_.reset();

    if (outputRelay_.joinable())
    {
        if (WaitForSingleObject(outputCompleteEvent_.get(), OutputDrainGraceMilliseconds) !=
            WAIT_OBJECT_0)
        {
            // A target process can retain a duplicate of its output client. Stop the
            // relay after the grace period instead of waiting indefinitely for EOF.
            outputRelay_.request_stop();
            CancelSynchronousIo(outputRelay_.native_handle());
            DisconnectNamedPipe(outputRead_.get());
            CancelSynchronousIo(outputRelay_.native_handle());
        }
        outputRelay_.join();
    }
    outputRead_.reset();

    terminalMode_.Restore();
    started_ = false;
}

bool TerminalBridge::SendResize(COORD size, DWORD& error) noexcept
{
    if (!resizeWrite_)
    {
        error = ERROR_INVALID_HANDLE;
        return false;
    }
    return WriteTerminalSize(resizeWrite_.get(), size, error);
}

COORD TerminalBridge::terminalSize() const noexcept { return CurrentTerminalSize(parentOutput_); }

bool TerminalBridge::supportsCursorInheritance() const noexcept
{
    return SupportsTerminalCursorInheritance(parentInput_, parentOutput_);
}

} // namespace launch_as
