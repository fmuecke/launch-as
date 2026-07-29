// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TerminalBridge.h"

#include <Windows.h>
#include <array>
#include <cstddef>
#include <exception>
#include <memory>
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

struct LocalFreeDeleter
{
    void operator()(void* value) const noexcept
    {
        if (value != nullptr)
        {
            LocalFree(value);
        }
    }
};

using UniqueLocalMemory = std::unique_ptr<void, LocalFreeDeleter>;

enum class PipeDirection
{
    ParentWrites,
    ParentReads
};

[[nodiscard]] bool CreatePipeSecurityDescriptor(UniqueLocalMemory& descriptor, std::wstring& error)
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

    DWORD tokenBytes = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &tokenBytes);
    const DWORD tokenSizeError = GetLastError();
    if (tokenSizeError != ERROR_INSUFFICIENT_BUFFER || tokenBytes == 0)
    {
        error = L"Could not size the launcher identity for terminal-pipe security: " +
                FormatWindowsError(tokenSizeError);
        return false;
    }

    std::vector<std::byte> tokenStorage(tokenBytes);
    if (!GetTokenInformation(token.get(), TokenUser, tokenStorage.data(), tokenBytes, &tokenBytes))
    {
        const DWORD tokenReadError = GetLastError();
        error = L"Could not read the launcher identity for terminal-pipe security: " +
                FormatWindowsError(tokenReadError);
        return false;
    }

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenStorage.data());
    wchar_t* rawSid = nullptr;
    if (!IsValidSid(tokenUser->User.Sid))
    {
        error = L"The launcher token contains an invalid SID.";
        return false;
    }
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &rawSid))
    {
        const DWORD sidError = GetLastError();
        error = L"Could not format the launcher identity for terminal-pipe security: " +
                FormatWindowsError(sidError);
        return false;
    }
    std::unique_ptr<wchar_t, LocalFreeDeleter> sid(rawSid);

    const std::wstring securityDefinition =
        L"D:P(A;;GA;;;SY)(A;;GA;;;" + std::wstring(sid.get()) + L")";
    PSECURITY_DESCRIPTOR rawDescriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            securityDefinition.c_str(), SDDL_REVISION_1, &rawDescriptor, nullptr))
    {
        const DWORD descriptorError = GetLastError();
        error = L"Could not create terminal-pipe security: " + FormatWindowsError(descriptorError);
        return false;
    }
    descriptor.reset(rawDescriptor);
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

[[nodiscard]] bool CreateTerminalPipePair(std::wstring_view purpose, PipeDirection direction,
    PSECURITY_DESCRIPTOR descriptor, UniqueHandle& parentEndpoint, UniqueHandle& childEndpoint,
    std::wstring& error)
{
    std::wstring pipeName;
    if (!CreatePipeName(purpose, pipeName, error))
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
    HANDLE rawServer = CreateNamedPipeW(pipeName.c_str(),
        serverAccess | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PipeMode,
        1,
        RelayBufferBytes,
        RelayBufferBytes,
        0,
        &serverSecurity);
    if (rawServer == INVALID_HANDLE_VALUE)
    {
        const DWORD serverError = GetLastError();
        error = L"Could not create the terminal " + std::wstring(purpose) + L" server: " +
                FormatWindowsError(serverError);
        return false;
    }
    UniqueHandle server(rawServer);

    SECURITY_ATTRIBUTES inheritableClient {
        .nLength = sizeof(inheritableClient),
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle = FALSE
    };
    const DWORD clientAccess =
        direction == PipeDirection::ParentWrites ? GENERIC_READ : GENERIC_WRITE;
    HANDLE rawClient = CreateFileW(pipeName.c_str(),
        clientAccess,
        0,
        &inheritableClient,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
        nullptr);
    if (rawClient == INVALID_HANDLE_VALUE)
    {
        const DWORD clientError = GetLastError();
        error = L"Could not connect the terminal " + std::wstring(purpose) + L" client: " +
                FormatWindowsError(clientError);
        return false;
    }
    UniqueHandle client(rawClient);

    if (!ConnectNamedPipe(server.get(), nullptr))
    {
        const DWORD connectError = GetLastError();
        if (connectError != ERROR_PIPE_CONNECTED)
        {
            error = L"Could not connect the terminal " + std::wstring(purpose) + L" server: " +
                    FormatWindowsError(connectError);
            return false;
        }
    }

    parentEndpoint = std::move(server);
    childEndpoint = std::move(client);
    return true;
}

} // namespace

TerminalBridge::~TerminalBridge() { Stop(); }

bool TerminalBridge::Initialize(STARTUPINFOW& childStartupInformation, std::wstring& error)
{
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

    UniqueLocalMemory pipeSecurity;
    if (!CreatePipeSecurityDescriptor(pipeSecurity, error))
    {
        return false;
    }

    if (!CreateTerminalPipePair(L"input",
            PipeDirection::ParentWrites,
            static_cast<PSECURITY_DESCRIPTOR>(pipeSecurity.get()),
            inputWrite_,
            childInputRead_,
            error))
    {
        return false;
    }

    if (!CreateTerminalPipePair(L"output",
            PipeDirection::ParentReads,
            static_cast<PSECURITY_DESCRIPTOR>(pipeSecurity.get()),
            outputRead_,
            childOutputWrite_,
            error))
    {
        return false;
    }

    childStartupInformation.dwFlags |= STARTF_USESTDHANDLES;
    childStartupInformation.hStdInput = childInputRead_.get();
    childStartupInformation.hStdOutput = childOutputWrite_.get();
    childStartupInformation.hStdError = childOutputWrite_.get();
    return true;
}

bool TerminalBridge::PrepareChildProcessCreation(std::wstring& error)
{
    if (!childInputRead_ || !childOutputWrite_ || childHandlesInheritable_ || childProcessCreated_)
    {
        error = L"The terminal bridge is not ready for child-process creation.";
        return false;
    }

    if (!SetHandleInformation(childInputRead_.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        const DWORD inheritanceError = GetLastError();
        error = L"Could not enable inheritance for the terminal input client: " +
                FormatWindowsError(inheritanceError);
        return false;
    }
    if (!SetHandleInformation(childOutputWrite_.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        const DWORD inheritanceError = GetLastError();
        SetHandleInformation(childInputRead_.get(), HANDLE_FLAG_INHERIT, 0);
        childInputRead_.reset();
        childOutputWrite_.reset();
        error = L"Could not enable inheritance for the terminal output client: " +
                FormatWindowsError(inheritanceError);
        return false;
    }

    childHandlesInheritable_ = true;
    return true;
}

bool TerminalBridge::CompleteChildProcessCreation(bool processCreated, std::wstring& error)
{
    if (!childHandlesInheritable_)
    {
        error = L"The terminal client handles were not prepared for process creation.";
        return false;
    }

    childHandlesInheritable_ = false;
    if (processCreated)
    {
        childInputRead_.reset();
        childOutputWrite_.reset();
        childProcessCreated_ = true;
        return true;
    }

    DWORD inheritanceError = ERROR_SUCCESS;
    if (!SetHandleInformation(childInputRead_.get(), HANDLE_FLAG_INHERIT, 0))
    {
        inheritanceError = GetLastError();
    }
    if (!SetHandleInformation(childOutputWrite_.get(), HANDLE_FLAG_INHERIT, 0) &&
        inheritanceError == ERROR_SUCCESS)
    {
        inheritanceError = GetLastError();
    }
    if (inheritanceError != ERROR_SUCCESS)
    {
        childInputRead_.reset();
        childOutputWrite_.reset();
        error = L"Could not disable inheritance for the terminal clients: " +
                FormatWindowsError(inheritanceError);
        return false;
    }
    return true;
}

bool TerminalBridge::Start(std::wstring& error)
{
    if (!childProcessCreated_ || childHandlesInheritable_ || !inputWrite_ || !outputRead_)
    {
        error = L"The terminal bridge is not initialized.";
        return false;
    }
    if (!terminalMode_.Configure(parentInput_, parentOutput_, error))
    {
        return false;
    }

    UniqueHandle inputRelayWrite(std::exchange(inputWrite_, {}));

    started_ = true;
    try
    {
        inputRelay_ = std::jthread(
            [source = parentInput_, destination = std::move(inputRelayWrite)]() noexcept
            { RelayInput(source, destination.get()); });

        outputRelay_ = std::jthread(
            [source = outputRead_.get(),
                destination = parentOutput_,
                completionEvent = outputCompleteEvent_.get()](std::stop_token stopToken) noexcept
            {
                RelayOutput(source, destination, stopToken);
                SetEvent(completionEvent);
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

void TerminalBridge::Stop() noexcept
{
    if (!started_)
    {
        return;
    }

    if (inputRelay_.joinable())
    {
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

COORD TerminalBridge::terminalSize() const noexcept { return CurrentTerminalSize(parentOutput_); }

bool TerminalBridge::supportsCursorInheritance() const noexcept
{
    return SupportsTerminalCursorInheritance(parentInput_, parentOutput_);
}

} // namespace launch_as
