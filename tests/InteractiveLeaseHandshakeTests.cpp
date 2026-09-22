// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProtocol.h"
#include "InteractiveDesktopLeaseCoordinator.h"
#include "TestSupport.h"

#include <Sddl.h>
#include <Windows.h>
#include <string>
#include <thread>

int wmain()
{
    const std::wstring pipeName = L"\\\\.\\pipe\\launch-as-interactive-handshake-test-" +
                                  std::to_wstring(GetCurrentProcessId()) + L"-" +
                                  std::to_wstring(GetTickCount64());
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!Expect(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    L"D:P(A;;GA;;;WD)", SDDL_REVISION_1, &descriptor, nullptr) != FALSE,
            L"Could not create the handshake test pipe descriptor."))
    {
        return 1;
    }
    SECURITY_ATTRIBUTES attributes {};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    HANDLE server = CreateNamedPipeW(pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        4096,
        4096,
        0,
        &attributes);
    LocalFree(descriptor);
    if (!Expect(server != INVALID_HANDLE_VALUE, L"Could not create the handshake test pipe."))
    {
        return 1;
    }

    constexpr std::wstring_view nonce = L"6f9619ff-8b86-d011-b42d-00c04fc964ff";
    DWORD coordinatorError = ERROR_SUCCESS;
    std::thread coordinator(
        [&]
        {
            const BOOL connected = ConnectNamedPipe(server, nullptr);
            const DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
            if (connected || connectError == ERROR_PIPE_CONNECTED)
            {
                coordinatorError = launch_as::ServeInteractiveDesktopLease(server, nonce);
            }
            else
            {
                coordinatorError = connectError;
            }
            DisconnectNamedPipe(server);
            CloseHandle(server);
        });

    HANDLE client = CreateFileW(pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
        nullptr);
    DWORD clientError = client != INVALID_HANDLE_VALUE ? ERROR_SUCCESS : GetLastError();
    if (client != INVALID_HANDLE_VALUE)
    {
        const std::string request =
            launch_as::broker::BuildInteractiveLeaseAcquireRequest(nonce, L"S-1-5-5-123-456");
        DWORD bytesWritten = 0;
        if (!WriteFile(
                client, request.data(), static_cast<DWORD>(request.size()), &bytesWritten, nullptr))
        {
            clientError = GetLastError();
        }
        char response = '\0';
        DWORD bytesRead = 0;
        if (clientError == ERROR_SUCCESS &&
            !ReadFile(client, &response, sizeof(response), &bytesRead, nullptr))
        {
            clientError = GetLastError();
        }
        CloseHandle(client);
    }
    coordinator.join();

    return Expect(
               coordinatorError != ERROR_SUCCESS, L"The coordinator accepted an anonymous peer.") &&
                   Expect(clientError != ERROR_SUCCESS,
                       L"The anonymous client unexpectedly received a lease response.")
               ? 0
               : 1;
}
