// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerPipeServer.h"
#include "BrokerProtocol.h"
#include "Win32Support.h"

#include <Windows.h>
#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace
{

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] std::wstring Quote(std::wstring_view value)
{
    return L"\"" + std::wstring(value) + L"\"";
}

[[nodiscard]] DWORD RunCommand(std::wstring_view brokerPath, std::wstring_view arguments)
{
    std::wstring commandLine = Quote(brokerPath) + L" " + std::wstring(arguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo {};
    if (!CreateProcessW(nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo))
    {
        return GetLastError();
    }
    CloseHandle(processInfo.hThread);
    WaitForSingleObject(processInfo.hProcess, INFINITE);
    DWORD exitCode = ERROR_GEN_FAILURE;
    if (!GetExitCodeProcess(processInfo.hProcess, &exitCode))
    {
        exitCode = GetLastError();
    }
    CloseHandle(processInfo.hProcess);
    return exitCode;
}

class ServerThread final
{
  public:
    ServerThread(HANDLE pipe, HANDLE stopEvent)
        : thread_([pipe, stopEvent, this] { Run(pipe, stopEvent); })
    {
    }

    ~ServerThread()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    [[nodiscard]] bool connected() const noexcept { return connected_; }

  private:
    void Run(HANDLE pipe, HANDLE stopEvent)
    {
        launch_as::UniqueHandle connectEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!connectEvent)
        {
            return;
        }
        OVERLAPPED overlapped {};
        overlapped.hEvent = connectEvent.get();
        if (!ConnectNamedPipe(pipe, &overlapped))
        {
            const DWORD connectError = GetLastError();
            if (connectError != ERROR_IO_PENDING ||
                WaitForSingleObject(connectEvent.get(), 1'000) != WAIT_OBJECT_0)
            {
                CancelIoEx(pipe, &overlapped);
                DWORD ignored = 0;
                static_cast<void>(GetOverlappedResult(pipe, &overlapped, &ignored, TRUE));
                return;
            }
            DWORD ignored = 0;
            if (!GetOverlappedResult(pipe, &overlapped, &ignored, FALSE))
            {
                return;
            }
        }
        connected_ = true;
        launch_as::broker::ServeControlPipeRequest(pipe, stopEvent);
        DisconnectNamedPipe(pipe);
    }

    std::thread thread_;
    std::atomic_bool connected_ = false;
};

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 2)
    {
        std::wcerr << L"Expected the launch-as-broker executable path.\n";
        return 1;
    }

    if (!Expect(RunCommand(arguments[1], L"register arbitrary-profile") == ERROR_INVALID_PARAMETER,
            L"Broker register accepted an arbitrary profile."))
    {
        return 1;
    }
    if (!Expect(RunCommand(arguments[1], L"install") == ERROR_ACCESS_DENIED,
            L"Broker install did not require elevation."))
    {
        return 1;
    }

    launch_as::UniqueHandle server(CreateNamedPipeW(launch_as::broker::ControlPipeName.data(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        0,
        nullptr));
    launch_as::UniqueHandle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!Expect(static_cast<bool>(server) && static_cast<bool>(stopEvent),
            L"Could not create the broker control pipe."))
    {
        return 1;
    }

    ServerThread serverThread(server.get(), stopEvent.get());
    const DWORD result = RunCommand(arguments[1], L"register agent-sandbox");
    return Expect(
               serverThread.connected(), L"Broker register did not connect to the control pipe.") &&
                   Expect(result == ERROR_NOT_READY,
                       L"Broker register did not return the service response.")
               ? 0
               : 1;
}
