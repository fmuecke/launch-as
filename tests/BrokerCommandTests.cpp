// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerControlPipe.h"
#include "BrokerPipeServer.h"
#include "BrokerProtocol.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace
{

constexpr int SkipInstalledBrokerService = 77;
constexpr wchar_t BrokerServiceName[] = L"launch-as-broker";

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

[[nodiscard]] bool IsBrokerServiceInstalled()
{
    const SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr)
    {
        return false;
    }
    const SC_HANDLE service = OpenServiceW(manager, BrokerServiceName, 0);
    if (service != nullptr)
    {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return true;
    }
    const DWORD serviceError = GetLastError();
    CloseServiceHandle(manager);
    return serviceError == ERROR_ACCESS_DENIED;
}

struct CommandResult
{
    DWORD exitCode = ERROR_GEN_FAILURE;
    std::wstring output;
};

[[nodiscard]] CommandResult RunCommandAndCapture(
    std::wstring_view brokerPath, std::wstring_view arguments)
{
    std::wstring commandLine = Quote(brokerPath) + L" " + std::wstring(arguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    SECURITY_ATTRIBUTES attributes {};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE rawRead = nullptr;
    HANDLE rawWrite = nullptr;
    if (!CreatePipe(&rawRead, &rawWrite, &attributes, 0))
    {
        return {.exitCode = GetLastError()};
    }
    launch_as::UniqueHandle read(rawRead);
    launch_as::UniqueHandle write(rawWrite);
    if (!SetHandleInformation(read.get(), HANDLE_FLAG_INHERIT, 0))
    {
        return {.exitCode = GetLastError()};
    }

    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.hStdInput = nullptr;
    startupInfo.hStdOutput = write.get();
    startupInfo.hStdError = write.get();
    PROCESS_INFORMATION processInfo {};
    if (!CreateProcessW(nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo))
    {
        return {.exitCode = GetLastError()};
    }
    CloseHandle(processInfo.hThread);
    write.reset();
    WaitForSingleObject(processInfo.hProcess, INFINITE);

    CommandResult result;
    if (!GetExitCodeProcess(processInfo.hProcess, &result.exitCode))
    {
        result.exitCode = GetLastError();
    }
    CloseHandle(processInfo.hProcess);

    std::array<char, 2048> output {};
    DWORD bytesRead = 0;
    if (!ReadFile(
            read.get(), output.data(), static_cast<DWORD>(output.size()), &bytesRead, nullptr) &&
        GetLastError() != ERROR_BROKEN_PIPE)
    {
        result.exitCode = GetLastError();
        return result;
    }
    const int characters =
        MultiByteToWideChar(CP_UTF8, 0, output.data(), static_cast<int>(bytesRead), nullptr, 0);
    if (characters > 0)
    {
        result.output.resize(static_cast<std::size_t>(characters));
        MultiByteToWideChar(CP_UTF8,
            0,
            output.data(),
            static_cast<int>(bytesRead),
            result.output.data(),
            characters);
    }
    return result;
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
    if (argumentCount != 3)
    {
        std::wcerr << L"Expected the launch-as-admin and launch-as-broker executable paths.\n";
        return 1;
    }
    const std::wstring_view adminPath(arguments[1]);
    const std::wstring_view brokerPath(arguments[2]);
    const CommandResult serviceCommand = RunCommandAndCapture(brokerPath, L"install");
    if (!Expect(serviceCommand.exitCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT &&
                    serviceCommand.output.find(L"Service Control Manager") != std::wstring::npos,
            L"The broker service accepted an administrative command."))
    {
        return 1;
    }
    if (IsBrokerServiceInstalled())
    {
        std::wcout << L"Skipped: the broker service is installed.\n";
        return SkipInstalledBrokerService;
    }

    const CommandResult unconfirmedEnroll =
        RunCommandAndCapture(adminPath, L"enroll arbitrary-profile");
    const CommandResult unconfirmedUnenroll =
        RunCommandAndCapture(adminPath, L"unenroll arbitrary-profile");
    if (!Expect(unconfirmedEnroll.exitCode == ERROR_CANCELLED &&
                    unconfirmedEnroll.output.find(L"without an interactive console") !=
                        std::wstring::npos,
            L"Broker enroll did not refuse a non-interactive destructive command.") ||
        !Expect(unconfirmedUnenroll.exitCode == ERROR_CANCELLED &&
                    unconfirmedUnenroll.output.find(L"without an interactive console") !=
                        std::wstring::npos,
            L"Broker unenroll did not refuse a non-interactive destructive command."))
    {
        return 1;
    }
    const CommandResult invalidCommand = RunCommandAndCapture(adminPath, L"enroll bad/name");
    if (!Expect(invalidCommand.exitCode == ERROR_INVALID_PARAMETER,
            L"Broker invalid account did not return ERROR_INVALID_PARAMETER.") ||
        !Expect(invalidCommand.output.find(L"Invalid account name") != std::wstring::npos &&
                    invalidCommand.output.find(L"enroll <account>") != std::wstring::npos,
            L"Broker invalid account did not explain its parameters."))
    {
        return 1;
    }
    if (!Expect(RunCommand(adminPath, L"install") == ERROR_ACCESS_DENIED,
            L"Admin install did not require elevation."))
    {
        return 1;
    }

    launch_as::UniqueHandle server(CreateNamedPipeW(launch_as::broker::ControlPipeName.data(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        0,
        nullptr));
    launch_as::UniqueHandle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!server)
    {
        const DWORD pipeError = GetLastError();
        if (pipeError == ERROR_ACCESS_DENIED)
        {
            std::wcout << L"Skipped: another broker instance owns the control pipe.\n";
            return SkipInstalledBrokerService;
        }
        std::wcerr << L"Could not create the broker control pipe: "
                   << launch_as::FormatWindowsError(pipeError) << L"\n";
        return 1;
    }
    if (!Expect(static_cast<bool>(stopEvent), L"Could not create the broker stop event."))
    {
        return 1;
    }

    launch_as::UniqueHandle occupied(CreateFileW(launch_as::broker::ControlPipeName.data(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr));
    if (!Expect(static_cast<bool>(occupied), L"Could not occupy the broker control pipe."))
    {
        return 1;
    }
    HANDLE rawSecondPipe = nullptr;
    const DWORD busyError = launch_as::broker::OpenBrokerControlPipe(rawSecondPipe);
    launch_as::UniqueHandle secondPipe(rawSecondPipe);
    if (!Expect(busyError == ERROR_PIPE_BUSY && !secondPipe,
            L"A second broker launch did not fail immediately while the pipe was busy."))
    {
        return 1;
    }
    occupied.reset();
    if (!DisconnectNamedPipe(server.get()))
    {
        std::wcerr << L"Could not release the occupied broker control pipe.\n";
        return 1;
    }

    ServerThread serverThread(server.get(), stopEvent.get());
    const DWORD result = RunCommand(adminPath, L"enroll LaunchAsUser --force");
    return Expect(serverThread.connected(), L"Admin enroll did not connect to the control pipe.") &&
                   Expect(result == ERROR_NOT_READY,
                       L"Admin enroll did not return the service response.")
               ? 0
               : 1;
}
