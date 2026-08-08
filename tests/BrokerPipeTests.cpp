// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerPipeServer.h"
#include "BrokerProtocol.h"
#include "Win32Support.h"

#include <Windows.h>
#include <iostream>
#include <string>
#include <thread>

namespace
{

struct LaunchCapture
{
    bool invoked = false;
    launch_as::broker::BrokerRequest request;
    bool capturedCallerIdentity = false;
};

DWORD CaptureLaunchRequest(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller)
{
    auto* capture = static_cast<LaunchCapture*>(context);
    if (capture == nullptr)
    {
        return ERROR_INVALID_PARAMETER;
    }
    capture->invoked = true;
    capture->request = request;
    capture->capturedCallerIdentity = !caller.userSid.empty();
    return ERROR_NOT_READY;
}

class ServerThread final
{
  public:
    ServerThread(HANDLE pipe, HANDLE stopEvent, LaunchCapture* capture)
        : thread_(
              [pipe, stopEvent, capture, this]
              {
                  if (!ConnectNamedPipe(pipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
                  {
                      connected_ = false;
                      return;
                  }
                  connected_ = true;
                  launch_as::broker::ServeControlPipeRequest(
                      pipe, stopEvent, nullptr, nullptr, CaptureLaunchRequest, capture);
                  DisconnectNamedPipe(pipe);
              })
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
    std::thread thread_;
    bool connected_ = false;
};

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

} // namespace

int wmain()
{
    const std::wstring pipeName =
        L"\\\\.\\pipe\\launch-as-broker-test-" + std::to_wstring(GetCurrentProcessId());
    launch_as::UniqueHandle server(CreateNamedPipeW(pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        0,
        nullptr));
    launch_as::UniqueHandle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!Expect(static_cast<bool>(server) && static_cast<bool>(stopEvent),
            L"Could not create the test pipe."))
    {
        return 1;
    }

    LaunchCapture capture;
    ServerThread serverThread(server.get(), stopEvent.get(), &capture);
    launch_as::UniqueHandle client(CreateFileW(
        pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!Expect(static_cast<bool>(client), L"Could not connect to the test pipe."))
    {
        return 1;
    }

    constexpr char request[] =
        R"json({"version":1,"requestId":"123e4567-e89b-12d3-a456-426614174000","operation":"launch","profileId":"agent-sandbox","mode":"console","arguments":[],"workingDirectory":"C:\\repo","console":{"pipeIn":"\\\\.\\pipe\\launch-as-test-in","pipeOut":"\\\\.\\pipe\\launch-as-test-out","cols":120,"rows":30}})json";
    DWORD bytesWritten = 0;
    if (!Expect(WriteFile(client.get(), request, sizeof(request) - 1, &bytesWritten, nullptr) &&
                    bytesWritten == sizeof(request) - 1,
            L"Could not send the broker request."))
    {
        return 1;
    }

    std::string response(512, '\0');
    DWORD bytesRead = 0;
    if (!Expect(ReadFile(client.get(),
                    response.data(),
                    static_cast<DWORD>(response.size()),
                    &bytesRead,
                    nullptr),
            L"Could not read the broker response."))
    {
        return 1;
    }
    response.resize(bytesRead);
    return Expect(serverThread.connected(), L"The broker test pipe did not connect.") &&
                   Expect(capture.invoked, L"The broker did not dispatch the launch request.") &&
                   Expect(capture.capturedCallerIdentity,
                       L"The broker did not provide the authenticated caller identity.") &&
                   Expect(capture.request.arguments.empty(),
                       L"The broker changed the launch request before dispatching it.") &&
                   Expect(response.find("\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\"") !=
                              std::string::npos,
                       L"The broker did not preserve the request id.") &&
                   Expect(response.find("\"reasonCode\":\"launch_failed\"") != std::string::npos,
                       L"The broker did not return the launch callback failure.")
               ? 0
               : 1;
}
