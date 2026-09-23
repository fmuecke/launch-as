// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerPipeServer.h"
#include "BrokerProtocol.h"
#include "TestSupport.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace
{

constexpr DWORD WorkerReleaseTimeoutMilliseconds = 1'000;

struct LaunchCapture
{
    bool invoked = false;
    launch_as::broker::BrokerRequest request;
    std::vector<BYTE> callerSid;
    std::vector<BYTE> callerLogonSid;
    DWORD callerSessionId = MAXDWORD;
};

struct SessionFinishCapture
{
    bool invoked = false;
    bool processTreeExited = true;
    std::wstring profileId;
};

void CaptureSessionFinished(
    void* context, const launch_as::broker::BrokerRequest& request, bool processTreeExited)
{
    auto* capture = static_cast<SessionFinishCapture*>(context);
    if (capture != nullptr)
    {
        capture->invoked = true;
        capture->processTreeExited = processTreeExited;
        capture->profileId = request.profileId;
    }
}

[[nodiscard]] bool TestUnconfirmedTeardownNotifiesSessionHandler()
{
    launch_as::broker::BrokerRequest request;
    request.profileId = L"LaunchAsUser";
    SessionFinishCapture capture;
    launch_as::broker::FinishBrokerSession(CaptureSessionFinished, &capture, request, true, false);
    return Expect(capture.invoked,
               L"The broker did not report an unconfirmed teardown to the session handler.") &&
           Expect(!capture.processTreeExited,
               L"The broker did not report the unconfirmed process tree to the session handler.") &&
           Expect(capture.profileId == request.profileId,
               L"The broker changed the profile while finishing a session.");
}

DWORD CaptureLaunchRequest(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller, launch_as::broker::BrokerChildProcess&)
{
    auto* capture = static_cast<LaunchCapture*>(context);
    if (capture == nullptr)
    {
        return ERROR_INVALID_PARAMETER;
    }
    capture->invoked = true;
    capture->request = request;
    capture->callerSid = caller.userSid;
    capture->callerLogonSid = caller.logonSid;
    capture->callerSessionId = caller.sessionId;
    return ERROR_BUSY;
}

DWORD LaunchQuickChild(void*, const launch_as::broker::BrokerRequest&,
    const launch_as::broker::BrokerCallerIdentity&, launch_as::broker::BrokerChildProcess& child)
{
    return launch_as::broker::LaunchQuickBrokerChildForTesting(child);
}

DWORD LaunchDelayedChild(void*, const launch_as::broker::BrokerRequest&,
    const launch_as::broker::BrokerCallerIdentity&, launch_as::broker::BrokerChildProcess& child)
{
    return launch_as::broker::LaunchDelayedBrokerChildForTesting(child);
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

class SessionServerThread final
{
  public:
    SessionServerThread(HANDLE pipe, HANDLE stopEvent,
        launch_as::broker::LaunchRequestHandler launchHandler = LaunchQuickChild,
        SessionFinishCapture* finishCapture = nullptr)
        : completed_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
          thread_(
              [pipe, stopEvent, launchHandler, finishCapture, this]
              {
                  launch_as::UniqueHandle connectEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
                  if (!connectEvent)
                  {
                      return;
                  }
                  OVERLAPPED overlapped {};
                  overlapped.hEvent = connectEvent.get();
                  const BOOL connected = ConnectNamedPipe(pipe, &overlapped);
                  const DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
                  if (!connected && connectError == ERROR_IO_PENDING)
                  {
                      if (WaitForSingleObject(connectEvent.get(),
                              WorkerReleaseTimeoutMilliseconds) != WAIT_OBJECT_0)
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
                  else if (!connected && connectError != ERROR_PIPE_CONNECTED)
                  {
                      return;
                  }
                  launch_as::broker::ServeControlPipeRequest(pipe,
                      stopEvent,
                      nullptr,
                      nullptr,
                      launchHandler,
                      nullptr,
                      CaptureSessionFinished,
                      finishCapture);
                  SetEvent(completed_.get());
              })
    {
    }

    ~SessionServerThread()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    [[nodiscard]] bool WaitForCompletion(DWORD timeout) const
    {
        return completed_ && WaitForSingleObject(completed_.get(), timeout) == WAIT_OBJECT_0;
    }

  private:
    launch_as::UniqueHandle completed_;
    std::thread thread_;
};

[[nodiscard]] bool TestInteractiveWorkerOwnsDetachedProcessTree()
{
    const std::wstring pipeName =
        L"\\\\.\\pipe\\launch-as-broker-detached-test-" + std::to_wstring(GetCurrentProcessId());
    launch_as::UniqueHandle server(CreateNamedPipeW(pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        0,
        nullptr));
    launch_as::UniqueHandle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!Expect(static_cast<bool>(server) && static_cast<bool>(stopEvent),
            L"Could not create the detached interactive test pipe."))
    {
        return false;
    }

    SessionFinishCapture finishCapture;
    SessionServerThread serverThread(
        server.get(), stopEvent.get(), LaunchDelayedChild, &finishCapture);
    launch_as::UniqueHandle client(CreateFileW(
        pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!Expect(static_cast<bool>(client), L"Could not connect the detached interactive test."))
    {
        return false;
    }
    constexpr char request[] =
        R"json({"version":1,"requestId":"123e4567-e89b-12d3-a456-426614174000","operation":"launch","profileId":"LaunchAsUser","mode":"interactive","arguments":[],"workingDirectory":"C:\\repo","interactive":{"leasePipe":"\\\\.\\pipe\\launch-as-interactive-123e4567e89b12d3a456426614174000","nonce":"6f9619ff-8b86-d011-b42d-00c04fc964ff"}})json";
    DWORD bytesWritten = 0;
    std::array<char, launch_as::broker::MaximumMessageBytes> response {};
    DWORD bytesRead = 0;
    if (!Expect(WriteFile(client.get(), request, sizeof(request) - 1, &bytesWritten, nullptr) &&
                    bytesWritten == sizeof(request) - 1,
            L"Could not send the detached interactive request.") ||
        !Expect(ReadFile(client.get(),
                    response.data(),
                    static_cast<DWORD>(response.size()),
                    &bytesRead,
                    nullptr) &&
                    bytesRead != 0,
            L"The detached interactive request did not receive a launch response."))
    {
        return false;
    }

    const ULONGLONG disconnectedAt = GetTickCount64();
    client.reset();
    const bool completed = serverThread.WaitForCompletion(3'000);
    const ULONGLONG elapsed = GetTickCount64() - disconnectedAt;
    return Expect(completed, L"The detached interactive worker did not finish.") &&
           Expect(elapsed >= 500,
               L"Closing the control connection terminated the interactive child early.") &&
           Expect(finishCapture.invoked && finishCapture.processTreeExited,
               L"The detached interactive worker did not confirm process-tree completion.");
}

[[nodiscard]] bool TestInteractiveModeDispatchesAuthenticatedCaller()
{
    const std::wstring pipeName = L"\\\\.\\pipe\\launch-as-broker-unsupported-mode-test-" +
                                  std::to_wstring(GetCurrentProcessId());
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
            L"Could not create the interactive-mode test pipe."))
    {
        return false;
    }

    LaunchCapture capture;
    ServerThread serverThread(server.get(), stopEvent.get(), &capture);
    launch_as::UniqueHandle client(CreateFileW(
        pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!Expect(static_cast<bool>(client), L"Could not connect to the interactive-mode test pipe."))
    {
        return false;
    }

    constexpr char request[] =
        R"json({"version":1,"requestId":"123e4567-e89b-12d3-a456-426614174000","operation":"launch","profileId":"LaunchAsUser","mode":"interactive","arguments":[],"workingDirectory":"C:\\repo","interactive":{"leasePipe":"\\\\.\\pipe\\launch-as-interactive-123e4567e89b12d3a456426614174000","nonce":"6f9619ff-8b86-d011-b42d-00c04fc964ff"}})json";
    DWORD bytesWritten = 0;
    if (!Expect(WriteFile(client.get(), request, sizeof(request) - 1, &bytesWritten, nullptr) &&
                    bytesWritten == sizeof(request) - 1,
            L"Could not send the interactive-mode broker request."))
    {
        return false;
    }

    std::string response(512, '\0');
    DWORD bytesRead = 0;
    if (!Expect(ReadFile(client.get(),
                    response.data(),
                    static_cast<DWORD>(response.size()),
                    &bytesRead,
                    nullptr),
            L"Could not read the interactive-mode broker response."))
    {
        return false;
    }
    response.resize(bytesRead);
    return Expect(serverThread.connected(), L"The interactive-mode test pipe did not connect.") &&
           Expect(capture.invoked, L"The broker did not dispatch the interactive request.") &&
           Expect(capture.request.operation ==
                          launch_as::broker::RequestOperation::InteractiveLaunch &&
                      capture.request.interactive.leasePipe ==
                          L"\\\\.\\pipe\\launch-as-interactive-"
                          L"123e4567e89b12d3a456426614174000" &&
                      capture.request.interactive.nonce == L"6f9619ff-8b86-d011-b42d-00c04fc964ff",
               L"The broker changed the private interactive payload before dispatch.") &&
           Expect(!capture.callerLogonSid.empty() &&
                      IsValidSid(const_cast<BYTE*>(capture.callerLogonSid.data())) &&
                      capture.callerSessionId != 0 && capture.callerSessionId != MAXDWORD,
               L"Interactive dispatch omitted the authenticated caller session identity.") &&
           Expect(response.find("\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\"") !=
                      std::string::npos,
               L"The interactive-mode response did not preserve the request id.") &&
           Expect(response.find("\"reasonCode\":\"session_limit_reached\"") != std::string::npos &&
                      response.find("\"win32Error\":170") != std::string::npos,
               L"The broker did not dispatch through the launch handler.");
}

[[nodiscard]] bool TestWorkerReleasesHeldControlClient()
{
    const std::wstring pipeName = L"\\\\.\\pipe\\launch-as-broker-held-control-test-" +
                                  std::to_wstring(GetCurrentProcessId());
    launch_as::UniqueHandle server(CreateNamedPipeW(pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        0,
        nullptr));
    launch_as::UniqueHandle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!Expect(static_cast<bool>(server) && static_cast<bool>(stopEvent),
            L"Could not create the held-control-client test pipe."))
    {
        return false;
    }

    SessionServerThread serverThread(server.get(), stopEvent.get());
    launch_as::UniqueHandle client(CreateFileW(
        pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!Expect(static_cast<bool>(client), L"Could not connect the held-control-client test pipe."))
    {
        return false;
    }

    constexpr char request[] =
        R"json({"version":1,"requestId":"123e4567-e89b-12d3-a456-426614174000","operation":"launch","profileId":"LaunchAsUser","mode":"console","arguments":[],"workingDirectory":"C:\\repo","console":{"pipeIn":"\\\\.\\pipe\\launch-as-test-in","pipeOut":"\\\\.\\pipe\\launch-as-test-out","pipeResize":"\\\\.\\pipe\\launch-as-test-resize","cols":120,"rows":30}})json";
    DWORD bytesWritten = 0;
    if (!Expect(WriteFile(client.get(), request, sizeof(request) - 1, &bytesWritten, nullptr) &&
                    bytesWritten == sizeof(request) - 1,
            L"Could not send the held-control-client launch request."))
    {
        return false;
    }

    std::array<char, launch_as::broker::MaximumMessageBytes> response {};
    DWORD bytesRead = 0;
    if (!Expect(ReadFile(client.get(),
                    response.data(),
                    static_cast<DWORD>(response.size()),
                    &bytesRead,
                    nullptr) &&
                    bytesRead != 0,
            L"The held-control-client test did not receive the launch response.") ||
        !Expect(ReadFile(client.get(),
                    response.data(),
                    static_cast<DWORD>(response.size()),
                    &bytesRead,
                    nullptr) &&
                    bytesRead != 0,
            L"The held-control-client test did not receive the exit response."))
    {
        return false;
    }

    const bool released = serverThread.WaitForCompletion(WorkerReleaseTimeoutMilliseconds);
    client.reset();
    static_cast<void>(serverThread.WaitForCompletion(WorkerReleaseTimeoutMilliseconds));
    return Expect(released,
        L"The broker worker remained occupied after a client held its control connection open.");
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
        R"json({"version":1,"requestId":"123e4567-e89b-12d3-a456-426614174000","operation":"launch","profileId":"LaunchAsUser","mode":"console","arguments":[],"workingDirectory":"C:\\repo","console":{"pipeIn":"\\\\.\\pipe\\launch-as-test-in","pipeOut":"\\\\.\\pipe\\launch-as-test-out","pipeResize":"\\\\.\\pipe\\launch-as-test-resize","cols":120,"rows":30}})json";
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
    if (!TestInteractiveModeDispatchesAuthenticatedCaller() ||
        !TestUnconfirmedTeardownNotifiesSessionHandler() ||
        !TestWorkerReleasesHeldControlClient() || !TestInteractiveWorkerOwnsDetachedProcessTree())
    {
        return 1;
    }
    return Expect(serverThread.connected(), L"The broker test pipe did not connect.") &&
                   Expect(capture.invoked, L"The broker did not dispatch the launch request.") &&
                   Expect(!capture.callerSid.empty() &&
                              IsValidSid(const_cast<BYTE*>(capture.callerSid.data())),
                       L"The broker did not provide a valid authenticated caller SID.") &&
                   Expect(!capture.callerLogonSid.empty() &&
                              IsValidSid(const_cast<BYTE*>(capture.callerLogonSid.data())),
                       L"The broker did not provide the authenticated caller logon SID.") &&
                   Expect(capture.request.arguments.empty(),
                       L"The broker changed the launch request before dispatching it.") &&
                   Expect(response.find("\"requestId\":\"123e4567-e89b-12d3-a456-426614174000\"") !=
                              std::string::npos,
                       L"The broker did not preserve the request id.") &&
                   Expect(response.find("\"reasonCode\":\"session_limit_reached\"") !=
                                  std::string::npos &&
                              response.find("\"win32Error\":170") != std::string::npos,
                       L"The broker did not return the stable session-limit response.")
               ? 0
               : 1;
}
