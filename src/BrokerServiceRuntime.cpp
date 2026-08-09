// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerServiceRuntime.h"

#include "BrokerAudit.h"
#include "BrokerCallerPolicy.h"
#include "BrokerDataDirectory.h"
#include "BrokerLogonToken.h"
#include "BrokerPipeServer.h"
#include "BrokerProcessLauncher.h"
#include "BrokerProtocol.h"
#include "BrokerRegistration.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <sddl.h>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr wchar_t ServiceName[] = L"launch-as-broker";
constexpr DWORD BrokerIdleTimeoutMilliseconds = 30'000;

SERVICE_STATUS_HANDLE serviceStatusHandle = nullptr;
SERVICE_STATUS serviceStatus {};
HANDLE stopEvent = nullptr;

void ReportServiceStatus(DWORD currentState, DWORD win32ExitCode = ERROR_SUCCESS)
{
    serviceStatus.dwCurrentState = currentState;
    serviceStatus.dwWin32ExitCode = win32ExitCode;
    serviceStatus.dwControlsAccepted =
        currentState == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    serviceStatus.dwCheckPoint =
        currentState == SERVICE_START_PENDING || currentState == SERVICE_STOP_PENDING ? 1 : 0;
    serviceStatus.dwWaitHint =
        currentState == SERVICE_START_PENDING || currentState == SERVICE_STOP_PENDING ? 10'000 : 0;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD, void*, void*)
{
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN)
    {
        ReportServiceStatus(SERVICE_STOP_PENDING);
        SetEvent(stopEvent);
    }
    return NO_ERROR;
}

class LocalSecurityDescriptor final
{
  public:
    LocalSecurityDescriptor() = default;

    ~LocalSecurityDescriptor()
    {
        if (value_ != nullptr)
        {
            LocalFree(value_);
        }
    }

    LocalSecurityDescriptor(const LocalSecurityDescriptor&) = delete;
    LocalSecurityDescriptor& operator=(const LocalSecurityDescriptor&) = delete;

    [[nodiscard]] PSECURITY_DESCRIPTOR* address() noexcept { return &value_; }
    [[nodiscard]] PSECURITY_DESCRIPTOR get() const noexcept { return value_; }

  private:
    PSECURITY_DESCRIPTOR value_ = nullptr;
};

class LocalString final
{
  public:
    ~LocalString()
    {
        if (value_ != nullptr)
        {
            LocalFree(value_);
        }
    }

    [[nodiscard]] PWSTR* address() noexcept { return &value_; }
    [[nodiscard]] PWSTR get() const noexcept { return value_; }

  private:
    PWSTR value_ = nullptr;
};

struct BrokerLaunchPolicy
{
    explicit BrokerLaunchPolicy(std::wstring_view credentialDirectory)
        : credentialStore(credentialDirectory), registration(credentialDirectory)
    {
    }

    std::vector<BYTE> authorizedCallerSid;
    launch_as::broker::CredentialStore credentialStore;
    launch_as::broker::RegistrationService registration;
    std::wstring controlPipeDacl;
};

[[nodiscard]] std::wstring AuditCallerSid(const launch_as::broker::BrokerCallerIdentity& caller)
{
    if (caller.userSid.empty() || !IsValidSid(const_cast<BYTE*>(caller.userSid.data())))
    {
        return L"unknown";
    }
    LocalString value;
    if (!ConvertSidToStringSidW(const_cast<BYTE*>(caller.userSid.data()), value.address()))
    {
        return L"unknown";
    }
    return value.get();
}

void AuditRequest(launch_as::broker::BrokerAuditEvent event, WORD type,
    const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller, DWORD result, DWORD processId = 0)
{
    const std::vector<std::wstring> fields {
        L"requestId=" + request.requestId,
        L"operation=" + std::wstring(launch_as::broker::RequestOperationName(request.operation)),
        L"account=" + request.profileId,
        L"callerSid=" + AuditCallerSid(caller),
        L"callerSession=" + std::to_wstring(caller.sessionId),
        L"result=" + std::wstring(result == ERROR_SUCCESS ? L"allowed" : L"rejected"),
        L"processId=" + std::to_wstring(processId),
        L"win32Error=" + std::to_wstring(result),
    };
    static_cast<void>(launch_as::broker::WriteBrokerAuditEvent(type, event, fields));
}

[[nodiscard]] DWORD BuildControlPipeDacl(
    const std::vector<BYTE>& authorizedCallerSid, std::wstring& dacl)
{
    dacl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    if (!authorizedCallerSid.empty())
    {
        LocalString callerSid;
        if (!ConvertSidToStringSidW(
                const_cast<BYTE*>(authorizedCallerSid.data()), callerSid.address()))
        {
            const DWORD sidError = GetLastError();
            return sidError;
        }
        dacl += L"(A;;GRGW;;;";
        dacl += callerSid.get();
        dacl += L")";
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] launch_as::UniqueHandle CreateControlPipe(std::wstring_view dacl)
{
    const std::wstring daclText(dacl);
    LocalSecurityDescriptor securityDescriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            daclText.c_str(), SDDL_REVISION_1, securityDescriptor.address(), nullptr))
    {
        return {};
    }
    SECURITY_ATTRIBUTES securityAttributes {};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = securityDescriptor.get();

    HANDLE pipe = CreateNamedPipeW(launch_as::broker::ControlPipeName.data(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        0,
        &securityAttributes);
    return launch_as::UniqueHandle(pipe);
}

DWORD ConfigureProfile(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller, std::vector<std::wstring>& accounts);
DWORD LaunchProfile(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller,
    launch_as::broker::BrokerChildProcess& child);

void RunPipeServer(BrokerLaunchPolicy& launchPolicy)
{
    while (WaitForSingleObject(stopEvent, 0) == WAIT_TIMEOUT)
    {
        launch_as::UniqueHandle pipe(CreateControlPipe(launchPolicy.controlPipeDacl));
        if (!pipe)
        {
            return;
        }

        launch_as::UniqueHandle connectEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!connectEvent)
        {
            return;
        }
        OVERLAPPED overlapped {};
        overlapped.hEvent = connectEvent.get();
        const BOOL connected = ConnectNamedPipe(pipe.get(), &overlapped);
        const DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (!connected && connectError == ERROR_IO_PENDING)
        {
            const std::array waitHandles {stopEvent, connectEvent.get()};
            const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(waitHandles.size()),
                waitHandles.data(),
                FALSE,
                BrokerIdleTimeoutMilliseconds);
            if (wait == WAIT_TIMEOUT)
            {
                CancelIoEx(pipe.get(), &overlapped);
                DWORD ignored = 0;
                static_cast<void>(GetOverlappedResult(pipe.get(), &overlapped, &ignored, TRUE));
                return;
            }
            if (wait != WAIT_OBJECT_0 + 1)
            {
                CancelIoEx(pipe.get(), &overlapped);
                DWORD ignored = 0;
                static_cast<void>(GetOverlappedResult(pipe.get(), &overlapped, &ignored, TRUE));
                continue;
            }
            DWORD ignored = 0;
            if (!GetOverlappedResult(pipe.get(), &overlapped, &ignored, FALSE))
            {
                continue;
            }
        }
        else if (!connected && connectError != ERROR_PIPE_CONNECTED)
        {
            continue;
        }
        launch_as::broker::ServeControlPipeRequest(
            pipe.get(), stopEvent, ConfigureProfile, &launchPolicy, LaunchProfile, &launchPolicy);
        DisconnectNamedPipe(pipe.get());
    }
}

DWORD ConfigureProfile(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller, std::vector<std::wstring>& accounts)
{
    const auto complete = [&](DWORD result)
    {
        AuditRequest(result == ERROR_SUCCESS
                         ? launch_as::broker::BrokerAuditEvent::ConfigurationChanged
                         : launch_as::broker::BrokerAuditEvent::ConfigurationRejected,
            result == ERROR_SUCCESS ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE,
            request,
            caller,
            result);
        return result;
    };
    auto* policy = static_cast<BrokerLaunchPolicy*>(context);
    if (policy == nullptr ||
        !launch_as::broker::IsAuthorizedCaller(policy->authorizedCallerSid, caller.userSid))
    {
        return complete(ERROR_ACCESS_DENIED);
    }
    if (request.operation == launch_as::broker::RequestOperation::List)
    {
        return complete(policy->registration.List(accounts));
    }
    if (request.operation != launch_as::broker::RequestOperation::Test && !request.confirmed)
    {
        return complete(ERROR_CANCELLED);
    }
    if (!caller.isElevated)
    {
        return complete(ERROR_ELEVATION_REQUIRED);
    }
    if (request.operation == launch_as::broker::RequestOperation::Enroll)
    {
        return complete(policy->registration.Enroll(request.profileId));
    }
    if (request.operation == launch_as::broker::RequestOperation::Rotate)
    {
        return complete(policy->registration.Rotate(request.profileId));
    }
    if (request.operation == launch_as::broker::RequestOperation::Test)
    {
        return complete(policy->registration.Test(request.profileId));
    }
    if (request.operation == launch_as::broker::RequestOperation::Unenroll)
    {
        return complete(policy->registration.Unenroll(request.profileId));
    }
    return complete(request.operation == launch_as::broker::RequestOperation::UnenrollAll
                        ? policy->registration.UnenrollAll()
                        : ERROR_INVALID_PARAMETER);
}

DWORD LaunchProfile(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller,
    launch_as::broker::BrokerChildProcess& child)
{
    const auto complete = [&](DWORD result)
    {
        AuditRequest(result == ERROR_SUCCESS ? launch_as::broker::BrokerAuditEvent::LaunchAllowed
                                             : launch_as::broker::BrokerAuditEvent::LaunchRejected,
            result == ERROR_SUCCESS ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE,
            request,
            caller,
            result,
            child.processId());
        return result;
    };
    const auto* policy = static_cast<const BrokerLaunchPolicy*>(context);
    if (policy == nullptr ||
        request.operation != launch_as::broker::RequestOperation::ConsoleLaunch ||
        !launch_as::broker::IsAuthorizedCaller(policy->authorizedCallerSid, caller.userSid))
    {
        return complete(ERROR_ACCESS_DENIED);
    }
    launch_as::broker::BrokerLogonToken token;
    const DWORD logonError = launch_as::broker::LogOnBrokerProfile(
        request.profileId, request.profileId, policy->credentialStore, token);
    if (logonError != ERROR_SUCCESS)
    {
        return complete(logonError);
    }
    if (request.arguments.empty())
    {
        return complete(ERROR_INVALID_PARAMETER);
    }
    std::vector<std::wstring> conhostArguments {
        L"--internal-pseudoconsole-host",
        L"--size",
        std::to_wstring(request.console.columns),
        std::to_wstring(request.console.rows),
        L"--pipe-in",
        request.console.pipeIn,
        L"--pipe-out",
        request.console.pipeOut,
        L"--pipe-resize",
        request.console.pipeResize,
        L"--",
    };
    conhostArguments.insert(
        conhostArguments.end(), request.arguments.begin(), request.arguments.end());
    const DWORD launchError = launch_as::broker::LaunchBrokerConsoleHost(
        token.get(), request.profileId, conhostArguments, request.workingDirectory, child);
    if (launchError != ERROR_SUCCESS)
    {
        return complete(launchError);
    }
    const DWORD validationError =
        launch_as::broker::ValidateChildLogonSid(child.process(), caller.logonSid);
    if (validationError != ERROR_SUCCESS)
    {
        child.Reset();
        return complete(validationError);
    }
    const DWORD resumeError = child.Resume();
    if (resumeError != ERROR_SUCCESS)
    {
        child.Reset();
    }
    return complete(resumeError);
}

void WINAPI ServiceMain(DWORD, wchar_t**)
{
    serviceStatusHandle =
        RegisterServiceCtrlHandlerExW(ServiceName, ServiceControlHandler, nullptr);
    if (serviceStatusHandle == nullptr)
    {
        return;
    }

    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ReportServiceStatus(SERVICE_START_PENDING);
    launch_as::UniqueHandle ownedStopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!ownedStopEvent)
    {
        const DWORD eventError = GetLastError();
        ReportServiceStatus(SERVICE_STOPPED, eventError);
        return;
    }
    stopEvent = ownedStopEvent.get();
    std::wstring credentialDirectory;
    const DWORD credentialDirectoryError =
        launch_as::broker::GetBrokerCredentialDirectory(credentialDirectory);
    if (credentialDirectoryError != ERROR_SUCCESS)
    {
        ReportServiceStatus(SERVICE_STOPPED, credentialDirectoryError);
        return;
    }
    std::wstring dataDirectory;
    const DWORD dataDirectoryError = launch_as::broker::GetBrokerDataDirectory(dataDirectory);
    if (dataDirectoryError != ERROR_SUCCESS)
    {
        ReportServiceStatus(SERVICE_STOPPED, dataDirectoryError);
        return;
    }
    BrokerLaunchPolicy launchPolicy(credentialDirectory);
    static_cast<void>(launch_as::broker::LoadAuthorizedCallerSid(
        launch_as::broker::GetAuthorizedCallerPolicyPath(dataDirectory),
        launchPolicy.authorizedCallerSid));
    const DWORD daclError =
        BuildControlPipeDacl(launchPolicy.authorizedCallerSid, launchPolicy.controlPipeDacl);
    if (daclError != ERROR_SUCCESS)
    {
        ReportServiceStatus(SERVICE_STOPPED, daclError);
        return;
    }
    ReportServiceStatus(SERVICE_RUNNING);
    RunPipeServer(launchPolicy);
    ReportServiceStatus(SERVICE_STOPPED);
}

} // namespace

int RunBrokerService()
{
    SERVICE_TABLE_ENTRYW serviceTable[] {
        {const_cast<wchar_t*>(ServiceName), ServiceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(serviceTable))
    {
        const DWORD dispatcherError = GetLastError();
        std::wcerr << L"launch-as-broker must be started by the Service Control Manager: "
                   << launch_as::FormatWindowsError(dispatcherError) << L"\n";
        return static_cast<int>(dispatcherError);
    }
    return 0;
}
