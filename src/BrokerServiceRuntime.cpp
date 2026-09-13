// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerServiceRuntime.h"

#include "BrokerAudit.h"
#include "BrokerCallerPolicy.h"
#include "BrokerControlPipe.h"
#include "BrokerDataDirectory.h"
#include "BrokerLogonToken.h"
#include "BrokerPassword.h"
#include "BrokerPipeServer.h"
#include "BrokerProcessLauncher.h"
#include "BrokerProtocol.h"
#include "BrokerRegistration.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <cwchar>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sddl.h>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace
{

constexpr wchar_t ServiceName[] = L"launch-as-broker";
constexpr DWORD BrokerIdleTimeoutMilliseconds = 30'000;
constexpr DWORD WorkerSlotWaitTimeoutMilliseconds = BrokerIdleTimeoutMilliseconds;
constexpr std::size_t MaximumConcurrentSessions = 4;
constexpr std::size_t MaximumConcurrentSessionsPerAccount = 2;
constexpr DWORD MaximumConcurrentPipeWorkers = 8;
static_assert(MaximumConcurrentPipeWorkers + 1 <= MAXIMUM_WAIT_OBJECTS);
static_assert(launch_as::broker::ControlPipeClientAccess == 0x0012008B);

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

using LocalSecurityDescriptor = launch_as::LocalAllocation<PSECURITY_DESCRIPTOR>;
using LocalString = launch_as::LocalAllocation<PWSTR>;

struct BrokerLaunchPolicy
{
    explicit BrokerLaunchPolicy(std::wstring_view enrollmentDirectory)
        : registration(enrollmentDirectory)
    {
    }

    std::vector<BYTE> authorizedCallerSid;
    launch_as::broker::RegistrationService registration;
    std::wstring controlPipeDacl;
    std::mutex launchGate;

    [[nodiscard]] bool TryReserveSession(std::wstring_view accountName)
    {
        std::lock_guard lock(sessionMutex);
        if (sessionCount >= MaximumConcurrentSessions)
        {
            return false;
        }
        const auto existing = sessionsByAccount.find(std::wstring(accountName));
        if (existing != sessionsByAccount.end() &&
            existing->second >= MaximumConcurrentSessionsPerAccount)
        {
            return false;
        }
        ++sessionsByAccount[std::wstring(accountName)];
        ++sessionCount;
        return true;
    }

    void ReleaseSession(std::wstring_view accountName)
    {
        std::lock_guard lock(sessionMutex);
        const auto existing = sessionsByAccount.find(std::wstring(accountName));
        if (existing == sessionsByAccount.end() || existing->second == 0)
        {
            return;
        }
        --existing->second;
        --sessionCount;
        if (existing->second == 0)
        {
            sessionsByAccount.erase(existing);
        }
    }

    [[nodiscard]] bool HasActiveSession(std::wstring_view accountName)
    {
        std::lock_guard lock(sessionMutex);
        const auto existing = sessionsByAccount.find(std::wstring(accountName));
        return existing != sessionsByAccount.end() && existing->second != 0;
    }

  private:
    struct AccountNameLess
    {
        [[nodiscard]] bool operator()(
            const std::wstring& left, const std::wstring& right) const noexcept
        {
            return _wcsicmp(left.c_str(), right.c_str()) < 0;
        }
    };

    std::mutex sessionMutex;
    std::map<std::wstring, std::size_t, AccountNameLess> sessionsByAccount;
    std::size_t sessionCount = 0;
};

struct BrokerPipeWorker
{
    launch_as::UniqueHandle completedEvent;
    std::thread thread;
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

[[nodiscard]] std::wstring AuditProfileId(std::wstring_view fieldName, std::wstring_view profileId)
{
    const std::wstring_view value =
        launch_as::broker::IsValidProfileId(profileId) ? profileId : L"<invalid>";
    return std::wstring(fieldName) + L"=" + std::wstring(value);
}

void AuditRequest(launch_as::broker::BrokerAuditEvent event, WORD type,
    const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller, DWORD result, DWORD processId = 0)
{
    const std::vector<std::wstring> fields {
        L"requestId=" + request.requestId,
        L"operation=" + std::wstring(launch_as::broker::RequestOperationName(request.operation)),
        AuditProfileId(L"account", request.profileId),
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
        dacl += L"(A;;0x0012008B;;;";
        dacl += callerSid.get();
        dacl += L")";
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] launch_as::UniqueHandle CreateControlPipe(
    std::wstring_view dacl, bool firstInstance, DWORD& error)
{
    error = ERROR_SUCCESS;
    const std::wstring daclText(dacl);
    LocalSecurityDescriptor securityDescriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            daclText.c_str(), SDDL_REVISION_1, securityDescriptor.address(), nullptr))
    {
        error = GetLastError();
        return {};
    }
    SECURITY_ATTRIBUTES securityAttributes {};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = securityDescriptor.get();

    const DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                           (firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
    HANDLE pipe = CreateNamedPipeW(launch_as::broker::ControlPipeName.data(),
        openMode,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        MaximumConcurrentPipeWorkers,
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        static_cast<DWORD>(launch_as::broker::MaximumMessageBytes),
        0,
        &securityAttributes);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        return {};
    }
    return launch_as::UniqueHandle(pipe);
}

DWORD ConfigureProfile(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller, std::vector<std::wstring>& accounts);
DWORD LaunchProfile(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller,
    launch_as::broker::BrokerChildProcess& child);
void FinishProfileSession(
    void* context, const launch_as::broker::BrokerRequest& request, bool processTreeExited);

void ReapCompletedWorkers(std::vector<std::unique_ptr<BrokerPipeWorker>>& workers)
{
    for (auto worker = workers.begin(); worker != workers.end();)
    {
        if (WaitForSingleObject((*worker)->completedEvent.get(), 0) != WAIT_OBJECT_0)
        {
            ++worker;
            continue;
        }
        if ((*worker)->thread.joinable())
        {
            (*worker)->thread.join();
        }
        worker = workers.erase(worker);
    }
}

void JoinWorkers(std::vector<std::unique_ptr<BrokerPipeWorker>>& workers)
{
    for (const auto& worker : workers)
    {
        if (worker->thread.joinable())
        {
            worker->thread.join();
        }
    }
    workers.clear();
}

[[nodiscard]] bool DispatchPipeWorker(launch_as::UniqueHandle pipe,
    BrokerLaunchPolicy& launchPolicy, std::vector<std::unique_ptr<BrokerPipeWorker>>& workers)
{
    auto worker = std::make_unique<BrokerPipeWorker>();
    worker->completedEvent.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!worker->completedEvent)
    {
        return false;
    }
    try
    {
        workers.push_back(std::move(worker));
    }
    catch (...)
    {
        return false;
    }

    BrokerPipeWorker* workerState = workers.back().get();
    try
    {
        workerState->thread = std::thread(
            [ownedPipe = std::move(pipe), &launchPolicy, workerState]() mutable
            {
                launch_as::broker::ServeControlPipeRequest(ownedPipe.get(),
                    stopEvent,
                    ConfigureProfile,
                    &launchPolicy,
                    LaunchProfile,
                    &launchPolicy,
                    FinishProfileSession,
                    &launchPolicy);
                DisconnectNamedPipe(ownedPipe.get());
                SetEvent(workerState->completedEvent.get());
            });
    }
    catch (...)
    {
        workers.pop_back();
        return false;
    }
    return true;
}

enum class WorkerSlotWaitResult
{
    Available,
    Stopped,
};

[[nodiscard]] WorkerSlotWaitResult WaitForAvailableWorkerSlot(
    std::vector<std::unique_ptr<BrokerPipeWorker>>& workers)
{
    while (workers.size() >= MaximumConcurrentPipeWorkers)
    {
        std::vector<HANDLE> waitHandles;
        waitHandles.reserve(workers.size() + 1);
        waitHandles.push_back(stopEvent);
        for (const auto& worker : workers)
        {
            waitHandles.push_back(worker->completedEvent.get());
        }
        const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(waitHandles.size()),
            waitHandles.data(),
            FALSE,
            WorkerSlotWaitTimeoutMilliseconds);
        if (wait == WAIT_TIMEOUT)
        {
            ReapCompletedWorkers(workers);
            if (workers.size() < MaximumConcurrentPipeWorkers)
            {
                return WorkerSlotWaitResult::Available;
            }
            SetEvent(stopEvent);
            return WorkerSlotWaitResult::Stopped;
        }
        if (wait == WAIT_OBJECT_0)
        {
            return WorkerSlotWaitResult::Stopped;
        }
        if (wait < WAIT_OBJECT_0 + 1 ||
            wait >= WAIT_OBJECT_0 + static_cast<DWORD>(waitHandles.size()))
        {
            SetEvent(stopEvent);
            return WorkerSlotWaitResult::Stopped;
        }
        ReapCompletedWorkers(workers);
    }
    return WorkerSlotWaitResult::Available;
}

[[nodiscard]] DWORD RunPipeServer(BrokerLaunchPolicy& launchPolicy)
{
    std::vector<std::unique_ptr<BrokerPipeWorker>> workers;
    bool firstInstance = true;
    DWORD serviceExitCode = ERROR_SUCCESS;
    while (WaitForSingleObject(stopEvent, 0) == WAIT_TIMEOUT)
    {
        ReapCompletedWorkers(workers);
        const WorkerSlotWaitResult workerSlotResult = WaitForAvailableWorkerSlot(workers);
        if (workerSlotResult == WorkerSlotWaitResult::Stopped)
        {
            break;
        }
        DWORD createError = ERROR_SUCCESS;
        launch_as::UniqueHandle pipe(
            CreateControlPipe(launchPolicy.controlPipeDacl, firstInstance, createError));
        if (!pipe)
        {
            if (firstInstance)
            {
                const std::vector<std::wstring> fields {
                    L"reason=first_pipe_instance_unavailable",
                    L"win32Error=" + std::to_wstring(createError),
                };
                static_cast<void>(launch_as::broker::WriteBrokerAuditEvent(EVENTLOG_ERROR_TYPE,
                    launch_as::broker::BrokerAuditEvent::ControlPipeCreationFailed,
                    fields));
                serviceExitCode = createError;
            }
            SetEvent(stopEvent);
            break;
        }
        firstInstance = false;

        launch_as::UniqueHandle connectEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!connectEvent)
        {
            SetEvent(stopEvent);
            break;
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
                ReapCompletedWorkers(workers);
                if (workers.empty())
                {
                    return serviceExitCode;
                }
                continue;
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
        if (!DispatchPipeWorker(std::move(pipe), launchPolicy, workers))
        {
            SetEvent(stopEvent);
            break;
        }
    }
    JoinWorkers(workers);
    return serviceExitCode;
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
    std::lock_guard launchLock(policy->launchGate);
    if (request.operation == launch_as::broker::RequestOperation::List)
    {
        return complete(policy->registration.List(accounts));
    }
    if (!request.confirmed)
    {
        return complete(ERROR_CANCELLED);
    }
    if (!caller.isElevated)
    {
        return complete(ERROR_ELEVATION_REQUIRED);
    }
    if (request.operation == launch_as::broker::RequestOperation::Create)
    {
        return complete(policy->registration.Create(request.profileId));
    }
    if (request.operation == launch_as::broker::RequestOperation::TakeOver)
    {
        return complete(policy->registration.TakeOver(request.profileId, request.force));
    }
    if (request.operation == launch_as::broker::RequestOperation::Forget)
    {
        return complete(policy->registration.Forget(request.profileId));
    }
    if (request.operation == launch_as::broker::RequestOperation::Delete)
    {
        return complete(policy->HasActiveSession(request.profileId)
                            ? ERROR_BUSY
                            : policy->registration.Delete(request.profileId));
    }
    return complete(ERROR_INVALID_PARAMETER);
}

DWORD LaunchProfile(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller,
    launch_as::broker::BrokerChildProcess& child)
{
    auto* policy = static_cast<BrokerLaunchPolicy*>(context);
    bool sessionReserved = false;
    const auto complete = [&](DWORD result)
    {
        if (result != ERROR_SUCCESS && sessionReserved && policy != nullptr)
        {
            policy->ReleaseSession(request.profileId);
            sessionReserved = false;
        }
        AuditRequest(result == ERROR_SUCCESS ? launch_as::broker::BrokerAuditEvent::LaunchAllowed
                                             : launch_as::broker::BrokerAuditEvent::LaunchRejected,
            result == ERROR_SUCCESS ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE,
            request,
            caller,
            result,
            child.processId());
        return result;
    };
    if (policy == nullptr ||
        request.operation != launch_as::broker::RequestOperation::ConsoleLaunch ||
        !launch_as::broker::IsAuthorizedCaller(policy->authorizedCallerSid, caller.userSid))
    {
        return complete(ERROR_ACCESS_DENIED);
    }
    if (request.arguments.empty())
    {
        return complete(ERROR_INVALID_PARAMETER);
    }
    if (!policy->TryReserveSession(request.profileId))
    {
        return complete(ERROR_BUSY);
    }
    sessionReserved = true;
    std::lock_guard launchLock(policy->launchGate);
    launch_as::broker::SecurePassword password;
    const DWORD passwordError = launch_as::broker::GenerateBrokerPassword(password);
    if (passwordError != ERROR_SUCCESS)
    {
        return complete(passwordError);
    }
    const DWORD resetError = policy->registration.ResetPassword(request.profileId, password);
    if (resetError != ERROR_SUCCESS)
    {
        password.Clear();
        return complete(resetError);
    }
    launch_as::broker::BrokerLogonToken token;
    const DWORD logonError =
        launch_as::broker::LogOnBrokerAccount(request.profileId, password, token);
    password.Clear();
    if (logonError != ERROR_SUCCESS)
    {
        return complete(logonError);
    }
    std::vector<std::wstring> conhostArguments {
        L"--internal-pseudoconsole-host",
        L"--size",
        std::to_wstring(request.console.columns),
        std::to_wstring(request.console.rows),
    };
    if (request.console.inheritCursor)
    {
        conhostArguments.emplace_back(L"--inherit-cursor");
    }
    conhostArguments.insert(conhostArguments.end(),
        {L"--pipe-in",
            request.console.pipeIn,
            L"--pipe-out",
            request.console.pipeOut,
            L"--pipe-resize",
            request.console.pipeResize,
            L"--"});
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
        static_cast<void>(child.TerminateAndWaitForExit());
        return complete(validationError);
    }
    const DWORD resumeError = child.Resume();
    if (resumeError != ERROR_SUCCESS)
    {
        static_cast<void>(child.TerminateAndWaitForExit());
    }
    return complete(resumeError);
}

void FinishProfileSession(
    void* context, const launch_as::broker::BrokerRequest& request, bool processTreeExited)
{
    auto* policy = static_cast<BrokerLaunchPolicy*>(context);
    if (policy != nullptr)
    {
        policy->ReleaseSession(request.profileId);
    }
    if (!processTreeExited)
    {
        const std::array<std::wstring, 3> fields {
            L"operation=launch",
            AuditProfileId(L"profileId", request.profileId),
            L"reason=process_tree_not_confirmed",
        };
        static_cast<void>(launch_as::broker::WriteBrokerAuditEvent(EVENTLOG_ERROR_TYPE,
            launch_as::broker::BrokerAuditEvent::SessionTeardownFailed,
            fields));
    }
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
    std::wstring dataDirectory;
    const DWORD dataDirectoryError = launch_as::broker::GetBrokerDataDirectory(dataDirectory);
    if (dataDirectoryError != ERROR_SUCCESS)
    {
        ReportServiceStatus(SERVICE_STOPPED, dataDirectoryError);
        return;
    }
    std::wstring enrollmentDirectory;
    const DWORD enrollmentDirectoryError =
        launch_as::broker::GetBrokerEnrollmentDirectory(enrollmentDirectory);
    if (enrollmentDirectoryError != ERROR_SUCCESS)
    {
        ReportServiceStatus(SERVICE_STOPPED, enrollmentDirectoryError);
        return;
    }
    BrokerLaunchPolicy launchPolicy(enrollmentDirectory);
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
    const DWORD pipeServerExitCode = RunPipeServer(launchPolicy);
    ReportServiceStatus(SERVICE_STOPPED, pipeServerExitCode);
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
