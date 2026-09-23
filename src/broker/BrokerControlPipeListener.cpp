// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerControlPipeListener.h"

#include "BrokerAudit.h"
#include "BrokerControlPipe.h"
#include "BrokerPipeServer.h"
#include "BrokerProtocol.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <memory>
#include <sddl.h>
#include <thread>
#include <utility>

namespace launch_as::broker
{
namespace
{

constexpr DWORD BrokerIdleTimeoutMilliseconds = 30'000;
constexpr DWORD WorkerSlotWaitTimeoutMilliseconds = BrokerIdleTimeoutMilliseconds;
constexpr DWORD MaximumConcurrentPipeWorkers = 8;
static_assert(MaximumConcurrentPipeWorkers + 1 <= MAXIMUM_WAIT_OBJECTS);
static_assert(ControlPipeClientAccess == 0x0012008B);

using LocalSecurityDescriptor = LocalAllocation<PSECURITY_DESCRIPTOR>;
using LocalString = LocalAllocation<PWSTR>;

struct BrokerPipeWorker
{
    UniqueHandle completedEvent;
    std::thread thread;
};

[[nodiscard]] UniqueHandle CreateControlPipe(
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
    HANDLE pipe = CreateNamedPipeW(ControlPipeName.data(),
        openMode,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        MaximumConcurrentPipeWorkers,
        static_cast<DWORD>(MaximumMessageBytes),
        static_cast<DWORD>(MaximumMessageBytes),
        0,
        &securityAttributes);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        return {};
    }
    return UniqueHandle(pipe);
}

DWORD ConfigureProfile(void* context, const BrokerRequest& request,
    const BrokerCallerIdentity& caller, std::vector<std::wstring>& accounts)
{
    auto* application = static_cast<BrokerApplication*>(context);
    return application == nullptr ? ERROR_INVALID_PARAMETER
                                  : application->Configure(request, caller, accounts);
}

DWORD LaunchProfile(void* context, const BrokerRequest& request, const BrokerCallerIdentity& caller,
    BrokerChildProcess& child)
{
    auto* application = static_cast<BrokerApplication*>(context);
    return application == nullptr ? ERROR_INVALID_PARAMETER
                                  : application->Launch(request, caller, child);
}

void FinishProfileSession(void* context, const BrokerRequest& request, bool processTreeExited)
{
    auto* application = static_cast<BrokerApplication*>(context);
    if (application != nullptr)
    {
        static_cast<void>(application->FinishSession(request, processTreeExited));
    }
}

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

[[nodiscard]] bool DispatchPipeWorker(UniqueHandle pipe, HANDLE stopEvent,
    BrokerApplication& application, std::vector<std::unique_ptr<BrokerPipeWorker>>& workers)
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
            [ownedPipe = std::move(pipe), stopEvent, &application, workerState]() mutable
            {
                ServeControlPipeRequest(ownedPipe.get(),
                    stopEvent,
                    ConfigureProfile,
                    &application,
                    LaunchProfile,
                    &application,
                    FinishProfileSession,
                    &application);
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
    HANDLE stopEvent, std::vector<std::unique_ptr<BrokerPipeWorker>>& workers)
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

} // namespace

DWORD BuildBrokerControlPipeDacl(const std::vector<BYTE>& authorizedCallerSid, std::wstring& dacl)
{
    dacl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    if (!authorizedCallerSid.empty())
    {
        LocalString callerSid;
        if (!ConvertSidToStringSidW(
                const_cast<BYTE*>(authorizedCallerSid.data()), callerSid.address()))
        {
            return GetLastError();
        }
        dacl += L"(A;;0x0012008B;;;";
        dacl += callerSid.get();
        dacl += L")";
    }
    return ERROR_SUCCESS;
}

DWORD RunBrokerControlPipeListener(
    HANDLE stopEvent, BrokerApplication& application, std::wstring_view controlPipeDacl)
{
    std::vector<std::unique_ptr<BrokerPipeWorker>> workers;
    bool firstInstance = true;
    DWORD serviceExitCode = ERROR_SUCCESS;
    while (WaitForSingleObject(stopEvent, 0) == WAIT_TIMEOUT)
    {
        ReapCompletedWorkers(workers);
        const WorkerSlotWaitResult workerSlotResult =
            WaitForAvailableWorkerSlot(stopEvent, workers);
        if (workerSlotResult == WorkerSlotWaitResult::Stopped)
        {
            break;
        }
        DWORD createError = ERROR_SUCCESS;
        UniqueHandle pipe(CreateControlPipe(controlPipeDacl, firstInstance, createError));
        if (!pipe)
        {
            if (firstInstance)
            {
                const std::vector<std::wstring> fields {
                    L"reason=first_pipe_instance_unavailable",
                    L"win32Error=" + std::to_wstring(createError),
                };
                static_cast<void>(WriteBrokerAuditEvent(
                    EVENTLOG_ERROR_TYPE, BrokerAuditEvent::ControlPipeCreationFailed, fields));
                serviceExitCode = createError;
            }
            SetEvent(stopEvent);
            break;
        }
        firstInstance = false;

        UniqueHandle connectEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
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
        if (!DispatchPipeWorker(std::move(pipe), stopEvent, application, workers))
        {
            SetEvent(stopEvent);
            break;
        }
    }
    JoinWorkers(workers);
    return serviceExitCode;
}

} // namespace launch_as::broker
