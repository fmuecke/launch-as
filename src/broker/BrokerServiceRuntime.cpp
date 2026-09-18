// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerServiceRuntime.h"

#include "BrokerApplication.h"
#include "BrokerCallerPolicy.h"
#include "BrokerControlPipeListener.h"
#include "BrokerDataDirectory.h"
#include "Win32Support.h"

#include <Windows.h>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace
{

constexpr wchar_t ServiceName[] = L"launch-as-broker";

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

    std::vector<BYTE> authorizedCallerSid;
    static_cast<void>(launch_as::broker::LoadAuthorizedCallerSid(
        launch_as::broker::GetAuthorizedCallerPolicyPath(dataDirectory), authorizedCallerSid));
    std::wstring controlPipeDacl;
    const DWORD daclError =
        launch_as::broker::BuildBrokerControlPipeDacl(authorizedCallerSid, controlPipeDacl);
    if (daclError != ERROR_SUCCESS)
    {
        ReportServiceStatus(SERVICE_STOPPED, daclError);
        return;
    }

    launch_as::broker::BrokerApplication application(
        enrollmentDirectory, std::move(authorizedCallerSid));
    ReportServiceStatus(SERVICE_RUNNING);
    const DWORD pipeServerExitCode =
        launch_as::broker::RunBrokerControlPipeListener(stopEvent, application, controlPipeDacl);
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
