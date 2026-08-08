// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAccountProvisioner.h"
#include "BrokerCallerPolicy.h"
#include "BrokerDataDirectory.h"
#include "BrokerLogonToken.h"
#include "BrokerPipeServer.h"
#include "BrokerProcessLauncher.h"
#include "BrokerProtocol.h"
#include "BrokerRegistration.h"
#include "BrokerServiceInstaller.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <objbase.h>
#include <optional>
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

class ServiceHandle final
{
  public:
    explicit ServiceHandle(SC_HANDLE value = nullptr) noexcept : value_(value) {}
    ~ServiceHandle()
    {
        if (value_ != nullptr)
        {
            CloseServiceHandle(value_);
        }
    }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }

  private:
    SC_HANDLE value_;
};

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
        : credentialStore(credentialDirectory)
    {
    }

    std::vector<BYTE> authorizedCallerSid;
    launch_as::broker::CredentialStore credentialStore;
    launch_as::broker::RegistrationService* registration = nullptr;
};

[[nodiscard]] launch_as::UniqueHandle CreateControlPipe(
    const std::vector<BYTE>& authorizedCallerSid)
{
    std::wstring dacl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    if (!authorizedCallerSid.empty())
    {
        LocalString callerSid;
        if (!ConvertSidToStringSidW(
                const_cast<BYTE*>(authorizedCallerSid.data()), callerSid.address()))
        {
            return {};
        }
        dacl += L"(A;;GRGW;;;";
        dacl += callerSid.get();
        dacl += L")";
    }
    LocalSecurityDescriptor securityDescriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            dacl.c_str(), SDDL_REVISION_1, securityDescriptor.address(), nullptr))
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
        launch_as::UniqueHandle pipe(CreateControlPipe(launchPolicy.authorizedCallerSid));
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
    auto* policy = static_cast<BrokerLaunchPolicy*>(context);
    if (policy == nullptr || policy->registration == nullptr ||
        !launch_as::broker::IsAuthorizedCaller(policy->authorizedCallerSid, caller.userSid))
    {
        return ERROR_ACCESS_DENIED;
    }
    if (request.operation == launch_as::broker::RequestOperation::List)
    {
        return policy->registration->List(accounts);
    }
    if (!request.confirmed)
    {
        return ERROR_CANCELLED;
    }
    if (!caller.isElevated)
    {
        return ERROR_ELEVATION_REQUIRED;
    }
    if (request.operation == launch_as::broker::RequestOperation::Enroll)
    {
        return policy->registration->Register(request.profileId);
    }
    if (request.operation == launch_as::broker::RequestOperation::Unenroll)
    {
        return policy->registration->Drop(request.profileId);
    }
    return request.operation == launch_as::broker::RequestOperation::UnenrollAll
               ? policy->registration->DropAll()
               : ERROR_INVALID_PARAMETER;
}

DWORD LaunchProfile(void* context, const launch_as::broker::BrokerRequest& request,
    const launch_as::broker::BrokerCallerIdentity& caller,
    launch_as::broker::BrokerChildProcess& child)
{
    const auto* policy = static_cast<const BrokerLaunchPolicy*>(context);
    if (policy == nullptr ||
        request.operation != launch_as::broker::RequestOperation::ConsoleLaunch ||
        !launch_as::broker::IsAuthorizedCaller(policy->authorizedCallerSid, caller.userSid))
    {
        return ERROR_ACCESS_DENIED;
    }
    launch_as::broker::BrokerLogonToken token;
    const DWORD logonError = launch_as::broker::LogOnBrokerProfile(
        request.profileId, request.profileId, policy->credentialStore, token);
    if (logonError != ERROR_SUCCESS)
    {
        return logonError;
    }
    const DWORD launchError = launch_as::broker::LaunchFixedBrokerProbe(token.get(), child);
    if (launchError != ERROR_SUCCESS)
    {
        return launchError;
    }
    const DWORD validationError =
        launch_as::broker::ValidateChildLogonSid(child.process(), caller.logonSid);
    if (validationError != ERROR_SUCCESS)
    {
        child.Reset();
        return validationError;
    }
    return ERROR_SUCCESS;
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
    launch_as::broker::RegistrationService registration(credentialDirectory);
    std::wstring dataDirectory;
    const DWORD dataDirectoryError = launch_as::broker::GetBrokerDataDirectory(dataDirectory);
    if (dataDirectoryError != ERROR_SUCCESS)
    {
        ReportServiceStatus(SERVICE_STOPPED, dataDirectoryError);
        return;
    }
    BrokerLaunchPolicy launchPolicy(credentialDirectory);
    launchPolicy.registration = &registration;
    static_cast<void>(launch_as::broker::LoadAuthorizedCallerSid(
        launch_as::broker::GetAuthorizedCallerPolicyPath(dataDirectory),
        launchPolicy.authorizedCallerSid));
    ReportServiceStatus(SERVICE_RUNNING);
    RunPipeServer(launchPolicy);
    ReportServiceStatus(SERVICE_STOPPED);
}

[[nodiscard]] std::optional<std::wstring> CreateRequestId()
{
    GUID identifier {};
    if (FAILED(CoCreateGuid(&identifier)))
    {
        return std::nullopt;
    }
    wchar_t formatted[39] {};
    if (StringFromGUID2(identifier, formatted, static_cast<int>(std::size(formatted))) != 39)
    {
        return std::nullopt;
    }
    return std::wstring(formatted + 1, 36);
}

[[nodiscard]] DWORD StartBrokerService()
{
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager)
    {
        const DWORD managerError = GetLastError();
        return managerError;
    }
    ServiceHandle service(OpenServiceW(manager.get(), ServiceName, SERVICE_START));
    if (!service)
    {
        const DWORD serviceError = GetLastError();
        return serviceError;
    }
    if (StartServiceW(service.get(), 0, nullptr))
    {
        return ERROR_SUCCESS;
    }
    const DWORD startError = GetLastError();
    return startError == ERROR_SERVICE_ALREADY_RUNNING ? ERROR_SUCCESS : startError;
}

[[nodiscard]] DWORD WaitForControlPipe(DWORD timeoutMilliseconds)
{
    const ULONGLONG deadline = GetTickCount64() + timeoutMilliseconds;
    DWORD waitError = ERROR_FILE_NOT_FOUND;
    do
    {
        if (WaitNamedPipeW(launch_as::broker::ControlPipeName.data(), 100))
        {
            return ERROR_SUCCESS;
        }
        waitError = GetLastError();
        if (waitError != ERROR_FILE_NOT_FOUND && waitError != ERROR_PIPE_BUSY)
        {
            return waitError;
        }
        Sleep(50);
    } while (GetTickCount64() < deadline);
    return waitError;
}

enum class ConfigurationCommand
{
    Enroll,
    List,
    Unenroll,
    UnenrollAll
};

[[nodiscard]] DWORD ForwardConfigurationRequest(ConfigurationCommand command,
    std::wstring_view accountName, bool confirmed, std::vector<std::wstring>* accounts)
{
    const std::optional<std::wstring> requestId = CreateRequestId();
    if (!requestId)
    {
        return ERROR_GEN_FAILURE;
    }
    std::string requestIdUtf8;
    requestIdUtf8.reserve(requestId->size());
    for (const wchar_t character : *requestId)
    {
        requestIdUtf8.push_back(static_cast<char>(character));
    }
    const std::string operation = command == ConfigurationCommand::Enroll     ? "enroll"
                                  : command == ConfigurationCommand::List     ? "list"
                                  : command == ConfigurationCommand::Unenroll ? "unenroll"
                                                                              : "unenroll-all";
    std::string request = "{\"version\":1,\"requestId\":\"" + requestIdUtf8 +
                          "\",\"operation\":\"" + operation + "\"";
    if (command != ConfigurationCommand::List && command != ConfigurationCommand::UnenrollAll)
    {
        std::string accountNameUtf8;
        const int accountCharacters = WideCharToMultiByte(CP_UTF8,
            WC_ERR_INVALID_CHARS,
            accountName.data(),
            static_cast<int>(accountName.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (accountCharacters <= 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        accountNameUtf8.resize(static_cast<std::size_t>(accountCharacters));
        if (WideCharToMultiByte(CP_UTF8,
                WC_ERR_INVALID_CHARS,
                accountName.data(),
                static_cast<int>(accountName.size()),
                accountNameUtf8.data(),
                accountCharacters,
                nullptr,
                nullptr) != accountCharacters)
        {
            return ERROR_INVALID_PARAMETER;
        }
        request += ",\"profileId\":\"" + accountNameUtf8 + "\"";
    }
    if (command != ConfigurationCommand::List)
    {
        request += confirmed ? ",\"confirmed\":true" : ",\"confirmed\":false";
    }
    request += "}";

    if (!WaitNamedPipeW(launch_as::broker::ControlPipeName.data(), 0))
    {
        const DWORD waitError = GetLastError();
        if (waitError != ERROR_FILE_NOT_FOUND)
        {
            return waitError;
        }
        const DWORD startError = StartBrokerService();
        if (startError != ERROR_SUCCESS)
        {
            return startError;
        }
        const DWORD readyError = WaitForControlPipe(5'000);
        if (readyError != ERROR_SUCCESS)
        {
            return readyError;
        }
    }
    HANDLE rawPipe = CreateFileW(launch_as::broker::ControlPipeName.data(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    const DWORD openError = rawPipe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    launch_as::UniqueHandle pipe(rawPipe);
    if (!pipe)
    {
        return openError;
    }

    DWORD bytesWritten = 0;
    const BOOL wroteRequest = WriteFile(
        pipe.get(), request.data(), static_cast<DWORD>(request.size()), &bytesWritten, nullptr);
    const DWORD writeError = wroteRequest ? ERROR_SUCCESS : GetLastError();
    if (!wroteRequest || bytesWritten != request.size())
    {
        return wroteRequest ? ERROR_WRITE_FAULT : writeError;
    }

    std::array<char, launch_as::broker::MaximumMessageBytes> responseBuffer {};
    DWORD bytesRead = 0;
    const BOOL readResponse = ReadFile(pipe.get(),
        responseBuffer.data(),
        static_cast<DWORD>(responseBuffer.size()),
        &bytesRead,
        nullptr);
    const DWORD readError = readResponse ? ERROR_SUCCESS : GetLastError();
    if (!readResponse)
    {
        return readError;
    }
    const std::string response(responseBuffer.data(), bytesRead);
    if (command == ConfigurationCommand::List)
    {
        return accounts != nullptr &&
                       launch_as::broker::ParseListResponse(response, *requestId, *accounts)
                   ? ERROR_SUCCESS
                   : ERROR_INVALID_DATA;
    }
    const char* successReason = command == ConfigurationCommand::Enroll ? "enrolled" : "unenrolled";
    if (response == launch_as::broker::BuildSuccessResponse(*requestId, successReason))
    {
        return ERROR_SUCCESS;
    }
    DWORD brokerError = ERROR_INVALID_DATA;
    if (launch_as::broker::ParseErrorResponse(response, *requestId, brokerError))
    {
        return brokerError;
    }
    return ERROR_INVALID_DATA;
}

[[nodiscard]] bool ConfirmDestructiveOperation(std::wstring_view description)
{
    DWORD consoleMode = 0;
    if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &consoleMode))
    {
        std::wcerr << L"Refusing to " << description
                   << L" without an interactive console. Re-run with --force to continue.\n";
        return false;
    }
    std::wcout << description << L". Type yes to continue: ";
    std::wstring answer;
    return std::getline(std::wcin, answer) && answer == L"yes";
}

void PrintUsage()
{
    std::wcerr
        << L"Usage:\n"
        << L"  launch-as-broker install                        Create or update the broker "
           L"service.\n"
        << L"  launch-as-broker uninstall [--force]            Stop and remove the service; "
           L"accounts "
           L"are retained.\n"
        << L"  launch-as-broker enroll <account> [--force]     Create an account or add an "
           L"existing. This will change its password.\n"
        << L"  launch-as-broker list                           Show owned accounts.\n"
        << L"  launch-as-broker unenroll <account> [--force]   Erase its credential and disable "
           L"the "
           L"account.\n"
        << L"  launch-as-broker unenroll-all [--force]         Unenroll every owned account.\n\n"
        << L"install and uninstall require elevation. uninstall, enroll, unenroll, and "
           L"unenroll-all "
           L"require "
           L"consent; --force skips the prompt.\n";
}

int RunConfigurationCommand(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount == 2 && std::wstring_view(arguments[1]) == L"install")
    {
        const DWORD installationError = launch_as::broker::InstallBrokerService();
        if (installationError == ERROR_SUCCESS)
        {
            std::wcout << L"Installed the launch-as-broker service.\n";
        }
        else
        {
            std::wcerr << L"Broker installation failed: "
                       << launch_as::FormatWindowsError(installationError) << L"\n";
        }
        return static_cast<int>(installationError);
    }
    if ((argumentCount == 2 || argumentCount == 3) &&
        std::wstring_view(arguments[1]) == L"uninstall" &&
        (argumentCount == 2 || std::wstring_view(arguments[2]) == L"--force"))
    {
        if (argumentCount == 2 && !ConfirmDestructiveOperation(L"Uninstall the broker service"))
        {
            return ERROR_CANCELLED;
        }
        const DWORD uninstallError = launch_as::broker::UninstallBrokerService();
        if (uninstallError == ERROR_SUCCESS)
        {
            std::wcout << L"Uninstalled the launch-as-broker service. Registered accounts were "
                          L"retained.\n";
        }
        else
        {
            std::wcerr << L"Broker uninstallation failed: "
                       << launch_as::FormatWindowsError(uninstallError) << L"\n";
        }
        return static_cast<int>(uninstallError);
    }
    if (argumentCount == 2 && std::wstring_view(arguments[1]) == L"list")
    {
        std::vector<std::wstring> accounts;
        const DWORD listError =
            ForwardConfigurationRequest(ConfigurationCommand::List, L"", false, &accounts);
        if (listError == ERROR_SUCCESS)
        {
            if (accounts.empty())
            {
                std::wcout << L"No broker accounts are registered.\n";
            }
            else
            {
                for (const std::wstring& account : accounts)
                {
                    std::wcout << account << L"\n";
                }
            }
        }
        else
        {
            std::wcerr << L"Broker list failed: " << launch_as::FormatWindowsError(listError)
                       << L"\n";
        }
        return static_cast<int>(listError);
    }
    if ((argumentCount == 3 || argumentCount == 4) &&
        (std::wstring_view(arguments[1]) == L"enroll" ||
            std::wstring_view(arguments[1]) == L"unenroll") &&
        (argumentCount == 3 || std::wstring_view(arguments[3]) == L"--force"))
    {
        const std::wstring_view accountName(arguments[2]);
        if (!launch_as::broker::IsValidBrokerAccountName(accountName))
        {
            std::wcerr << L"Invalid account name: " << accountName << L"\n";
            PrintUsage();
            return ERROR_INVALID_PARAMETER;
        }
        const bool isEnrollment = std::wstring_view(arguments[1]) == L"enroll";
        if (isEnrollment)
        {
            const DWORD validationError =
                launch_as::broker::ValidateBrokerAccountForRegistration(accountName);
            if (validationError == ERROR_MEMBER_IN_GROUP)
            {
                std::wcerr << L"Broker enrollment refused for " << accountName
                           << L": the account is a member of the local Administrators group.\n";
                return static_cast<int>(validationError);
            }
            if (validationError != ERROR_SUCCESS)
            {
                std::wcerr << L"Broker enrollment preflight failed: "
                           << launch_as::FormatWindowsError(validationError) << L"\n";
                return static_cast<int>(validationError);
            }
        }
        const bool forced = argumentCount == 4;
        const std::wstring action =
            isEnrollment
                ? L"Enroll " + std::wstring(accountName) + L" and create or rotate its password"
                : L"Unenroll " + std::wstring(accountName) + L" and disable the account";
        if (!forced && !ConfirmDestructiveOperation(action))
        {
            return ERROR_CANCELLED;
        }
        const DWORD configurationError = ForwardConfigurationRequest(
            isEnrollment ? ConfigurationCommand::Enroll : ConfigurationCommand::Unenroll,
            accountName,
            true,
            nullptr);
        if (configurationError == ERROR_SUCCESS)
        {
            std::wcout << (isEnrollment ? L"Enrolled " : L"Unenrolled ") << accountName << L".\n";
        }
        else if (isEnrollment && configurationError == ERROR_MEMBER_IN_GROUP)
        {
            std::wcerr << L"Broker enrollment refused for " << accountName
                       << L": the account is a member of the local Administrators group.\n";
        }
        else
        {
            std::wcerr << L"Broker " << (isEnrollment ? L"enrollment" : L"unenrollment")
                       << L" failed: " << launch_as::FormatWindowsError(configurationError)
                       << L"\n";
        }
        return static_cast<int>(configurationError);
    }
    if ((argumentCount == 2 || argumentCount == 3) &&
        std::wstring_view(arguments[1]) == L"unenroll-all" &&
        (argumentCount == 2 || std::wstring_view(arguments[2]) == L"--force"))
    {
        if (argumentCount == 2 &&
            !ConfirmDestructiveOperation(L"Unenroll every enrolled broker account"))
        {
            return ERROR_CANCELLED;
        }
        const DWORD dropError =
            ForwardConfigurationRequest(ConfigurationCommand::UnenrollAll, L"", true, nullptr);
        if (dropError == ERROR_SUCCESS)
        {
            std::wcout << L"Unenrolled all broker accounts.\n";
        }
        else
        {
            std::wcerr << L"Broker unenrollment failed: "
                       << launch_as::FormatWindowsError(dropError) << L"\n";
        }
        return static_cast<int>(dropError);
    }
    PrintUsage();
    return ERROR_INVALID_PARAMETER;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount > 1)
    {
        return RunConfigurationCommand(argumentCount, arguments);
    }

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
