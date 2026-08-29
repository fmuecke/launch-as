// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAdminCli.h"

#include "BrokerAccountProvisioner.h"
#include "BrokerControlPipe.h"
#include "BrokerProtocol.h"
#include "BrokerServiceInstaller.h"
#include "LicenseHeader.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <objbase.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{
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

[[nodiscard]] DWORD ForwardManagementRequest(launch_as::broker::RequestOperation operation,
    std::wstring_view accountName, bool confirmed, std::vector<std::wstring>* accounts)
{
    const std::optional<std::wstring> requestId = CreateRequestId();
    if (!requestId)
    {
        return ERROR_GEN_FAILURE;
    }
    const std::string request =
        launch_as::broker::BuildManagementRequest(operation, *requestId, accountName, confirmed);

    HANDLE rawPipe = nullptr;
    const DWORD openError = launch_as::broker::OpenBrokerControlPipe(rawPipe);
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
    if (operation == launch_as::broker::RequestOperation::List)
    {
        return accounts != nullptr &&
                       launch_as::broker::ParseListResponse(response, *requestId, *accounts)
                   ? ERROR_SUCCESS
                   : ERROR_INVALID_DATA;
    }
    if (response == launch_as::broker::BuildSuccessResponse(
                        *requestId, launch_as::broker::RequestOperationSuccessReason(operation)))
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
    launch_as::PrintLicenseHeader();
    std::wcerr << LR"usage(Usage:
  launch-as-admin install                         Stop active sessions, then create or update the broker service.
  launch-as-admin uninstall [--force]             Stop and remove the service; accounts are retained.
  launch-as-admin enroll <account> [--force]      Create an account or take over an existing one; changes its password.
  launch-as-admin list                            Show owned accounts.
  launch-as-admin unenroll <account> [--force]    End its sessions, forget it, and disable the account.
  launch-as-admin unenroll-all [--force]          Unenroll every owned account.

install, uninstall, enroll, unenroll, and unenroll-all require elevation.
uninstall, enroll, unenroll, and unenroll-all require consent; --force skips the prompt.

)usage";
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
        const DWORD listError = ForwardManagementRequest(
            launch_as::broker::RequestOperation::List, L"", false, &accounts);
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
        const std::wstring_view command(arguments[1]);
        const bool isEnrollment = command == L"enroll";
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
                ? L"Enroll " + std::wstring(accountName) + L" and create or take over its account"
                : L"Unenroll " + std::wstring(accountName) + L" and disable the account";
        if (!forced && !ConfirmDestructiveOperation(action))
        {
            return ERROR_CANCELLED;
        }
        const launch_as::broker::RequestOperation operation =
            isEnrollment ? launch_as::broker::RequestOperation::Enroll
                         : launch_as::broker::RequestOperation::Unenroll;
        if (!isEnrollment)
        {
            const DWORD stopError = launch_as::broker::StopBrokerService();
            if (stopError != ERROR_SUCCESS)
            {
                std::wcerr << L"Could not stop broker sessions before unenrollment: "
                           << launch_as::FormatWindowsError(stopError) << L"\n";
                return static_cast<int>(stopError);
            }
        }
        const DWORD configurationError =
            ForwardManagementRequest(operation, accountName, true, nullptr);
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
        const DWORD stopError = launch_as::broker::StopBrokerService();
        if (stopError != ERROR_SUCCESS)
        {
            std::wcerr << L"Could not stop broker sessions before unenrollment: "
                       << launch_as::FormatWindowsError(stopError) << L"\n";
            return static_cast<int>(stopError);
        }
        const DWORD dropError = ForwardManagementRequest(
            launch_as::broker::RequestOperation::UnenrollAll, L"", true, nullptr);
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

int RunBrokerAdminCli(int argumentCount, wchar_t* arguments[])
{
    return RunConfigurationCommand(argumentCount, arguments);
}
