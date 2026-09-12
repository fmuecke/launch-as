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
    std::wstring_view accountName, bool confirmed, bool force, std::vector<std::wstring>* accounts)
{
    const std::optional<std::wstring> requestId = CreateRequestId();
    if (!requestId)
    {
        return ERROR_GEN_FAILURE;
    }
    const std::string request = launch_as::broker::BuildManagementRequest(
        operation, *requestId, accountName, confirmed, force);

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
    std::wcout << description << L". Type YES to continue: ";
    std::wstring answer;
    return std::getline(std::wcin, answer) && answer == L"YES";
}

void PrintUsage()
{
    launch_as::PrintLicenseHeader();
    std::wcerr << LR"usage(Usage:  launch-as-admin <COMMAND> <PARAMS...>

  Commands are:
    install                         Stop active sessions, then create or update the broker service.
    uninstall [--force]             Stop and remove the service; accounts are retained.
    create <account>                Create a new account owned by launch-as; it fails if the name exists.
    create --takeover <account>  [--force]    Take over an existing account and make it launch-as-owned.
    list                            Show owned accounts.
    forget <account> [--force]      Deregister it; leave the Windows account unchanged.
    delete <account> [--force]      Delete an owned account after its sessions end.

install, uninstall, create, forget, and delete require elevation.
uninstall, create --takeover, forget, and delete require consent; --force skips the prompt.

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
            launch_as::broker::RequestOperation::List, L"", false, false, &accounts);
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
    if (argumentCount >= 2 && std::wstring_view(arguments[1]) == L"create")
    {
        bool forced = false;
        bool takeOverExisting = false;
        std::wstring accountName;
        for (int index = 2; index < argumentCount; ++index)
        {
            const std::wstring_view argument(arguments[index]);
            if (argument == L"--force" && !forced)
            {
                forced = true;
            }
            else if (argument == L"--takeover" && !takeOverExisting && accountName.empty() &&
                     index + 1 < argumentCount)
            {
                takeOverExisting = true;
                accountName = arguments[++index];
            }
            else if (!takeOverExisting && accountName.empty() && !argument.starts_with(L"--"))
            {
                accountName = argument;
            }
            else
            {
                PrintUsage();
                return ERROR_INVALID_PARAMETER;
            }
        }
        if (accountName.empty())
        {
            PrintUsage();
            return ERROR_INVALID_PARAMETER;
        }
        if (forced && !takeOverExisting)
        {
            PrintUsage();
            return ERROR_INVALID_PARAMETER;
        }
        if (!launch_as::broker::IsValidBrokerAccountName(accountName))
        {
            std::wcerr << L"Invalid account name: " << accountName << L"\n";
            PrintUsage();
            return ERROR_INVALID_PARAMETER;
        }
        const DWORD validationError =
            launch_as::broker::ValidateBrokerAccountForRegistration(accountName);
        if (validationError == ERROR_MEMBER_IN_GROUP)
        {
            std::wcerr << L"Broker takeover refused for " << accountName
                       << L": the account is a member of the local Administrators group.\n";
            return static_cast<int>(validationError);
        }
        if (validationError != ERROR_SUCCESS)
        {
            std::wcerr << L"Broker account preflight failed: "
                       << launch_as::FormatWindowsError(validationError) << L"\n";
            return static_cast<int>(validationError);
        }
        const std::wstring action =
            L"Take over " + accountName + L", reset its password, and make it launch-as-owned";
        if (takeOverExisting && !forced && !ConfirmDestructiveOperation(action))
        {
            return ERROR_CANCELLED;
        }
        const launch_as::broker::RequestOperation operation =
            takeOverExisting ? launch_as::broker::RequestOperation::TakeOver
                             : launch_as::broker::RequestOperation::Create;
        const DWORD configurationError =
            ForwardManagementRequest(operation, accountName, true, forced, nullptr);
        if (configurationError == ERROR_SUCCESS)
        {
            std::wcout << (takeOverExisting ? L"Took over " : L"Created ") << accountName << L".\n";
        }
        else if (configurationError == ERROR_ACCOUNT_DISABLED && !forced)
        {
            std::wcerr << L"Broker takeover refused because " << accountName
                       << L" is disabled. Re-run with --force to re-enable and take it over.\n";
        }
        else
        {
            std::wcerr << L"Broker " << (takeOverExisting ? L"takeover" : L"create") << L" failed: "
                       << launch_as::FormatWindowsError(configurationError) << L"\n";
        }
        return static_cast<int>(configurationError);
    }
    if ((argumentCount == 3 || argumentCount == 4) &&
        (std::wstring_view(arguments[1]) == L"forget" ||
            std::wstring_view(arguments[1]) == L"delete") &&
        (argumentCount == 3 || std::wstring_view(arguments[3]) == L"--force"))
    {
        const std::wstring_view accountName(arguments[2]);
        if (!launch_as::broker::IsValidBrokerAccountName(accountName))
        {
            std::wcerr << L"Invalid account name: " << accountName << L"\n";
            PrintUsage();
            return ERROR_INVALID_PARAMETER;
        }
        const bool forced = argumentCount == 4;
        const bool deleting = std::wstring_view(arguments[1]) == L"delete";
        const std::wstring action = deleting
                                        ? L"Delete launch-as account " + std::wstring(accountName)
                                        : L"Forget launch-as account " + std::wstring(accountName) +
                                              L" without changing the Windows account";
        if (!forced && !ConfirmDestructiveOperation(action))
        {
            return ERROR_CANCELLED;
        }
        const DWORD operationError =
            ForwardManagementRequest(deleting ? launch_as::broker::RequestOperation::Delete
                                              : launch_as::broker::RequestOperation::Forget,
                accountName,
                true,
                forced,
                nullptr);
        if (operationError == ERROR_SUCCESS)
        {
            std::wcout << (deleting ? L"Deleted " : L"Forgot ") << accountName << L".\n";
        }
        else
        {
            std::wcerr << L"Broker " << (deleting ? L"delete" : L"forget") << L" failed: "
                       << launch_as::FormatWindowsError(operationError) << L"\n";
        }
        return static_cast<int>(operationError);
    }
    PrintUsage();
    return ERROR_INVALID_PARAMETER;
}

} // namespace

int RunBrokerAdminCli(int argumentCount, wchar_t* arguments[])
{
    return RunConfigurationCommand(argumentCount, arguments);
}
