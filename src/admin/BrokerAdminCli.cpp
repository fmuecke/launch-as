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
#include <string>
#include <string_view>
#include <vector>

namespace
{
[[nodiscard]] DWORD ForwardManagementRequest(launch_as::broker::RequestOperation operation,
    std::wstring_view accountName, bool force, std::vector<std::wstring>* accounts)
{
    std::wstring requestId;
    if (!launch_as::CreateGuidString(requestId))
    {
        return ERROR_GEN_FAILURE;
    }
    const std::string request =
        launch_as::broker::BuildManagementRequest(operation, requestId, accountName, force);

    HANDLE rawPipe = nullptr;
    const DWORD openError = launch_as::broker::OpenBrokerControlPipe(rawPipe);
    launch_as::UniqueHandle pipe(rawPipe);
    if (!pipe)
    {
        return openError;
    }

    const DWORD writeError = launch_as::broker::WritePipeMessage(pipe.get(), request);
    if (writeError != ERROR_SUCCESS)
    {
        return writeError;
    }
    std::string response;
    const DWORD readError = launch_as::broker::ReadPipeMessage(pipe.get(), response);
    if (readError != ERROR_SUCCESS)
    {
        return readError;
    }
    if (operation == launch_as::broker::RequestOperation::List)
    {
        return accounts != nullptr &&
                       launch_as::broker::ParseListResponse(response, requestId, *accounts)
                   ? ERROR_SUCCESS
                   : ERROR_INVALID_DATA;
    }
    if (response == launch_as::broker::BuildSuccessResponse(
                        requestId, launch_as::broker::RequestOperationSuccessReason(operation)))
    {
        return ERROR_SUCCESS;
    }
    DWORD brokerError = ERROR_INVALID_DATA;
    if (launch_as::broker::ParseErrorResponse(response, requestId, brokerError))
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
    uninstall [--force]             Stop and remove the service and installed executables; accounts are retained.
    create <account>                Create a new account owned by launch-as; it fails if the name exists.
    create <account> --takeover [--force]    Take over an account and make it launch-as-owned.
    list                            Show owned accounts.
    forget <account> [--force]      Deregister it; leave the Windows account unchanged.
    delete <account> [--force]      Delete an owned account after its sessions end.

install, uninstall, create, forget, and delete require elevation.
uninstall, create <account> --takeover, forget, and delete require consent; --force skips the prompt.

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
            std::wcout << L"Uninstalled the launch-as-broker service and installed executables. "
                          L"Registered accounts were retained.\n";
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
            else if (argument == L"--takeover" && !takeOverExisting)
            {
                takeOverExisting = true;
            }
            else if (accountName.empty() && !argument.starts_with(L"--"))
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
            ForwardManagementRequest(operation, accountName, forced, nullptr);
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
                false,
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
