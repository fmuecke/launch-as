// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LaunchProcess.h"

#include "BrokerControlClient.h"
#include "InteractiveDesktopLeaseCoordinator.h"
#include "TerminalBridge.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <filesystem>
#include <iostream>
#include <objbase.h>
#include <optional>
#include <sddl.h>
#include <thread>
#include <vector>

namespace launch_as
{
std::optional<AccountIdentity> ResolveLocalAccount(const std::wstring& username)
{
    const std::wstring qualifiedUsername = L".\\" + username;
    std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> computerName {};
    DWORD computerNameCharacters = static_cast<DWORD>(computerName.size());
    if (!GetComputerNameW(computerName.data(), &computerNameCharacters))
    {
        const DWORD nameError = GetLastError();
        std::wcerr << L"Could not resolve the local computer name: "
                   << FormatWindowsError(nameError) << L"\n";
        return std::nullopt;
    }
    const std::wstring lookupName =
        std::wstring(computerName.data(), computerNameCharacters) + L"\\" + username;

    DWORD sidBytes = 0;
    DWORD domainCharacters = 0;
    SID_NAME_USE sidType {};
    LookupAccountNameW(
        nullptr, lookupName.c_str(), nullptr, &sidBytes, nullptr, &domainCharacters, &sidType);
    const DWORD lookupError = GetLastError();
    if (lookupError != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0 || domainCharacters == 0)
    {
        std::wcerr << L"Could not resolve local account '" << qualifiedUsername << L"': "
                   << FormatWindowsError(lookupError) << L"\n";
        return std::nullopt;
    }

    std::vector<BYTE> sid(sidBytes);
    std::vector<wchar_t> domain(domainCharacters);
    if (!LookupAccountNameW(nullptr,
            lookupName.c_str(),
            sid.data(),
            &sidBytes,
            domain.data(),
            &domainCharacters,
            &sidType))
    {
        const DWORD lookupAccountError = GetLastError();
        std::wcerr << L"Could not resolve local account '" << qualifiedUsername << L"': "
                   << FormatWindowsError(lookupAccountError) << L"\n";
        return std::nullopt;
    }
    if (sidType != SidTypeUser || !IsValidSid(sid.data()))
    {
        std::wcerr << L"Account '" << qualifiedUsername
                   << L"' does not resolve to a valid user SID.\n";
        return std::nullopt;
    }

    wchar_t* rawSid = nullptr;
    if (!ConvertSidToStringSidW(sid.data(), &rawSid))
    {
        const DWORD convertError = GetLastError();
        std::wcerr << L"Could not format SID for '" << qualifiedUsername << L"': "
                   << FormatWindowsError(convertError) << L"\n";
        return std::nullopt;
    }
    LocalAllocation<void*> sidBuffer(rawSid);
    return AccountIdentity {
        .username = username, .qualifiedUsername = qualifiedUsername, .sid = rawSid
    };
}

bool ValidateRunPaths(const Options& options)
{
    std::error_code error;
    if (!options.executablePath.is_absolute() ||
        !std::filesystem::is_regular_file(options.executablePath, error))
    {
        std::wcerr << L"Executable is not an existing absolute file: "
                   << options.executablePath.c_str() << L"\n";
        return false;
    }
    if (!options.workingDirectory.empty())
    {
        error.clear();
        if (!options.workingDirectory.is_absolute() ||
            !std::filesystem::is_directory(options.workingDirectory, error))
        {
            std::wcerr << L"Working directory is not an existing absolute directory: "
                       << options.workingDirectory.c_str() << L"\n";
            return false;
        }
    }
    return true;
}

ExitCode RunBrokerConsole(const AccountIdentity& account, const Options& options)
{
    TerminalBridge terminalBridge;
    TerminalPipeNames pipeNames;
    std::wstring terminalError;
    if (!terminalBridge.InitializeForBroker(account.sid, pipeNames, terminalError))
    {
        std::wcerr << terminalError << L"\n";
        return ExitFailure;
    }

    std::error_code currentDirectoryError;
    const std::filesystem::path workingDirectory =
        options.workingDirectory.empty() ? std::filesystem::current_path(currentDirectoryError)
                                         : options.workingDirectory;
    if (currentDirectoryError)
    {
        std::wcerr << L"Could not resolve the current working directory: "
                   << currentDirectoryError.message().c_str() << L"\n";
        return ExitFailure;
    }
    std::vector<std::wstring> arguments;
    arguments.reserve(options.processArguments.size() + 1);
    arguments.emplace_back(options.executablePath.native());
    arguments.insert(
        arguments.end(), options.processArguments.begin(), options.processArguments.end());

    BrokerControlConnection connection;
    DWORD processId = 0;
    const DWORD launchError = LaunchBrokerConsole(account.username,
        arguments,
        workingDirectory.native(),
        pipeNames,
        terminalBridge.terminalSize(),
        terminalBridge.supportsCursorInheritance(),
        connection,
        processId);
    if (launchError != ERROR_SUCCESS)
    {
        if (launchError == ERROR_PIPE_BUSY)
        {
            std::wcerr << L"The broker control pipe stayed busy while connecting.\n";
            return ExitFailure;
        }
        if (launchError == ERROR_BUSY)
        {
            std::wcerr << L"The broker session limit has been reached. Wait for a session to "
                          L"finish before starting another.\n";
            return ExitFailure;
        }
        std::wcerr << L"Could not launch the enrolled account through the broker: "
                   << FormatWindowsError(launchError) << L"\n";
        return ExitFailure;
    }
    if (!terminalBridge.ConnectBrokerChild(terminalError))
    {
        connection.Reset();
        std::wcerr << terminalError << L"\n";
        return ExitFailure;
    }
    if (!terminalBridge.Start(terminalError))
    {
        connection.Reset();
        std::wcerr << terminalError << L"\n";
        return ExitFailure;
    }
    std::wcout << L"Starting broker terminal session as " << account.qualifiedUsername
               << L" (host PID " << processId
               << L"). Output in this pane is controlled by that session until it exits.\n";
    std::wcout.flush();
    DWORD waitError = ERROR_SUCCESS;
    const DWORD waitResult = terminalBridge.WaitForOutput(waitError);
    terminalBridge.Stop();
    if (waitResult != WAIT_OBJECT_0)
    {
        connection.Reset();
        const DWORD reportedError = waitResult == WAIT_FAILED ? waitError : ERROR_GEN_FAILURE;
        std::wcerr << L"Could not wait for the broker terminal output: "
                   << FormatWindowsError(reportedError) << L"\n";
        return ExitFailure;
    }
    DWORD childExitCode = 0;
    std::wstring exitDiagnostics;
    const DWORD exitError = WaitForBrokerConsoleExit(connection, childExitCode, exitDiagnostics);
    connection.Reset();
    if (exitError != ERROR_SUCCESS)
    {
        if (!exitDiagnostics.empty())
        {
            std::wcerr << exitDiagnostics << L"\n";
        }
        else
        {
            std::wcerr << L"Could not read the broker terminal exit code: "
                       << FormatWindowsError(exitError) << L"\n";
        }
        return ExitFailure;
    }
    std::wcout << L"Broker terminal session ended.\n";
    return childExitCode;
}

ExitCode RunBrokerInteractive(const AccountIdentity& account, const Options& options)
{
    std::error_code currentDirectoryError;
    const std::filesystem::path workingDirectory =
        options.workingDirectory.empty() ? std::filesystem::current_path(currentDirectoryError)
                                         : options.workingDirectory;
    if (currentDirectoryError)
    {
        std::wcerr << L"Could not resolve the current working directory: "
                   << currentDirectoryError.message().c_str() << L"\n";
        return ExitFailure;
    }
    std::vector<std::wstring> arguments;
    arguments.reserve(options.processArguments.size() + 1);
    arguments.emplace_back(options.executablePath.native());
    arguments.insert(
        arguments.end(), options.processArguments.begin(), options.processArguments.end());

    GUID identifier {};
    if (FAILED(CoCreateGuid(&identifier)))
    {
        std::wcerr << L"Could not create the interactive lease identifier.\n";
        return ExitFailure;
    }
    wchar_t nonceBuffer[39] {};
    if (StringFromGUID2(identifier, nonceBuffer, static_cast<int>(std::size(nonceBuffer))) != 39)
    {
        std::wcerr << L"Could not format the interactive lease identifier.\n";
        return ExitFailure;
    }
    const std::wstring nonce(nonceBuffer + 1, 36);
    std::wstring pipeSuffix;
    pipeSuffix.reserve(nonce.size());
    for (const wchar_t character : nonce)
    {
        if (character != L'-')
        {
            pipeSuffix.push_back(character);
        }
    }
    const std::wstring pipeName = L"\\\\.\\pipe\\launch-as-interactive-" + pipeSuffix;
    HANDLE rawLeasePipe = nullptr;
    const DWORD pipeError = CreateInteractiveDesktopLeasePipe(pipeName, rawLeasePipe);
    if (pipeError != ERROR_SUCCESS)
    {
        std::wcerr << L"Could not create the interactive desktop lease pipe: "
                   << FormatWindowsError(pipeError) << L"\n";
        return ExitFailure;
    }
    UniqueHandle leasePipe(rawLeasePipe);
    UniqueHandle launchCompleted(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!launchCompleted)
    {
        const DWORD eventError = GetLastError();
        std::wcerr << L"Could not create the interactive launch event: "
                   << FormatWindowsError(eventError) << L"\n";
        return ExitFailure;
    }

    BrokerControlConnection connection;
    DWORD processId = 0;
    DWORD launchError = ERROR_IO_PENDING;
    std::thread launchWorker(
        [&]
        {
            launchError = LaunchBrokerInteractive(account.username,
                arguments,
                workingDirectory.native(),
                pipeName,
                nonce,
                connection,
                processId);
            SetEvent(launchCompleted.get());
        });
    const DWORD coordinatorError =
        CoordinateInteractiveDesktopLease(leasePipe.get(), nonce, launchCompleted.get());
    launchWorker.join();
    connection.Reset();
    DisconnectNamedPipe(leasePipe.get());

    if (launchError != ERROR_SUCCESS)
    {
        if (launchError == ERROR_PIPE_BUSY)
        {
            std::wcerr << L"The broker control pipe stayed busy while connecting.\n";
        }
        else if (launchError == ERROR_BUSY)
        {
            std::wcerr << L"The broker session limit has been reached. Wait for a session to "
                          L"finish before starting another.\n";
        }
        else
        {
            std::wcerr << L"Could not launch the enrolled account in interactive mode: "
                       << FormatWindowsError(launchError) << L"\n";
        }
        return ExitFailure;
    }
    if (coordinatorError != ERROR_SUCCESS)
    {
        std::wcerr << L"The interactive desktop lease failed: "
                   << FormatWindowsError(coordinatorError) << L"\n";
        return ExitFailure;
    }
    std::wcout << L"Interactive broker session as " << account.qualifiedUsername << L" (PID "
               << processId << L") ended and its desktop lease was released.\n";
    return ExitSuccess;
}

} // namespace launch_as
