// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LaunchProcess.h"

#include "BrokerControlClient.h"
#include "TerminalBridge.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <filesystem>
#include <iostream>
#include <optional>
#include <sddl.h>
#include <vector>

namespace launch_as
{
namespace
{

class LocalBuffer final
{
  public:
    explicit LocalBuffer(void* value) noexcept : value_(value) {}

    ~LocalBuffer()
    {
        if (value_ != nullptr)
        {
            LocalFree(value_);
        }
    }

    LocalBuffer(const LocalBuffer&) = delete;
    LocalBuffer& operator=(const LocalBuffer&) = delete;

  private:
    void* value_;
};

} // namespace

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
    LocalBuffer sidBuffer(rawSid);
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
        connection,
        processId);
    if (launchError != ERROR_SUCCESS)
    {
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
    std::wcout << L"Starting broker terminal session as " << account.qualifiedUsername
               << L" (host PID " << processId
               << L"). Output in this pane is controlled by that session until it exits.\n";
    std::wcout.flush();
    if (!terminalBridge.Start(terminalError))
    {
        connection.Reset();
        std::wcerr << terminalError << L"\n";
        return ExitFailure;
    }
    const DWORD waitResult = terminalBridge.WaitForOutput();
    terminalBridge.Stop();
    if (waitResult != WAIT_OBJECT_0)
    {
        connection.Reset();
        const DWORD waitError = waitResult == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
        std::wcerr << L"Could not wait for the broker terminal output: "
                   << FormatWindowsError(waitError) << L"\n";
        return ExitFailure;
    }
    DWORD childExitCode = 0;
    const DWORD exitError = WaitForBrokerConsoleExit(connection, childExitCode);
    connection.Reset();
    if (exitError != ERROR_SUCCESS)
    {
        std::wcerr << L"Could not read the broker terminal exit code: "
                   << FormatWindowsError(exitError) << L"\n";
        return ExitFailure;
    }
    std::wcout << L"Broker terminal session ended.\n";
    return childExitCode;
}

} // namespace launch_as
