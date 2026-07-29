// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LaunchProcess.h"

#include "CredentialInput.h"
#include "Credentials.h"
#include "PseudoConsoleHost.h"
#include "TerminalBridge.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <optional>
#include <sddl.h>
#include <string>
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

[[nodiscard]] bool ProcessHasAccountSid(HANDLE process, const AccountIdentity& account)
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &rawToken))
    {
        const DWORD tokenError = GetLastError();
        std::wcerr << L"Could not open the child process token: " << FormatWindowsError(tokenError)
                   << L"\n";
        return false;
    }
    UniqueHandle token(rawToken);

    DWORD tokenInformationBytes = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &tokenInformationBytes);
    const DWORD tokenSizeError = GetLastError();
    if (tokenSizeError != ERROR_INSUFFICIENT_BUFFER || tokenInformationBytes == 0)
    {
        std::wcerr << L"Could not size the child process identity: "
                   << FormatWindowsError(tokenSizeError) << L"\n";
        return false;
    }

    std::vector<BYTE> tokenInformation(tokenInformationBytes);
    if (!GetTokenInformation(token.get(),
            TokenUser,
            tokenInformation.data(),
            tokenInformationBytes,
            &tokenInformationBytes))
    {
        const DWORD tokenInformationError = GetLastError();
        std::wcerr << L"Could not read the child process identity: "
                   << FormatWindowsError(tokenInformationError) << L"\n";
        return false;
    }

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenInformation.data());
    if (!IsValidSid(tokenUser->User.Sid))
    {
        std::wcerr << L"The child process has an invalid user SID.\n";
        return false;
    }

    wchar_t* rawSid = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &rawSid))
    {
        const DWORD sidError = GetLastError();
        std::wcerr << L"Could not format the child process SID: " << FormatWindowsError(sidError)
                   << L"\n";
        return false;
    }
    LocalBuffer sidBuffer(rawSid);
    if (_wcsicmp(rawSid, account.sid.c_str()) != 0)
    {
        std::wcerr << L"The child process SID was " << rawSid << L"; expected " << account.sid
                   << L".\n";
        return false;
    }
    return ValidateNonAdministrativeToken(token.get(), account);
}

[[nodiscard]] ExitCode AcquirePassword(const AccountIdentity& account, CredentialMode mode,
    SecretBuffer& password, bool& fromStoredCredential, bool& persistPromptedCredential)
{
    fromStoredCredential = false;
    persistPromptedCredential = false;

    if (mode != CredentialMode::Prompt)
    {
        const StoredCredentialResult storedResult = LoadStoredPassword(account, password);
        if (storedResult == StoredCredentialResult::Success)
        {
            fromStoredCredential = true;
            return ExitSuccess;
        }
        if (storedResult == StoredCredentialResult::Error)
        {
            return ExitFailure;
        }
        if (mode == CredentialMode::Stored)
        {
            std::wcerr << L"No stored launch-as credential exists for " << account.qualifiedUsername
                       << L". Register one first or use " << L"--credential-mode auto.\n";
            return ExitCredentialMissing;
        }
    }

    // The Credential UI checkbox is opt-in: do not preselect saving the password.
    persistPromptedCredential = false;
    const CredentialPromptResult promptResult = PromptForPassword(
        account, password, mode == CredentialMode::Auto, persistPromptedCredential);
    if (promptResult == CredentialPromptResult::Cancelled)
    {
        return ExitCancelled;
    }
    if (promptResult == CredentialPromptResult::Error)
    {
        return ExitFailure;
    }
    return ExitSuccess;
}

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
    const DWORD lookupError2 = GetLastError();

    if (lookupError2 != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0 || domainCharacters == 0)
    {
        std::wcerr << L"Could not resolve local account '" << qualifiedUsername << L"': "
                   << FormatWindowsError(lookupError2) << L"\n";
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
        const DWORD lookupError = GetLastError();
        std::wcerr << L"Could not resolve local account '" << qualifiedUsername << L"': "
                   << FormatWindowsError(lookupError) << L"\n";
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
        .username = username,
        .qualifiedUsername = qualifiedUsername,
        .sid = rawSid,
        .testCredentialTag = {}
    };
}

bool ValidateNonAdministrativeToken(HANDLE token, const AccountIdentity& account)
{
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid {};
    DWORD administratorsSidBytes = static_cast<DWORD>(administratorsSid.size());
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid,
            nullptr,
            administratorsSid.data(),
            &administratorsSidBytes))
    {
        const DWORD error = GetLastError();
        std::wcerr << L"Could not construct the Administrators SID: " << FormatWindowsError(error)
                   << L"\n";
        return false;
    }

    DWORD tokenGroupsBytes = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &tokenGroupsBytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || tokenGroupsBytes == 0)
    {
        std::wcerr << L"Could not size token groups for " << account.qualifiedUsername << L": "
                   << FormatWindowsError(sizeError) << L"\n";
        return false;
    }

    std::vector<BYTE> tokenGroupsBuffer(tokenGroupsBytes);
    if (!GetTokenInformation(
            token, TokenGroups, tokenGroupsBuffer.data(), tokenGroupsBytes, &tokenGroupsBytes))
    {
        const DWORD error = GetLastError();
        std::wcerr << L"Could not read token groups for " << account.qualifiedUsername << L": "
                   << FormatWindowsError(error) << L"\n";
        return false;
    }

    const auto* tokenGroups = reinterpret_cast<const TOKEN_GROUPS*>(tokenGroupsBuffer.data());
    for (DWORD index = 0; index < tokenGroups->GroupCount; ++index)
    {
        if (EqualSid(tokenGroups->Groups[index].Sid, administratorsSid.data()))
        {
            std::wcerr << L"Refusing privileged account " << account.qualifiedUsername
                       << L": its token contains the local Administrators SID.\n";
            return false;
        }
    }
    return true;
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

ExitCode RunProcessAsUser(const AccountIdentity& account, const Options& options)
{
    STARTUPINFOW standardStartupInfo {};
    standardStartupInfo.cb = sizeof(standardStartupInfo);
    DWORD creationFlags = CREATE_SUSPENDED;
    std::filesystem::path applicationPath = options.executablePath;
    std::vector<std::wstring> terminalHostArguments;
    const std::vector<std::wstring>* processArguments = &options.processArguments;
    TerminalBridge terminalBridge;

    if (options.terminal)
    {
        creationFlags |= CREATE_NO_WINDOW;

        std::wstring launcherPathError;
        applicationPath = GetLauncherExecutablePath(launcherPathError);
        if (applicationPath.empty())
        {
            std::wcerr << launcherPathError << L"\n";
            return ExitFailure;
        }

        std::wstring terminalError;
        if (!terminalBridge.Initialize(standardStartupInfo, terminalError))
        {
            std::wcerr << terminalError << L"\n";
            return ExitFailure;
        }

        terminalHostArguments = BuildPseudoConsoleHostArguments(
            options, terminalBridge.terminalSize(), terminalBridge.supportsCursorInheritance());
        processArguments = &terminalHostArguments;
    }

    SecretBuffer password;
    bool fromStoredCredential = false;
    bool persistPromptedCredential = false;
    const ExitCode passwordResult = AcquirePassword(
        account, options.credentialMode, password, fromStoredCredential, persistPromptedCredential);
    if (passwordResult != ExitSuccess)
    {
        return passwordResult;
    }

    PROCESS_INFORMATION processInfo {};

    const wchar_t* workingDirectory =
        options.workingDirectory.empty() ? nullptr : options.workingDirectory.c_str();
    BOOL created = FALSE;
    DWORD launchError = ERROR_SUCCESS;
    for (;;)
    {
        std::wstring commandLine =
            BuildWindowsCommandLine(applicationPath.native(), *processArguments);
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        if (options.terminal)
        {
            std::wstring terminalError;
            if (!terminalBridge.PrepareChildProcessCreation(terminalError))
            {
                password.clear();
                std::wcerr << terminalError << L"\n";
                return ExitFailure;
            }
        }

        processInfo = {};
        created = CreateProcessWithLogonW(account.username.c_str(),
            L".",
            password.data(),
            LOGON_WITH_PROFILE,
            applicationPath.c_str(),
            mutableCommandLine.data(),
            creationFlags,
            nullptr,
            workingDirectory,
            &standardStartupInfo,
            &processInfo);
        launchError = created ? ERROR_SUCCESS : GetLastError();
        if (options.terminal)
        {
            std::wstring terminalError;
            if (!terminalBridge.CompleteChildProcessCreation(created != FALSE, terminalError))
            {
                password.clear();
                if (created)
                {
                    TerminateProcess(processInfo.hProcess, ExitFailure);
                    WaitForSingleObject(processInfo.hProcess, 5'000);
                    CloseHandle(processInfo.hThread);
                    CloseHandle(processInfo.hProcess);
                }
                std::wcerr << terminalError << L"\n";
                return ExitFailure;
            }
        }
        if (created || launchError != ERROR_LOGON_FAILURE ||
            options.credentialMode != CredentialMode::Auto || !fromStoredCredential)
        {
            break;
        }

        std::wcerr << L"The stored credential for " << account.qualifiedUsername
                   << L" was rejected. Enter its current password.\n";
        password.clear();
        fromStoredCredential = false;
        // A replacement stored credential also requires an explicit opt-in to save.
        persistPromptedCredential = false;
        const CredentialPromptResult promptResult =
            PromptForPassword(account, password, true, persistPromptedCredential);
        if (promptResult == CredentialPromptResult::Cancelled)
        {
            return ExitCancelled;
        }
        if (promptResult == CredentialPromptResult::Error)
        {
            return ExitFailure;
        }
    }

    if (!created)
    {
        password.clear();
        std::wcerr << L"Could not run the process as " << account.qualifiedUsername << L": "
                   << FormatWindowsError(launchError) << L"\n";
        if (launchError == ERROR_LOGON_FAILURE)
        {
            std::wcerr << L"Windows rejected the supplied password.\n";
        }
        return ExitFailure;
    }

    UniqueHandle process(processInfo.hProcess);
    UniqueHandle thread(processInfo.hThread);
    if (!ProcessHasAccountSid(process.get(), account))
    {
        password.clear();
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), 5'000);
        return ExitFailure;
    }
    if (persistPromptedCredential)
    {
        if (SaveCredential(account, password))
        {
            std::wcout << L"Stored the credential for future runs.\n";
        }
        else
        {
            std::wcerr << L"The process will continue without persisting the credential.\n";
        }
    }
    password.clear();

    if (options.terminal)
    {
        std::wcout << L"Starting terminal session as " << account.qualifiedUsername
                   << L". Output in this pane is controlled by that session until it exits.\n";
        std::wcout.flush();

        std::wstring terminalError;
        if (!terminalBridge.Start(terminalError))
        {
            TerminateProcess(process.get(), ExitFailure);
            WaitForSingleObject(process.get(), 5'000);
            std::wcerr << terminalError << L"\n";
            return ExitFailure;
        }
    }

    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
    {
        const DWORD resumeError = GetLastError();
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), 5'000);
        terminalBridge.Stop();
        std::wcerr << L"Could not start the child process: " << FormatWindowsError(resumeError)
                   << L"\n";
        return ExitFailure;
    }

    const DWORD waitResult = WaitForSingleObject(process.get(), INFINITE);
    if (waitResult != WAIT_OBJECT_0)
    {
        const DWORD waitError = GetLastError();
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), 5'000);
        terminalBridge.Stop();
        std::wcerr << L"Could not wait for the child process: " << FormatWindowsError(waitError)
                   << L"\n";
        return ExitFailure;
    }
    terminalBridge.Stop();

    DWORD childExitCode = 0;
    if (!GetExitCodeProcess(process.get(), &childExitCode))
    {
        const DWORD err = GetLastError();
        std::wcerr << L"Could not read the child process exit code: " << FormatWindowsError(err)
                   << L"\n";
        return ExitFailure;
    }

    std::wcout << L"Process as " << account.qualifiedUsername << L" exited with code "
               << childExitCode << L"";

    if (childExitCode != ExitSuccess)
    {
        wchar_t* rawMessage = nullptr;
        const DWORD length =
            FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                               FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                childExitCode,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<wchar_t*>(&rawMessage),
                0,
                nullptr);
        LocalBuffer messageBuffer(rawMessage);

        if (length == 0 || rawMessage == nullptr)
        {
            std::wcout << L".\n";
        }
        else
        {
            std::wstring message(rawMessage, length);
            while (!message.empty() &&
                   (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' '))
            {
                message.pop_back();
            }
            std::wcout << L": " << message << "\n";
        }
    }
    return childExitCode;
}

} // namespace launch_as
