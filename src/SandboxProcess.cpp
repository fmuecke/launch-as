// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#include "SandboxProcess.h"

#include "Credentials.h"
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

namespace sandbox_launcher
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
        std::wcerr << L"Could not open the child process token: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }
    UniqueHandle token(rawToken);

    DWORD tokenInformationBytes = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &tokenInformationBytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || tokenInformationBytes == 0)
    {
        std::wcerr << L"Could not size the child process identity: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }

    std::vector<BYTE> tokenInformation(tokenInformationBytes);
    if (!GetTokenInformation(token.get(),
                             TokenUser,
                             tokenInformation.data(),
                             tokenInformationBytes,
                             &tokenInformationBytes))
    {
        std::wcerr << L"Could not read the child process identity: "
                   << FormatWindowsError(GetLastError()) << L"\n";
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
        std::wcerr << L"Could not format the child process SID: "
                   << FormatWindowsError(GetLastError()) << L"\n";
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

} // namespace

std::optional<AccountIdentity> ResolveLocalAccount(const std::wstring& username)
{
    const std::wstring qualifiedUsername = L".\\" + username;
    std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> computerName{};
    DWORD computerNameCharacters = static_cast<DWORD>(computerName.size());
    if (!GetComputerNameW(computerName.data(), &computerNameCharacters))
    {
        std::wcerr << L"Could not resolve the local computer name: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return std::nullopt;
    }
    const std::wstring lookupName =
        std::wstring(computerName.data(), computerNameCharacters) + L"\\" + username;

    DWORD sidBytes = 0;
    DWORD domainCharacters = 0;
    SID_NAME_USE sidType{};
    LookupAccountNameW(
        nullptr, lookupName.c_str(), nullptr, &sidBytes, nullptr, &domainCharacters, &sidType);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0 || domainCharacters == 0)
    {
        std::wcerr << L"Could not resolve local account '" << qualifiedUsername << L"': "
                   << FormatWindowsError(GetLastError()) << L"\n";
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
        std::wcerr << L"Could not resolve local account '" << qualifiedUsername << L"': "
                   << FormatWindowsError(GetLastError()) << L"\n";
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
        std::wcerr << L"Could not format SID for '" << qualifiedUsername << L"': "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return std::nullopt;
    }
    LocalBuffer sidBuffer(rawSid);

    return AccountIdentity{ .username = username,
                            .qualifiedUsername = qualifiedUsername,
                            .sid = rawSid,
                            .testCredentialTag = {} };
}

bool ValidateNonAdministrativeToken(HANDLE token, const AccountIdentity& account)
{
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid{};
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

ExitCode RunSandboxProcess(const AccountIdentity& account, const Options& options)
{
    SecretBuffer password;
    const ExitCode passwordResult = LoadStoredPassword(account, password);
    if (passwordResult != ExitSuccess)
    {
        return passwordResult;
    }

    std::wstring commandLine =
        BuildWindowsCommandLine(options.executablePath.native(), options.processArguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    if (options.newConsole)
    {
        startupInfo.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    }
    PROCESS_INFORMATION processInfo{};

    DWORD creationFlags = CREATE_SUSPENDED;
    if (options.newConsole)
    {
        creationFlags |= CREATE_NEW_CONSOLE;
    }
    const wchar_t* workingDirectory =
        options.workingDirectory.empty() ? nullptr : options.workingDirectory.c_str();
    const BOOL created = CreateProcessWithLogonW(account.username.c_str(),
                                                 L".",
                                                 password.data(),
                                                 LOGON_WITH_PROFILE,
                                                 options.executablePath.c_str(),
                                                 mutableCommandLine.data(),
                                                 creationFlags,
                                                 nullptr,
                                                 workingDirectory,
                                                 &startupInfo,
                                                 &processInfo);
    const DWORD launchError = created ? ERROR_SUCCESS : GetLastError();
    password.clear();

    if (!created)
    {
        std::wcerr << L"Could not run the process as " << account.qualifiedUsername << L": "
                   << FormatWindowsError(launchError) << L"\n";
        if (launchError == ERROR_LOGON_FAILURE)
        {
            std::wcerr << L"The stored password may be stale. Register it again.\n";
        }
        return ExitFailure;
    }

    UniqueHandle process(processInfo.hProcess);
    UniqueHandle thread(processInfo.hThread);
    if (!ProcessHasAccountSid(process.get(), account))
    {
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), 5'000);
        return ExitFailure;
    }
    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
    {
        const DWORD resumeError = GetLastError();
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), 5'000);
        std::wcerr << L"Could not start the child process: " << FormatWindowsError(resumeError)
                   << L"\n";
        return ExitFailure;
    }

    const DWORD waitResult = WaitForSingleObject(process.get(), INFINITE);
    if (waitResult != WAIT_OBJECT_0)
    {
        std::wcerr << L"Could not wait for the child process: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return ExitFailure;
    }

    DWORD childExitCode = 0;
    if (!GetExitCodeProcess(process.get(), &childExitCode))
    {
        std::wcerr << L"Could not read the child process exit code: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return ExitFailure;
    }

    std::wcout << L"Process as " << account.qualifiedUsername << L" exited with code "
               << childExitCode << L".\n";
    return childExitCode;
}

} // namespace sandbox_launcher
