// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#include <Windows.h>
#include <sddl.h>
#include <wincred.h>

#include "WindowsCommandLine.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::wstring_view CredentialPrefix = L"claude-win-sandbox:";
constexpr DWORD ExitSuccess = 0;
constexpr DWORD ExitFailure = 1;
constexpr DWORD ExitUsage = 2;
constexpr DWORD ExitCredentialMissing = 3;
constexpr std::size_t MaximumPasswordCharacters = 512;
constexpr std::size_t MaximumTestCredentialTagCharacters = 64;

class UniqueHandle {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE value) noexcept : value_(value) {}

    ~UniqueHandle() {
        reset();
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept
        : value_(std::exchange(other.value_, nullptr)) {}

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.value_, nullptr));
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept {
        return value_;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

    void reset(HANDLE value = nullptr) noexcept {
        if (*this) {
            CloseHandle(value_);
        }
        value_ = value;
    }

private:
    HANDLE value_ = nullptr;
};

class LocalBuffer {
public:
    explicit LocalBuffer(void* value = nullptr) noexcept : value_(value) {}

    ~LocalBuffer() {
        if (value_ != nullptr) {
            LocalFree(value_);
        }
    }

    LocalBuffer(const LocalBuffer&) = delete;
    LocalBuffer& operator=(const LocalBuffer&) = delete;

    [[nodiscard]] void* get() const noexcept {
        return value_;
    }

private:
    void* value_ = nullptr;
};

class SecretBuffer {
public:
    explicit SecretBuffer(std::size_t capacityCharacters)
        : characters_(capacityCharacters, L'\0') {}

    ~SecretBuffer() {
        clear();
    }

    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;
    SecretBuffer(SecretBuffer&&) = delete;
    SecretBuffer& operator=(SecretBuffer&&) = delete;

    [[nodiscard]] wchar_t* data() noexcept {
        return characters_.data();
    }

    [[nodiscard]] const wchar_t* data() const noexcept {
        return characters_.data();
    }

    [[nodiscard]] std::size_t capacity() const noexcept {
        return characters_.size();
    }

    [[nodiscard]] std::size_t length() const noexcept {
        return length_;
    }

    [[nodiscard]] DWORD byte_size() const noexcept {
        return static_cast<DWORD>(length_ * sizeof(wchar_t));
    }

    bool set_length(std::size_t length) noexcept {
        if (length >= characters_.size()) {
            return false;
        }
        length_ = length;
        characters_[length_] = L'\0';
        return true;
    }

    bool assign_bytes(const BYTE* bytes, DWORD byteCount) {
        if (bytes == nullptr || byteCount == 0 ||
            (byteCount % sizeof(wchar_t)) != 0) {
            return false;
        }

        const auto characterCount =
            static_cast<std::size_t>(byteCount / sizeof(wchar_t));
        if (characterCount + 1 > characters_.size()) {
            return false;
        }

        clear();
        std::memcpy(characters_.data(), bytes, byteCount);
        length_ = characterCount;
        characters_[length_] = L'\0';
        return true;
    }

    void clear() noexcept {
        if (!characters_.empty()) {
            SecureZeroMemory(
                characters_.data(),
                characters_.size() * sizeof(wchar_t));
        }
        length_ = 0;
    }

private:
    std::vector<wchar_t> characters_;
    std::size_t length_ = 0;
};

class ConsoleModeGuard {
public:
    ConsoleModeGuard(HANDLE handle, DWORD originalMode) noexcept
        : handle_(handle), originalMode_(originalMode) {}

    ~ConsoleModeGuard() {
        SetConsoleMode(handle_, originalMode_);
    }

    ConsoleModeGuard(const ConsoleModeGuard&) = delete;
    ConsoleModeGuard& operator=(const ConsoleModeGuard&) = delete;

private:
    HANDLE handle_;
    DWORD originalMode_;
};

class CredentialBuffer {
public:
    CredentialBuffer() noexcept = default;

    ~CredentialBuffer() {
        reset();
    }

    CredentialBuffer(const CredentialBuffer&) = delete;
    CredentialBuffer& operator=(const CredentialBuffer&) = delete;

    [[nodiscard]] PCREDENTIALW* address() noexcept {
        return &credential_;
    }

    [[nodiscard]] PCREDENTIALW get() const noexcept {
        return credential_;
    }

    void reset() noexcept {
        if (credential_ == nullptr) {
            return;
        }

        if (credential_->CredentialBlob != nullptr &&
            credential_->CredentialBlobSize > 0) {
            SecureZeroMemory(
                credential_->CredentialBlob,
                credential_->CredentialBlobSize);
        }
        CredFree(credential_);
        credential_ = nullptr;
    }

private:
    PCREDENTIALW credential_ = nullptr;
};

struct AccountIdentity {
    std::wstring username;
    std::wstring qualifiedUsername;
    std::wstring sid;
    std::wstring testCredentialTag;
};

enum class Command {
    Register,
    Run,
    Status,
    Forget
};

struct Options {
    Command command;
    std::wstring username;
    std::wstring testCredentialTag;
    bool testCredentialTagSpecified = false;
    std::filesystem::path workingDirectory;
    std::filesystem::path executablePath;
    std::vector<std::wstring> processArguments;
    bool newConsole = false;
};

[[nodiscard]] std::wstring FormatWindowsError(DWORD error) {
    wchar_t* rawMessage = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<wchar_t*>(&rawMessage),
        0,
        nullptr);
    LocalBuffer messageBuffer(rawMessage);

    if (length == 0 || rawMessage == nullptr) {
        return L"Windows error " + std::to_wstring(error);
    }

    std::wstring message(rawMessage, length);
    while (!message.empty() &&
           (message.back() == L'\r' ||
            message.back() == L'\n' ||
            message.back() == L' ')) {
        message.pop_back();
    }
    return message + L" (" + std::to_wstring(error) + L")";
}

void PrintUsage() {
    std::wcerr
        << L"Usage:\n"
        << L"  ClaudeSandboxLauncher.exe register --user <local-user>\n"
        << L"  ClaudeSandboxLauncher.exe status --user <local-user>\n"
        << L"  ClaudeSandboxLauncher.exe forget --user <local-user>\n"
        << L"  ClaudeSandboxLauncher.exe run --user <local-user>"
           L" [--working-directory <directory>] [--new-console]"
           L" -- <absolute-executable> [arguments...]\n"
        << L"Credential commands used by tests also accept:"
           L" --test-credential-tag <tag>\n";
}

[[nodiscard]] std::optional<Command> ParseCommand(std::wstring_view value) {
    if (value == L"register") {
        return Command::Register;
    }
    if (value == L"run") {
        return Command::Run;
    }
    if (value == L"status") {
        return Command::Status;
    }
    if (value == L"forget") {
        return Command::Forget;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<Options> ParseOptions(
    std::span<wchar_t*> arguments) {
    if (arguments.size() < 2) {
        return std::nullopt;
    }

    const auto command = ParseCommand(arguments[1]);
    if (!command) {
        return std::nullopt;
    }

    Options options{.command = *command};
    bool processArgumentsStarted = false;
    for (std::size_t index = 2; index < arguments.size(); ++index) {
        const std::wstring_view name(arguments[index]);
        if (name == L"--") {
            processArgumentsStarted = true;
            for (++index; index < arguments.size(); ++index) {
                options.processArguments.emplace_back(arguments[index]);
            }
            break;
        }
        if (name == L"--new-console") {
            options.newConsole = true;
            continue;
        }
        if (index + 1 >= arguments.size()) {
            return std::nullopt;
        }
        const std::wstring value(arguments[++index]);

        if (name == L"--user") {
            options.username = value;
        } else if (name == L"--test-credential-tag") {
            if (options.testCredentialTagSpecified) {
                return std::nullopt;
            }
            options.testCredentialTagSpecified = true;
            options.testCredentialTag = value;
        } else if (name == L"--working-directory") {
            options.workingDirectory = value;
        } else {
            return std::nullopt;
        }
    }

    if (options.username.empty()) {
        return std::nullopt;
    }
    if (options.username.find_first_of(L"\\/@") != std::wstring::npos) {
        return std::nullopt;
    }
    if (options.testCredentialTagSpecified) {
        if (options.testCredentialTag.empty()) {
            return std::nullopt;
        }
        const bool validTag =
            options.testCredentialTag.size() <=
                MaximumTestCredentialTagCharacters &&
            std::all_of(
                options.testCredentialTag.begin(),
                options.testCredentialTag.end(),
                [](wchar_t character) {
                    return
                        (character >= L'a' && character <= L'z') ||
                        (character >= L'A' && character <= L'Z') ||
                        (character >= L'0' && character <= L'9') ||
                        character == L'-' ||
                        character == L'_' ||
                        character == L'.';
                });
        if (!validTag) {
            return std::nullopt;
        }
    }
    if (*command == Command::Run) {
        if (!processArgumentsStarted || options.processArguments.empty()) {
            return std::nullopt;
        }
        options.executablePath = options.processArguments.front();
        options.processArguments.erase(options.processArguments.begin());
    } else if (
        processArgumentsStarted ||
        !options.workingDirectory.empty() ||
        options.newConsole) {
        return std::nullopt;
    }
    return options;
}

[[nodiscard]] std::optional<AccountIdentity> ResolveLocalAccount(
    const std::wstring& username) {
    const std::wstring qualifiedUsername = L".\\" + username;
    std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> computerName{};
    DWORD computerNameCharacters =
        static_cast<DWORD>(computerName.size());
    if (!GetComputerNameW(computerName.data(), &computerNameCharacters)) {
        std::wcerr << L"Could not resolve the local computer name: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return std::nullopt;
    }
    const std::wstring lookupName =
        std::wstring(computerName.data(), computerNameCharacters) +
        L"\\" + username;

    DWORD sidBytes = 0;
    DWORD domainCharacters = 0;
    SID_NAME_USE sidType{};
    LookupAccountNameW(
        nullptr,
        lookupName.c_str(),
        nullptr,
        &sidBytes,
        nullptr,
        &domainCharacters,
        &sidType);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        sidBytes == 0 ||
        domainCharacters == 0) {
        std::wcerr << L"Could not resolve local account '"
                   << qualifiedUsername << L"': "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return std::nullopt;
    }

    std::vector<BYTE> sid(sidBytes);
    std::vector<wchar_t> domain(domainCharacters);
    if (!LookupAccountNameW(
            nullptr,
            lookupName.c_str(),
            sid.data(),
            &sidBytes,
            domain.data(),
            &domainCharacters,
            &sidType)) {
        std::wcerr << L"Could not resolve local account '"
                   << qualifiedUsername << L"': "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return std::nullopt;
    }
    if (sidType != SidTypeUser || !IsValidSid(sid.data())) {
        std::wcerr << L"Account '" << qualifiedUsername
                   << L"' does not resolve to a valid user SID.\n";
        return std::nullopt;
    }

    wchar_t* rawSid = nullptr;
    if (!ConvertSidToStringSidW(sid.data(), &rawSid)) {
        std::wcerr << L"Could not format SID for '"
                   << qualifiedUsername << L"': "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return std::nullopt;
    }
    LocalBuffer sidBuffer(rawSid);

    return AccountIdentity{
        .username = username,
        .qualifiedUsername = qualifiedUsername,
        .sid = rawSid,
        .testCredentialTag = {}};
}

[[nodiscard]] std::wstring CredentialTarget(
    const AccountIdentity& account) {
    if (!account.testCredentialTag.empty()) {
        return std::wstring(CredentialPrefix) +
            L"test:" + account.testCredentialTag + L":" + account.sid;
    }
    return std::wstring(CredentialPrefix) + account.sid;
}

[[nodiscard]] bool ReadPassword(
    std::wstring_view prompt,
    SecretBuffer& password) {
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == nullptr || input == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Password input requires an interactive console.\n";
        return false;
    }

    DWORD originalMode = 0;
    if (!GetConsoleMode(input, &originalMode)) {
        std::wcerr
            << L"Password input must not be redirected; use an interactive console.\n";
        return false;
    }

    const DWORD passwordMode =
        originalMode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT);
    if (!SetConsoleMode(input, passwordMode)) {
        std::wcerr << L"Could not disable console echo: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }
    ConsoleModeGuard restoreMode(input, originalMode);

    std::wcout << prompt << std::flush;
    DWORD charactersRead = 0;
    if (!ReadConsoleW(
            input,
            password.data(),
            static_cast<DWORD>(password.capacity() - 1),
            &charactersRead,
            nullptr)) {
        std::wcout << L"\n";
        std::wcerr << L"Could not read password: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }
    std::wcout << L"\n";

    std::size_t length = charactersRead;
    while (length > 0 &&
           (password.data()[length - 1] == L'\r' ||
            password.data()[length - 1] == L'\n')) {
        --length;
    }
    if (!password.set_length(length) || length == 0) {
        std::wcerr << L"Password cannot be empty.\n";
        return false;
    }
    return true;
}

[[nodiscard]] bool ValidateNonAdministrativeToken(
    HANDLE token,
    const AccountIdentity& account) {
    std::array<BYTE, SECURITY_MAX_SID_SIZE> administratorsSid{};
    DWORD administratorsSidBytes =
        static_cast<DWORD>(administratorsSid.size());
    if (!CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            nullptr,
            administratorsSid.data(),
            &administratorsSidBytes)) {
        const DWORD error = GetLastError();
        std::wcerr << L"Could not construct the Administrators SID: "
                   << FormatWindowsError(error) << L"\n";
        return false;
    }

    DWORD tokenGroupsBytes = 0;
    GetTokenInformation(
        token,
        TokenGroups,
        nullptr,
        0,
        &tokenGroupsBytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER ||
        tokenGroupsBytes == 0) {
        std::wcerr << L"Could not size token groups for "
                   << account.qualifiedUsername << L": "
                   << FormatWindowsError(sizeError) << L"\n";
        return false;
    }

    std::vector<BYTE> tokenGroupsBuffer(tokenGroupsBytes);
    if (!GetTokenInformation(
            token,
            TokenGroups,
            tokenGroupsBuffer.data(),
            tokenGroupsBytes,
            &tokenGroupsBytes)) {
        const DWORD error = GetLastError();
        std::wcerr << L"Could not read token groups for "
                   << account.qualifiedUsername << L": "
                   << FormatWindowsError(error) << L"\n";
        return false;
    }

    const auto* tokenGroups =
        reinterpret_cast<const TOKEN_GROUPS*>(tokenGroupsBuffer.data());
    for (DWORD index = 0; index < tokenGroups->GroupCount; ++index) {
        if (EqualSid(
                tokenGroups->Groups[index].Sid,
                administratorsSid.data())) {
            std::wcerr
                << L"Refusing privileged account "
                << account.qualifiedUsername
                << L": its token contains the local Administrators SID.\n";
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool ValidatePassword(
    const AccountIdentity& account,
    const SecretBuffer& password) {
    HANDLE rawToken = nullptr;
    if (!LogonUserW(
            account.username.c_str(),
            L".",
            password.data(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &rawToken)) {
        std::wcerr << L"Windows rejected the credential for '"
                   << account.qualifiedUsername << L"': "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }
    UniqueHandle token(rawToken);
    return ValidateNonAdministrativeToken(token.get(), account);
}

[[nodiscard]] bool WriteCredential(
    const AccountIdentity& account,
    const SecretBuffer& password) {
    std::wstring target = CredentialTarget(account);
    std::wstring comment = L"claude-win-sandbox launcher credential";
    if (!account.testCredentialTag.empty()) {
        comment =
            L"claude-win-sandbox test credential: " +
            account.testCredentialTag;
    }
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = target.data();
    credential.Comment = comment.data();
    credential.CredentialBlobSize = password.byte_size();
    credential.CredentialBlob =
        reinterpret_cast<LPBYTE>(const_cast<wchar_t*>(password.data()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName =
        const_cast<wchar_t*>(account.qualifiedUsername.c_str());

    if (!CredWriteW(&credential, 0)) {
        std::wcerr << L"Could not store credential: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }
    return true;
}

[[nodiscard]] DWORD RegisterCredential(const AccountIdentity& account) {
    SecretBuffer password(MaximumPasswordCharacters);
    if (!ReadPassword(
            L"Password for " + account.qualifiedUsername + L": ",
            password)) {
        return ExitFailure;
    }
    if (!ValidatePassword(account, password)) {
        return ExitFailure;
    }
    if (!WriteCredential(account, password)) {
        return ExitFailure;
    }

    std::wcout
        << L"Stored a machine-local credential for "
        << account.qualifiedUsername
        << L" in the current Windows user's Credential Manager.\n";
    return ExitSuccess;
}

enum class CredentialReadResult {
    Success,
    NotFound,
    Error
};

[[nodiscard]] CredentialReadResult ReadCredential(
    const AccountIdentity& account,
    CredentialBuffer& credential) {
    const std::wstring target = CredentialTarget(account);
    if (CredReadW(
            target.c_str(),
            CRED_TYPE_GENERIC,
            0,
            credential.address())) {
        return CredentialReadResult::Success;
    }

    const DWORD error = GetLastError();
    if (error == ERROR_NOT_FOUND) {
        return CredentialReadResult::NotFound;
    }
    std::wcerr << L"Could not read credential: "
               << FormatWindowsError(error) << L"\n";
    return CredentialReadResult::Error;
}

[[nodiscard]] DWORD CredentialStatus(const AccountIdentity& account) {
    CredentialBuffer credential;
    const CredentialReadResult result = ReadCredential(account, credential);
    if (result == CredentialReadResult::NotFound) {
        std::wcout << L"No launcher credential is registered for "
                   << account.qualifiedUsername << L".\n";
        return ExitCredentialMissing;
    }
    if (result == CredentialReadResult::Error) {
        return ExitFailure;
    }

    std::wcout << L"A launcher credential is registered for "
               << account.qualifiedUsername << L".\n";
    return ExitSuccess;
}

[[nodiscard]] DWORD LoadStoredPassword(
    const AccountIdentity& account,
    SecretBuffer& password) {
    CredentialBuffer credential;
    const CredentialReadResult result = ReadCredential(account, credential);
    if (result == CredentialReadResult::NotFound) {
        std::wcerr << L"Register the credential first with:\n"
                   << L"  ClaudeSandboxLauncher.exe register --user "
                   << account.username << L"\n";
        return ExitCredentialMissing;
    }
    if (result == CredentialReadResult::Error) {
        return ExitFailure;
    }
    if (credential.get()->CredentialBlobSize == 0 ||
        credential.get()->CredentialBlob == nullptr) {
        std::wcerr << L"The stored credential contains no password.\n";
        return ExitFailure;
    }
    if (credential.get()->UserName == nullptr ||
        _wcsicmp(
            credential.get()->UserName,
            account.qualifiedUsername.c_str()) != 0) {
        std::wcerr
            << L"The stored credential belongs to an unexpected account. "
            << L"Forget and register it again.\n";
        return ExitFailure;
    }
    if (!password.assign_bytes(
            credential.get()->CredentialBlob,
            credential.get()->CredentialBlobSize)) {
        std::wcerr
            << L"The stored credential has an invalid password representation.\n";
        return ExitFailure;
    }

    credential.reset();
    return ExitSuccess;
}

[[nodiscard]] DWORD ForgetCredential(const AccountIdentity& account) {
    const std::wstring target = CredentialTarget(account);
    if (CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0)) {
        std::wcout << L"Removed the launcher credential for "
                   << account.qualifiedUsername << L".\n";
        return ExitSuccess;
    }

    const DWORD error = GetLastError();
    if (error == ERROR_NOT_FOUND) {
        std::wcout << L"No launcher credential was registered for "
                   << account.qualifiedUsername << L".\n";
        return ExitSuccess;
    }

    std::wcerr << L"Could not remove credential: "
               << FormatWindowsError(error) << L"\n";
    return ExitFailure;
}

[[nodiscard]] bool ProcessHasAccountSid(
    HANDLE process,
    const AccountIdentity& account) {
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &rawToken)) {
        std::wcerr << L"Could not open the child process token: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }
    UniqueHandle token(rawToken);

    DWORD tokenInformationBytes = 0;
    GetTokenInformation(
        token.get(),
        TokenUser,
        nullptr,
        0,
        &tokenInformationBytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        tokenInformationBytes == 0) {
        std::wcerr << L"Could not size the child process identity: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }

    std::vector<BYTE> tokenInformation(tokenInformationBytes);
    if (!GetTokenInformation(
            token.get(),
            TokenUser,
            tokenInformation.data(),
            tokenInformationBytes,
            &tokenInformationBytes)) {
        std::wcerr << L"Could not read the child process identity: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }

    const auto* tokenUser =
        reinterpret_cast<const TOKEN_USER*>(tokenInformation.data());
    if (!IsValidSid(tokenUser->User.Sid)) {
        std::wcerr << L"The child process has an invalid user SID.\n";
        return false;
    }

    wchar_t* rawSid = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &rawSid)) {
        std::wcerr << L"Could not format the child process SID: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }
    LocalBuffer sidBuffer(rawSid);
    if (_wcsicmp(rawSid, account.sid.c_str()) != 0) {
        std::wcerr << L"The child process SID was " << rawSid
                   << L"; expected " << account.sid << L".\n";
        return false;
    }
    return ValidateNonAdministrativeToken(token.get(), account);
}

[[nodiscard]] bool ValidateRunPaths(const Options& options) {
    std::error_code error;
    if (!options.executablePath.is_absolute() ||
        !std::filesystem::is_regular_file(options.executablePath, error)) {
        std::wcerr << L"Executable is not an existing absolute file: "
                   << options.executablePath.c_str() << L"\n";
        return false;
    }
    if (!options.workingDirectory.empty()) {
        error.clear();
        if (!options.workingDirectory.is_absolute() ||
            !std::filesystem::is_directory(
                options.workingDirectory,
                error)) {
            std::wcerr
                << L"Working directory is not an existing absolute directory: "
                << options.workingDirectory.c_str() << L"\n";
            return false;
        }
    }
    return true;
}

[[nodiscard]] DWORD Run(
    const AccountIdentity& account,
    const Options& options) {
    SecretBuffer password(MaximumPasswordCharacters);
    const DWORD passwordResult = LoadStoredPassword(account, password);
    if (passwordResult != ExitSuccess) {
        return passwordResult;
    }

    std::wstring commandLine =
        sandbox_launcher::BuildWindowsCommandLine(
            options.executablePath.native(),
            options.processArguments);
    std::vector<wchar_t> mutableCommandLine(
        commandLine.begin(),
        commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    if (options.newConsole) {
        startupInfo.lpDesktop =
            const_cast<wchar_t*>(L"winsta0\\default");
    }
    PROCESS_INFORMATION processInfo{};

    DWORD creationFlags = CREATE_SUSPENDED;
    if (options.newConsole) {
        creationFlags |= CREATE_NEW_CONSOLE;
    }
    const wchar_t* workingDirectory =
        options.workingDirectory.empty()
            ? nullptr
            : options.workingDirectory.c_str();
    const BOOL created = CreateProcessWithLogonW(
        account.username.c_str(),
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

    if (!created) {
        std::wcerr << L"Could not run the process as "
                   << account.qualifiedUsername << L": "
                   << FormatWindowsError(launchError) << L"\n";
        if (launchError == ERROR_LOGON_FAILURE) {
            std::wcerr
                << L"The stored password may be stale. Register it again.\n";
        }
        return ExitFailure;
    }

    UniqueHandle process(processInfo.hProcess);
    UniqueHandle thread(processInfo.hThread);
    if (!ProcessHasAccountSid(process.get(), account)) {
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), 5'000);
        return ExitFailure;
    }
    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
        const DWORD resumeError = GetLastError();
        TerminateProcess(process.get(), ExitFailure);
        WaitForSingleObject(process.get(), 5'000);
        std::wcerr << L"Could not start the child process: "
                   << FormatWindowsError(resumeError) << L"\n";
        return ExitFailure;
    }

    const DWORD waitResult = WaitForSingleObject(process.get(), INFINITE);
    if (waitResult != WAIT_OBJECT_0) {
        std::wcerr << L"Could not wait for the child process: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return ExitFailure;
    }

    DWORD childExitCode = 0;
    if (!GetExitCodeProcess(process.get(), &childExitCode)) {
        std::wcerr << L"Could not read the child process exit code: "
                   << FormatWindowsError(GetLastError()) << L"\n";
        return ExitFailure;
    }

    std::wcout << L"Process as " << account.qualifiedUsername
               << L" exited with code " << childExitCode << L".\n";
    return childExitCode;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    const auto options = ParseOptions(
        std::span<wchar_t*>(argv, static_cast<std::size_t>(argc)));
    if (!options) {
        PrintUsage();
        return static_cast<int>(ExitUsage);
    }
    if (options->command == Command::Run &&
        !ValidateRunPaths(*options)) {
        return static_cast<int>(ExitFailure);
    }

    auto account = ResolveLocalAccount(options->username);
    if (!account) {
        return static_cast<int>(ExitFailure);
    }
    account->testCredentialTag = options->testCredentialTag;

    DWORD exitCode = ExitFailure;
    switch (options->command) {
    case Command::Register:
        exitCode = RegisterCredential(*account);
        break;
    case Command::Run:
        exitCode = Run(*account, *options);
        break;
    case Command::Status:
        exitCode = CredentialStatus(*account);
        break;
    case Command::Forget:
        exitCode = ForgetCredential(*account);
        break;
    }
    return static_cast<int>(exitCode);
}
