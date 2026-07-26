// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#include "Credentials.h"

#include "CredentialInput.h"
#include "SandboxProcess.h"
#include "Win32Support.h"

#include <Lmcons.h>
#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <string>
#include <string_view>
#include <wincred.h>

namespace sandbox_launcher
{
namespace
{

constexpr std::wstring_view CredentialPrefix = L"claude-win-sandbox: ";
constexpr std::size_t MaximumPasswordCharacters = 512;

class CredentialBuffer final
{
  public:
    CredentialBuffer() noexcept = default;
    ~CredentialBuffer() { reset(); }

    CredentialBuffer(const CredentialBuffer&) = delete;
    CredentialBuffer& operator=(const CredentialBuffer&) = delete;

    [[nodiscard]] PCREDENTIALW* address() noexcept { return &credential_; }
    [[nodiscard]] PCREDENTIALW get() const noexcept { return credential_; }

    void reset() noexcept
    {
        if (credential_ == nullptr)
        {
            return;
        }
        if (credential_->CredentialBlob != nullptr && credential_->CredentialBlobSize > 0)
        {
            SecureZeroMemory(credential_->CredentialBlob, credential_->CredentialBlobSize);
        }
        CredFree(credential_);
        credential_ = nullptr;
    }

  private:
    PCREDENTIALW credential_ = nullptr;
};

enum class CredentialReadResult
{
    Success,
    NotFound,
    Error
};

[[nodiscard]] std::wstring CurrentWindowsUsername()
{
    std::array<wchar_t, UNLEN + 1> username {};
    DWORD usernameCharacters = static_cast<DWORD>(username.size());
    if (!GetUserNameW(username.data(), &usernameCharacters))
    {
        return L"<unknown Windows user>";
    }
    return username.data();
}

[[nodiscard]] std::wstring CredentialTarget(const AccountIdentity& account)
{
    if (!account.testCredentialTag.empty())
    {
        return std::wstring(CredentialPrefix) + L"test:" + account.testCredentialTag + L":" +
               account.sid;
    }
    return std::wstring(CredentialPrefix) + account.sid;
}

[[nodiscard]] bool ValidatePassword(const AccountIdentity& account, const SecretBuffer& password)
{
    HANDLE rawToken = nullptr;
    if (!LogonUserW(account.username.c_str(),
            L".",
            password.data(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &rawToken))
    {
        std::wcerr << L"Windows rejected the credential for '" << account.qualifiedUsername
                   << L"': " << FormatWindowsError(GetLastError()) << L"\n";
        return false;
    }
    UniqueHandle token(rawToken);
    return ValidateNonAdministrativeToken(token.get(), account);
}

[[nodiscard]] CredentialReadResult ReadCredential(
    const AccountIdentity& account, CredentialBuffer& credential)
{
    const std::wstring target = CredentialTarget(account);
    if (CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, credential.address()))
    {
        return CredentialReadResult::Success;
    }

    const DWORD error = GetLastError();
    if (error == ERROR_NOT_FOUND)
    {
        return CredentialReadResult::NotFound;
    }
    std::wcerr << L"Could not read credential: " << FormatWindowsError(error) << L"\n";
    return CredentialReadResult::Error;
}

[[nodiscard]] ExitCode ValidateAndSaveCredential(
    const AccountIdentity& account, SecretBuffer& password)
{
    if (!ValidatePassword(account, password) || !SaveCredential(account, password))
    {
        return ExitFailure;
    }
    std::wcout << L"Stored a machine-local credential for " << account.qualifiedUsername << L" in "
               << CurrentWindowsUsername() << L"'s Windows Credential Manager.\n";
    return ExitSuccess;
}

} // namespace

SecretBuffer::SecretBuffer() : characters_(MaximumPasswordCharacters, L'\0') {}

SecretBuffer::~SecretBuffer() { clear(); }

wchar_t* SecretBuffer::data() noexcept { return characters_.data(); }

const wchar_t* SecretBuffer::data() const noexcept { return characters_.data(); }

std::size_t SecretBuffer::capacity() const noexcept { return characters_.size(); }

DWORD SecretBuffer::byte_size() const noexcept
{
    return static_cast<DWORD>(length_ * sizeof(wchar_t));
}

bool SecretBuffer::set_length(std::size_t length) noexcept
{
    if (length >= characters_.size())
    {
        return false;
    }
    length_ = length;
    characters_[length_] = L'\0';
    return true;
}

bool SecretBuffer::assign_bytes(const BYTE* bytes, DWORD byteCount)
{
    if (bytes == nullptr || byteCount == 0 || (byteCount % sizeof(wchar_t)) != 0)
    {
        return false;
    }
    const auto characterCount = static_cast<std::size_t>(byteCount / sizeof(wchar_t));
    if (characterCount + 1 > characters_.size())
    {
        return false;
    }

    clear();
    std::memcpy(characters_.data(), bytes, byteCount);
    length_ = characterCount;
    characters_[length_] = L'\0';
    return true;
}

void SecretBuffer::clear() noexcept
{
    if (!characters_.empty())
    {
        SecureZeroMemory(characters_.data(), characters_.size() * sizeof(wchar_t));
    }
    length_ = 0;
}

ExitCode RegisterCredential(const AccountIdentity& account)
{
    SecretBuffer password;
    bool persist = false;
    const CredentialPromptResult promptResult =
        PromptForPassword(account, password, false, persist);
    if (promptResult == CredentialPromptResult::Cancelled)
    {
        return ExitCancelled;
    }
    if (promptResult == CredentialPromptResult::Error)
    {
        return ExitFailure;
    }
    return ValidateAndSaveCredential(account, password);
}

ExitCode RegisterCredentialFromStandardInput(const AccountIdentity& account)
{
    SecretBuffer password;
    if (!ReadPasswordFromStandardInput(password))
    {
        return ExitFailure;
    }
    return ValidateAndSaveCredential(account, password);
}

ExitCode CredentialStatus(const AccountIdentity& account)
{
    CredentialBuffer credential;
    const CredentialReadResult result = ReadCredential(account, credential);
    if (result == CredentialReadResult::NotFound)
    {
        std::wcout << L"No launcher credential is registered for " << account.qualifiedUsername
                   << L".\n";
        return ExitCredentialMissing;
    }
    if (result == CredentialReadResult::Error)
    {
        return ExitFailure;
    }

    std::wcout << L"A launcher credential is registered for " << account.qualifiedUsername
               << L".\n";
    return ExitSuccess;
}

StoredCredentialResult LoadStoredPassword(const AccountIdentity& account, SecretBuffer& password)
{
    CredentialBuffer credential;
    const CredentialReadResult result = ReadCredential(account, credential);
    if (result == CredentialReadResult::NotFound)
    {
        return StoredCredentialResult::NotFound;
    }
    if (result == CredentialReadResult::Error)
    {
        return StoredCredentialResult::Error;
    }
    if (credential.get()->CredentialBlobSize == 0 || credential.get()->CredentialBlob == nullptr)
    {
        std::wcerr << L"The stored credential contains no password.\n";
        return StoredCredentialResult::Error;
    }
    if (credential.get()->UserName == nullptr ||
        _wcsicmp(credential.get()->UserName, account.qualifiedUsername.c_str()) != 0)
    {
        std::wcerr << L"The stored credential belongs to an unexpected account. "
                   << L"Forget and register it again.\n";
        return StoredCredentialResult::Error;
    }
    if (!password.assign_bytes(
            credential.get()->CredentialBlob, credential.get()->CredentialBlobSize))
    {
        std::wcerr << L"The stored credential has an invalid password representation.\n";
        return StoredCredentialResult::Error;
    }

    credential.reset();
    return StoredCredentialResult::Success;
}

bool SaveCredential(const AccountIdentity& account, const SecretBuffer& password)
{
    std::wstring target = CredentialTarget(account);
    std::wstring comment = L"claude-win-sandbox launcher credential";
    if (!account.testCredentialTag.empty())
    {
        comment = L"claude-win-sandbox test credential: " + account.testCredentialTag;
    }
    CREDENTIALW credential {};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = target.data();
    credential.Comment = comment.data();
    credential.CredentialBlobSize = password.byte_size();
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<wchar_t*>(password.data()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName = const_cast<wchar_t*>(account.qualifiedUsername.c_str());

    if (!CredWriteW(&credential, 0))
    {
        std::wcerr << L"Could not store credential: " << FormatWindowsError(GetLastError())
                   << L"\n";
        return false;
    }
    return true;
}

ExitCode ForgetCredential(const AccountIdentity& account)
{
    const std::wstring target = CredentialTarget(account);
    if (CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0))
    {
        std::wcout << L"Removed the launcher credential for " << account.qualifiedUsername
                   << L".\n";
        return ExitSuccess;
    }

    const DWORD error = GetLastError();
    if (error == ERROR_NOT_FOUND)
    {
        std::wcout << L"No launcher credential was registered for " << account.qualifiedUsername
                   << L".\n";
        return ExitSuccess;
    }

    std::wcerr << L"Could not remove credential: " << FormatWindowsError(error) << L"\n";
    return ExitFailure;
}

} // namespace sandbox_launcher
