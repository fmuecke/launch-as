// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "CredentialInput.h"

#include "LaunchProcess.h"
#include "Win32Support.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <objbase.h>
#include <string>
#include <string_view>
#include <vector>
#include <wincred.h>

namespace launch_as
{
namespace
{

class AuthenticationBuffer final
{
  public:
    AuthenticationBuffer() noexcept = default;
    ~AuthenticationBuffer() { reset(); }

    AuthenticationBuffer(const AuthenticationBuffer&) = delete;
    AuthenticationBuffer& operator=(const AuthenticationBuffer&) = delete;

    [[nodiscard]] void** address() noexcept { return &buffer_; }
    [[nodiscard]] void* get() const noexcept { return buffer_; }
    [[nodiscard]] ULONG size() const noexcept { return size_; }
    [[nodiscard]] ULONG* size_address() noexcept { return &size_; }

    void reset() noexcept
    {
        if (buffer_ == nullptr)
        {
            return;
        }
        SecureZeroMemory(buffer_, size_);
        CoTaskMemFree(buffer_);
        buffer_ = nullptr;
        size_ = 0;
    }

  private:
    void* buffer_ = nullptr;
    ULONG size_ = 0;
};

class SensitiveBytes final
{
  public:
    explicit SensitiveBytes(std::size_t capacity) : bytes_(capacity, 0) {}
    ~SensitiveBytes() { SecureZeroMemory(bytes_.data(), bytes_.size()); }

    SensitiveBytes(const SensitiveBytes&) = delete;
    SensitiveBytes& operator=(const SensitiveBytes&) = delete;

    [[nodiscard]] BYTE* data() noexcept { return bytes_.data(); }
    [[nodiscard]] const BYTE* data() const noexcept { return bytes_.data(); }
    [[nodiscard]] std::size_t capacity() const noexcept { return bytes_.size(); }

  private:
    std::vector<BYTE> bytes_;
};

[[nodiscard]] bool PromptUsernameMatches(
    const AccountIdentity& account, std::wstring_view username, std::wstring_view domain)
{
    std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> computerName {};
    DWORD computerNameCharacters = static_cast<DWORD>(computerName.size());
    if (!GetComputerNameW(computerName.data(), &computerNameCharacters))
    {
        return false;
    }

    const std::wstring expectedComputerAccount =
        std::wstring(computerName.data(), computerNameCharacters) + L"\\" + account.username;
    const std::wstring suppliedUsername(username);
    if (domain.empty() &&
        (_wcsicmp(suppliedUsername.c_str(), account.qualifiedUsername.c_str()) == 0 ||
            _wcsicmp(suppliedUsername.c_str(), expectedComputerAccount.c_str()) == 0))
    {
        return true;
    }
    if (_wcsicmp(suppliedUsername.c_str(), account.username.c_str()) != 0)
    {
        return false;
    }
    return domain.empty() || domain == L"." ||
           _wcsicmp(std::wstring(domain).c_str(), computerName.data()) == 0;
}

[[nodiscard]] CredentialPromptResult UnpackPromptResult(
    const AccountIdentity& account, const AuthenticationBuffer& packed, SecretBuffer& password)
{
    std::array<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> username {};
    std::array<wchar_t, CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1> domain {};
    DWORD usernameCharacters = static_cast<DWORD>(username.size());
    DWORD domainCharacters = static_cast<DWORD>(domain.size());
    DWORD passwordCharacters = static_cast<DWORD>(password.capacity());
    if (!CredUnPackAuthenticationBufferW(0,
            packed.get(),
            packed.size(),
            username.data(),
            &usernameCharacters,
            domain.data(),
            &domainCharacters,
            password.data(),
            &passwordCharacters))
    {
        const DWORD unpackError = GetLastError();
        std::wcerr << L"Could not unpack the supplied credential: "
                   << FormatWindowsError(unpackError) << L"\n";
        return CredentialPromptResult::Error;
    }

    if (!PromptUsernameMatches(account, username.data(), domain.data()))
    {
        std::wcerr << L"Credential entry must remain fixed to " << account.qualifiedUsername
                   << L".\n";
        return CredentialPromptResult::Error;
    }

    std::size_t passwordLength = 0;
    while (passwordLength < password.capacity() && password.data()[passwordLength] != L'\0')
    {
        ++passwordLength;
    }
    if (passwordLength == 0 || !password.set_length(passwordLength))
    {
        std::wcerr << L"Password cannot be empty or exceed " << password.capacity() - 1
                   << L" characters.\n";
        return CredentialPromptResult::Error;
    }
    return CredentialPromptResult::Success;
}

} // namespace

CredentialPromptResult PromptForPassword(
    const AccountIdentity& account, SecretBuffer& password, bool offerPersistence, bool& persist)
{
    std::wstring inputUsername = account.qualifiedUsername;
    std::array<wchar_t, 1> emptyPassword {L'\0'};
    DWORD inputBufferBytes = 0;
    CredPackAuthenticationBufferW(
        0, inputUsername.data(), emptyPassword.data(), nullptr, &inputBufferBytes);
    const DWORD inputBufferError = GetLastError();
    if (inputBufferError != ERROR_INSUFFICIENT_BUFFER || inputBufferBytes == 0)
    {
        std::wcerr << L"Could not prepare Windows Credential UI: "
                   << FormatWindowsError(inputBufferError) << L"\n";
        return CredentialPromptResult::Error;
    }

    std::vector<BYTE> inputBuffer(inputBufferBytes);
    if (!CredPackAuthenticationBufferW(
            0, inputUsername.data(), emptyPassword.data(), inputBuffer.data(), &inputBufferBytes))
    {
        const DWORD packError = GetLastError();
        std::wcerr << L"Could not prepare Windows Credential UI: " << FormatWindowsError(packError)
                   << L"\n";
        return CredentialPromptResult::Error;
    }

    const std::wstring message = L"Enter the password for " + account.qualifiedUsername +
                                 L". The launcher will reject administrative accounts.";
    CREDUI_INFOW uiInfo {};
    uiInfo.cbSize = sizeof(uiInfo);
    uiInfo.pszCaptionText = L"launch-as";
    uiInfo.pszMessageText = message.c_str();

    ULONG authenticationPackage = 0;
    AuthenticationBuffer outputBuffer;
    BOOL save = offerPersistence && persist ? TRUE : FALSE;
    DWORD flags = CREDUIWIN_GENERIC;
    if (offerPersistence)
    {
        flags |= CREDUIWIN_CHECKBOX;
    }
    const DWORD promptResult = CredUIPromptForWindowsCredentialsW(&uiInfo,
        0,
        &authenticationPackage,
        inputBuffer.data(),
        inputBufferBytes,
        outputBuffer.address(),
        outputBuffer.size_address(),
        offerPersistence ? &save : nullptr,
        flags);
    SecureZeroMemory(inputBuffer.data(), inputBuffer.size());
    if (promptResult == ERROR_CANCELLED)
    {
        return CredentialPromptResult::Cancelled;
    }
    if (promptResult != ERROR_SUCCESS)
    {
        std::wcerr << L"Windows Credential UI failed: " << FormatWindowsError(promptResult)
                   << L"\n";
        return CredentialPromptResult::Error;
    }

    persist = save != FALSE;
    return UnpackPromptResult(account, outputBuffer, password);
}

bool ReadPasswordFromStandardInput(SecretBuffer& password)
{
    const HANDLE standardInput = GetStdHandle(STD_INPUT_HANDLE);
    if (standardInput == nullptr || standardInput == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Password input requires redirected standard input.\n";
        return false;
    }

    DWORD consoleMode = 0;
    if (GetConsoleMode(standardInput, &consoleMode))
    {
        std::wcerr << L"--password-stdin requires redirected standard input; "
                      L"it will not echo a password typed into a console.\n";
        return false;
    }

    const std::size_t maximumUtf8Bytes = (password.capacity() - 1) * 4;
    SensitiveBytes input(maximumUtf8Bytes + 3);
    std::size_t bytesRead = 0;
    while (bytesRead < input.capacity())
    {
        DWORD chunkBytes = 0;
        if (!ReadFile(standardInput,
                input.data() + bytesRead,
                static_cast<DWORD>(input.capacity() - bytesRead),
                &chunkBytes,
                nullptr))
        {
            const DWORD readError = GetLastError();
            if (readError == ERROR_BROKEN_PIPE)
            {
                break;
            }
            std::wcerr << L"Could not read password from standard input: "
                       << FormatWindowsError(readError) << L"\n";
            return false;
        }
        if (chunkBytes == 0)
        {
            break;
        }
        bytesRead += chunkBytes;
    }

    BYTE overflowByte = 0;
    DWORD overflowBytes = 0;
    if (bytesRead == input.capacity())
    {
        const BOOL overflowRead =
            ReadFile(standardInput, &overflowByte, 1, &overflowBytes, nullptr);
        const DWORD overflowError = overflowRead ? ERROR_SUCCESS : GetLastError();
        if ((overflowRead && overflowBytes != 0) ||
            (!overflowRead && overflowError != ERROR_BROKEN_PIPE))
        {
            SecureZeroMemory(&overflowByte, sizeof(overflowByte));
            std::wcerr << L"Password input exceeds the supported length.\n";
            return false;
        }
    }
    SecureZeroMemory(&overflowByte, sizeof(overflowByte));

    if (bytesRead >= 3 && input.data()[0] == 0xEF && input.data()[1] == 0xBB &&
        input.data()[2] == 0xBF)
    {
        std::memmove(input.data(), input.data() + 3, bytesRead - 3);
        bytesRead -= 3;
    }
    if (bytesRead > 0 && input.data()[bytesRead - 1] == '\n')
    {
        --bytesRead;
    }
    if (bytesRead > 0 && input.data()[bytesRead - 1] == '\r')
    {
        --bytesRead;
    }
    if (bytesRead == 0 ||
        std::find(input.data(), input.data() + bytesRead, static_cast<BYTE>('\0')) !=
            input.data() + bytesRead ||
        std::find(input.data(), input.data() + bytesRead, static_cast<BYTE>('\r')) !=
            input.data() + bytesRead ||
        std::find(input.data(), input.data() + bytesRead, static_cast<BYTE>('\n')) !=
            input.data() + bytesRead)
    {
        std::wcerr << L"Password input must contain exactly one non-empty UTF-8 line.\n";
        return false;
    }

    const int requiredCharacters = MultiByteToWideChar(CP_UTF8,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(input.data()),
        static_cast<int>(bytesRead),
        nullptr,
        0);
    if (requiredCharacters <= 0 ||
        static_cast<std::size_t>(requiredCharacters) >= password.capacity())
    {
        std::wcerr << L"Password input is not valid UTF-8 or exceeds the supported length.\n";
        return false;
    }
    if (MultiByteToWideChar(CP_UTF8,
            MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(input.data()),
            static_cast<int>(bytesRead),
            password.data(),
            requiredCharacters) != requiredCharacters ||
        !password.set_length(static_cast<std::size_t>(requiredCharacters)))
    {
        std::wcerr << L"Could not decode password input.\n";
        return false;
    }
    return true;
}

} // namespace launch_as
