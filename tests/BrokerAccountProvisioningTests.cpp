// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerLogonToken.h"
#include "BrokerRegistration.h"
#include "Win32Support.h"

#include <Lm.h>
#include <Windows.h>
#include <array>
#include <iostream>
#include <string>

namespace
{

class TestAccount final
{
  public:
    explicit TestAccount(std::wstring name) : name_(std::move(name)) {}

    ~TestAccount()
    {
        if (created_)
        {
            NetUserDel(nullptr, name_.c_str());
        }
    }

    [[nodiscard]] const std::wstring& name() const noexcept { return name_; }
    void MarkCreated() noexcept { created_ = true; }
    [[nodiscard]] NET_API_STATUS Remove() noexcept
    {
        if (!created_)
        {
            return NERR_Success;
        }
        const NET_API_STATUS status = NetUserDel(nullptr, name_.c_str());
        if (status == NERR_Success)
        {
            created_ = false;
        }
        return status;
    }

  private:
    std::wstring name_;
    bool created_ = false;
};

class TemporaryDirectory final
{
  public:
    TemporaryDirectory()
    {
        std::array<wchar_t, MAX_PATH> temporaryPath {};
        const DWORD length =
            GetTempPathW(static_cast<DWORD>(temporaryPath.size()), temporaryPath.data());
        if (length == 0 || length >= temporaryPath.size())
        {
            return;
        }
        path_ = std::wstring(temporaryPath.data(), length) + L"launch-as-register-" +
                std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount());
        created_ = CreateDirectoryW(path_.c_str(), nullptr) != FALSE;
    }

    ~TemporaryDirectory()
    {
        if (created_)
        {
            DeleteFileW((path_ + L"\\agent-sandbox.blob").c_str());
            DeleteFileW((path_ + L"\\agent-sandbox.blob.tmp").c_str());
            RemoveDirectoryW(path_.c_str());
        }
    }

    [[nodiscard]] bool created() const noexcept { return created_; }
    [[nodiscard]] std::wstring_view path() const noexcept { return path_; }

  private:
    std::wstring path_;
    bool created_ = false;
};

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] bool AccountDoesNotExist(const std::wstring& name)
{
    LPBYTE buffer = nullptr;
    const NET_API_STATUS status = NetUserGetInfo(nullptr, name.c_str(), 0, &buffer);
    if (buffer != nullptr)
    {
        NetApiBufferFree(buffer);
    }
    return status == NERR_UserNotFound;
}

[[nodiscard]] bool HasRequiredFlags(const std::wstring& name)
{
    LPBYTE buffer = nullptr;
    const NET_API_STATUS status = NetUserGetInfo(nullptr, name.c_str(), 4, &buffer);
    if (status != NERR_Success || buffer == nullptr)
    {
        if (buffer != nullptr)
        {
            NetApiBufferFree(buffer);
        }
        return false;
    }
    const auto* user = reinterpret_cast<const USER_INFO_4*>(buffer);
    const DWORD requiredFlags = UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE;
    const bool hasFlags = (user->usri4_flags & requiredFlags) == requiredFlags;
    NetApiBufferFree(buffer);
    return hasFlags;
}

} // namespace

int wmain()
{
    TestAccount account(L"lab" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                        std::to_wstring(GetTickCount() % 100'000'000));
    if (!Expect(
            AccountDoesNotExist(account.name()), L"The disposable account name is already in use."))
    {
        return 1;
    }

    TemporaryDirectory credentialDirectory;
    if (!Expect(credentialDirectory.created(),
            L"Could not create the disposable credential directory."))
    {
        return 1;
    }

    launch_as::broker::RegistrationService registration(credentialDirectory.path());
    account.MarkCreated();
    const DWORD initialRegistrationError = registration.Register(account.name());
    if (!Expect(initialRegistrationError == ERROR_SUCCESS,
            L"Could not register the disposable local account."))
    {
        std::wcerr << L"Registration status: " << initialRegistrationError << L"\n";
        return 1;
    }
    const DWORD rotationRegistrationError = registration.Register(account.name());
    if (!Expect(rotationRegistrationError == ERROR_SUCCESS,
            L"Could not rotate the disposable account password."))
    {
        std::wcerr << L"Rotation status: " << rotationRegistrationError << L"\n";
        return 1;
    }
    launch_as::broker::CredentialStore store(credentialDirectory.path());
    launch_as::broker::SecurePassword storedPassword;
    launch_as::broker::BrokerLogonToken token;
    const DWORD brokerTokenError =
        launch_as::broker::LogOnBrokerProfile(account.name(), account.name(), store, token);
    if (!Expect(HasRequiredFlags(account.name()), L"Disposable account flags are not hardened.") ||
        !Expect(store.Load(account.name(), storedPassword) == ERROR_SUCCESS,
            L"Could not load the stored disposable account password.") ||
        !Expect(brokerTokenError == ERROR_SUCCESS && static_cast<bool>(token),
            L"Rotated disposable account password did not produce a valid broker token."))
    {
        std::wcerr << L"Broker token status: " << brokerTokenError << L"\n";
        return 1;
    }
    const NET_API_STATUS removalStatus = account.Remove();
    if (!Expect(removalStatus == NERR_Success, L"Could not remove the disposable local account."))
    {
        std::wcerr << L"Cleanup status: " << removalStatus << L"\n";
        return 1;
    }
    return 0;
}
