// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAccountProvisioner.h"
#include "BrokerEnrollmentStore.h"
#include "BrokerLogonToken.h"
#include "BrokerPassword.h"
#include "BrokerRegistration.h"
#include "Win32Support.h"

#include <Lm.h>
#include <Windows.h>
#include <array>
#include <iostream>
#include <ntsecapi.h>
#include <string>
#include <vector>

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
            const std::wstring search = path_ + L"\\*";
            WIN32_FIND_DATAW file {};
            HANDLE find = FindFirstFileW(search.c_str(), &file);
            if (find != INVALID_HANDLE_VALUE)
            {
                do
                {
                    if ((file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        DeleteFileW((path_ + L"\\" + file.cFileName).c_str());
                    }
                } while (FindNextFileW(find, &file));
                FindClose(find);
            }
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

[[nodiscard]] bool IsAccountDisabled(const std::wstring& name)
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
    const bool disabled = (user->usri4_flags & UF_ACCOUNTDISABLE) != 0;
    NetApiBufferFree(buffer);
    return disabled;
}

[[nodiscard]] bool EnableAccount(const std::wstring& name)
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
    USER_INFO_1008 flags {};
    flags.usri1008_flags = user->usri4_flags & ~UF_ACCOUNTDISABLE;
    NetApiBufferFree(buffer);
    return NetUserSetInfo(nullptr, name.c_str(), 1008, reinterpret_cast<LPBYTE>(&flags), nullptr) ==
           NERR_Success;
}

void InitLsaString(LSA_UNICODE_STRING& lsaString, const wchar_t* value)
{
    const size_t length = wcslen(value);
    lsaString.Buffer = const_cast<wchar_t*>(value);
    lsaString.Length = static_cast<USHORT>(length * sizeof(wchar_t));
    lsaString.MaximumLength = static_cast<USHORT>((length + 1) * sizeof(wchar_t));
}

// Whether Backup-Operators membership actually confers SeBackupPrivilege depends on the local or
// domain "User Rights Assignment" policy, which varies by machine (e.g. a hardened GPO baseline).
// Granting the right directly is deterministic and exercises the broker's account-right admission
// check even when a local policy does not project the right into an interactive token.
[[nodiscard]] bool SetBackupPrivilege(PSID accountSid, bool grant)
{
    LSA_OBJECT_ATTRIBUTES objectAttributes {};
    LSA_HANDLE policyHandle = nullptr;
    if (LsaOpenPolicy(nullptr, &objectAttributes, POLICY_ALL_ACCESS, &policyHandle) != 0)
    {
        return false;
    }
    LSA_UNICODE_STRING privilegeName {};
    InitLsaString(privilegeName, SE_BACKUP_NAME);
    const NTSTATUS status =
        grant ? LsaAddAccountRights(policyHandle, accountSid, &privilegeName, 1)
              : LsaRemoveAccountRights(policyHandle, accountSid, FALSE, &privilegeName, 1);
    LsaClose(policyHandle);
    return status == 0;
}

} // namespace

int wmain()
{
    if (!Expect(!launch_as::broker::IsValidBrokerAccountName(L"invalid\naccount"),
            L"Broker account validation accepted a control character."))
    {
        return 1;
    }
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
    const DWORD initialRegistrationError = registration.Enroll(account.name());
    if (!Expect(initialRegistrationError == ERROR_SUCCESS,
            L"Could not register the disposable local account."))
    {
        std::wcerr << L"Registration status: " << initialRegistrationError << L"\n";
        return 1;
    }
    launch_as::broker::SecurePassword password;
    const DWORD passwordError = launch_as::broker::GenerateBrokerPassword(password);
    const DWORD resetError = passwordError == ERROR_SUCCESS
                                 ? registration.ResetPassword(account.name(), password)
                                 : passwordError;
    launch_as::broker::BrokerLogonToken token;
    const DWORD brokerTokenError =
        resetError == ERROR_SUCCESS
            ? launch_as::broker::LogOnBrokerAccount(account.name(), password, token)
            : resetError;
    password.Clear();
    launch_as::broker::EnrollmentStore enrollments(credentialDirectory.path());
    std::vector<BYTE> enrolledSid;
    if (!Expect(HasRequiredFlags(account.name()), L"Disposable account flags are not hardened.") ||
        !Expect(enrollments.Load(account.name(), enrolledSid) == ERROR_SUCCESS,
            L"Enrollment did not retain the account identity.") ||
        !Expect(brokerTokenError == ERROR_SUCCESS && static_cast<bool>(token),
            L"Active disposable account password did not produce a valid broker token."))
    {
        std::wcerr << L"Broker token status: " << brokerTokenError << L"\n";
        return 1;
    }

    if (!Expect(registration.Unenroll(account.name()) == ERROR_SUCCESS,
            L"Could not unenroll the disposable account.") ||
        !Expect(enrollments.Load(account.name(), enrolledSid) == ERROR_FILE_NOT_FOUND,
            L"Unenrollment retained the account enrollment.") ||
        !Expect(IsAccountDisabled(account.name()), L"Unenrollment did not disable the account."))
    {
        return 1;
    }

    if (!Expect(EnableAccount(account.name()),
            L"Could not re-enable the unregistered disposable account.") ||
        !Expect(registration.Unenroll(account.name()) == ERROR_NOT_FOUND,
            L"Broker unenrolled an account without a registration.") ||
        !Expect(!IsAccountDisabled(account.name()),
            L"Broker disabled an account without a registration."))
    {
        return 1;
    }

    if (!Expect(registration.Enroll(account.name()) == ERROR_SUCCESS,
            L"Could not re-enroll the disposable account.") ||
        !Expect(enrollments.Load(account.name(), enrolledSid) == ERROR_SUCCESS,
            L"Re-enrollment did not restore the account enrollment.") ||
        !Expect(account.Remove() == NERR_Success,
            L"Could not externally remove the disposable account.") ||
        !Expect(launch_as::broker::GenerateBrokerPassword(password) == ERROR_SUCCESS,
            L"Could not generate a disposable password for the missing-account check.") ||
        !Expect(registration.ResetPassword(account.name(), password) != ERROR_SUCCESS,
            L"Broker password reset recreated a missing enrolled account.") ||
        !Expect(launch_as::broker::ProvisionStandardLocalAccount(account.name(), password) ==
                    ERROR_SUCCESS,
            L"Could not recreate the account with its original name."))
    {
        return 1;
    }
    password.Clear();
    account.MarkCreated();
    std::vector<std::wstring> accounts;
    if (!Expect(registration.Unenroll(account.name()) == ERROR_ACCESS_DENIED,
            L"Broker unenrolled a replacement account with a different SID.") ||
        !Expect(!IsAccountDisabled(account.name()),
            L"Broker disabled a replacement account with a different SID.") ||
        !Expect(registration.List(accounts) == ERROR_SUCCESS && accounts.empty(),
            L"Broker listed an enrollment whose account SID had changed.") ||
        !Expect(registration.Enroll(account.name()) == ERROR_SUCCESS,
            L"Could not re-enroll the replacement account.") ||
        !Expect(registration.Unenroll(account.name()) == ERROR_SUCCESS,
            L"Could not unenroll the re-enrolled replacement account."))
    {
        return 1;
    }

    // An account with a directly assigned privilege beyond the standard allow-list must be
    // rejected, even when local policy does not project it into the interactive token and the
    // Administrators-only membership check never sees it.
    // Local SAM account names are capped at 20 characters regardless of UNLEN, so this mirrors
    // the disposable account's naming budget above rather than adding a longer distinguishing
    // infix.
    TestAccount privilegedAccount(L"lac" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                  std::to_wstring(GetTickCount() % 100'000'000));
    if (!Expect(AccountDoesNotExist(privilegedAccount.name()),
            L"The privileged disposable account name is already in use."))
    {
        return 1;
    }
    launch_as::broker::RegistrationService privilegedRegistration(credentialDirectory.path());
    privilegedAccount.MarkCreated();
    const DWORD privilegedRegistrationError =
        privilegedRegistration.Enroll(privilegedAccount.name());
    if (!Expect(privilegedRegistrationError == ERROR_SUCCESS,
            L"Could not register the privileged disposable account."))
    {
        std::wcerr << L"Registration status: " << privilegedRegistrationError << L"\n";
        return 1;
    }
    std::vector<BYTE> privilegedAccountSid;
    if (!Expect(launch_as::broker::GetBrokerAccountSid(
                    privilegedAccount.name(), privilegedAccountSid) == ERROR_SUCCESS,
            L"Could not resolve the privileged disposable account SID."))
    {
        return 1;
    }
    if (!Expect(SetBackupPrivilege(privilegedAccountSid.data(), true),
            L"Could not grant SeBackupPrivilege to the disposable account."))
    {
        return 1;
    }
    launch_as::broker::SecurePassword privilegedPassword;
    const DWORD privilegedPasswordError =
        launch_as::broker::GenerateBrokerPassword(privilegedPassword);
    const DWORD privilegedResetError =
        privilegedPasswordError == ERROR_SUCCESS
            ? privilegedRegistration.ResetPassword(privilegedAccount.name(), privilegedPassword)
            : privilegedPasswordError;
    launch_as::broker::BrokerLogonToken privilegedToken;
    const DWORD privilegedLogonError =
        privilegedResetError == ERROR_SUCCESS
            ? launch_as::broker::LogOnBrokerAccount(
                  privilegedAccount.name(), privilegedPassword, privilegedToken)
            : privilegedResetError;
    privilegedPassword.Clear();
    static_cast<void>(SetBackupPrivilege(privilegedAccountSid.data(), false));
    if (!Expect(privilegedResetError == ERROR_SUCCESS,
            L"Could not reset the password for the disposable SeBackupPrivilege account.") ||
        !Expect(privilegedLogonError == ERROR_ACCESS_DENIED && !static_cast<bool>(privilegedToken),
            L"Broker minted a usable token for an account holding SeBackupPrivilege."))
    {
        std::wcerr << L"Privileged logon status: " << privilegedLogonError << L"\n";
        return 1;
    }

    return 0;
}
