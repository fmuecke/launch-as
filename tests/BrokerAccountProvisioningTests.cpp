// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAccountProvisioner.h"
#include "BrokerEnrollmentStore.h"
#include "BrokerLogonToken.h"
#include "BrokerPassword.h"
#include "BrokerRegistration.h"
#include "TestSupport.h"
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

[[nodiscard]] bool HasManagedComment(const std::wstring& name)
{
    LPBYTE buffer = nullptr;
    const NET_API_STATUS status = NetUserGetInfo(nullptr, name.c_str(), 1, &buffer);
    if (status != NERR_Success || buffer == nullptr)
    {
        if (buffer != nullptr)
        {
            NetApiBufferFree(buffer);
        }
        return false;
    }
    const auto* user = reinterpret_cast<const USER_INFO_1*>(buffer);
    const bool managed = user->usri1_comment != nullptr &&
                         std::wstring_view(user->usri1_comment) == L"Managed by launch-as.";
    NetApiBufferFree(buffer);
    return managed;
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

[[nodiscard]] bool SetAccountDisabled(const std::wstring& name, bool disabled)
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
    flags.usri1008_flags =
        disabled ? user->usri4_flags | UF_ACCOUNTDISABLE : user->usri4_flags & ~UF_ACCOUNTDISABLE;
    NetApiBufferFree(buffer);
    return NetUserSetInfo(nullptr, name.c_str(), 1008, reinterpret_cast<LPBYTE>(&flags), nullptr) ==
           NERR_Success;
}

[[nodiscard]] bool EnableAccount(const std::wstring& name)
{
    return SetAccountDisabled(name, false);
}

[[nodiscard]] bool DisableAccount(const std::wstring& name)
{
    return SetAccountDisabled(name, true);
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

[[nodiscard]] bool IsMediumIntegrityToken(HANDLE token)
{
    DWORD integrityBytes = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &integrityBytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || integrityBytes == 0)
    {
        return false;
    }
    std::vector<BYTE> integrityBuffer(integrityBytes);
    if (!GetTokenInformation(
            token, TokenIntegrityLevel, integrityBuffer.data(), integrityBytes, &integrityBytes))
    {
        return false;
    }
    const auto* integrity = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrityBuffer.data());
    if (!IsValidSid(integrity->Label.Sid))
    {
        return false;
    }
    const PUCHAR subAuthorityCount = GetSidSubAuthorityCount(integrity->Label.Sid);
    if (subAuthorityCount == nullptr || *subAuthorityCount == 0)
    {
        return false;
    }
    const PDWORD integrityRid =
        GetSidSubAuthority(integrity->Label.Sid, static_cast<DWORD>(*subAuthorityCount - 1));
    return integrityRid != nullptr && *integrityRid == SECURITY_MANDATORY_MEDIUM_RID;
}

[[nodiscard]] bool HasNoUnexpectedEnabledPrivileges(HANDLE token)
{
    LUID changeNotifyPrivilege {};
    if (!LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &changeNotifyPrivilege))
    {
        return false;
    }
    DWORD privilegesBytes = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &privilegesBytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || privilegesBytes == 0)
    {
        return false;
    }
    std::vector<BYTE> privilegesBuffer(privilegesBytes);
    if (!GetTokenInformation(
            token, TokenPrivileges, privilegesBuffer.data(), privilegesBytes, &privilegesBytes))
    {
        return false;
    }
    const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(privilegesBuffer.data());
    for (DWORD index = 0; index < privileges->PrivilegeCount; ++index)
    {
        const LUID_AND_ATTRIBUTES& privilege = privileges->Privileges[index];
        const bool isChangeNotify = privilege.Luid.LowPart == changeNotifyPrivilege.LowPart &&
                                    privilege.Luid.HighPart == changeNotifyPrivilege.HighPart;
        if ((privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0 && !isChangeNotify)
        {
            return false;
        }
    }
    return true;
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
    const DWORD initialRegistrationError = registration.Create(account.name());
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
    launch_as::broker::EnrollmentRecord enrollment;
    if (!Expect(HasRequiredFlags(account.name()), L"Disposable account flags are not hardened.") ||
        !Expect(HasManagedComment(account.name()),
            L"Created account did not receive the managed-account comment.") ||
        !Expect(enrollments.Load(account.name(), enrollment) == ERROR_SUCCESS &&
                    enrollment.brokerManaged,
            L"Created account enrollment was not marked broker-managed.") ||
        !Expect(brokerTokenError == ERROR_SUCCESS && static_cast<bool>(token),
            L"Active disposable account password did not produce a valid broker token.") ||
        !Expect(IsMediumIntegrityToken(token.get()), L"Broker token is not at Medium integrity.") ||
        !Expect(HasNoUnexpectedEnabledPrivileges(token.get()),
            L"Broker token retained an unexpected enabled privilege."))
    {
        std::wcerr << L"Broker token status: " << brokerTokenError << L"\n";
        return 1;
    }

    if (!Expect(
            DisableAccount(account.name()), L"Could not disable the managed disposable account.") ||
        !Expect(registration.TakeOver(account.name(), true) == ERROR_SUCCESS,
            L"Broker could not re-enable its managed account.") ||
        !Expect(
            !IsAccountDisabled(account.name()), L"Broker did not re-enable its managed account.") ||
        !Expect(HasManagedComment(account.name()),
            L"Managed account refresh did not retain the managed-account comment."))
    {
        return 1;
    }

    if (!Expect(registration.Forget(account.name()) == ERROR_SUCCESS,
            L"Could not forget the disposable account.") ||
        !Expect(enrollments.Load(account.name(), enrollment) == ERROR_FILE_NOT_FOUND,
            L"Forget retained the account registration.") ||
        !Expect(!IsAccountDisabled(account.name()), L"Forget changed the account state."))
    {
        return 1;
    }

    if (!Expect(DisableAccount(account.name()), L"Could not disable the forgotten account.") ||
        !Expect(registration.TakeOver(account.name(), false) == ERROR_ACCOUNT_DISABLED,
            L"Broker re-enabled a disabled account without --force.") ||
        !Expect(IsAccountDisabled(account.name()),
            L"Failed takeover changed the disabled account state.") ||
        !Expect(registration.TakeOver(account.name(), true) == ERROR_SUCCESS,
            L"Forced takeover did not re-enable the disabled account.") ||
        !Expect(
            !IsAccountDisabled(account.name()), L"Forced takeover did not re-enable the account."))
    {
        return 1;
    }

    if (!Expect(registration.Create(account.name()) == ERROR_ALREADY_EXISTS,
            L"Create accepted an existing account.") ||
        !Expect(enrollments.Load(account.name(), enrollment) == ERROR_SUCCESS &&
                    enrollment.brokerManaged,
            L"Forced takeover did not mark the account broker-managed.") ||
        !Expect(account.Remove() == NERR_Success,
            L"Could not externally remove the disposable account.") ||
        !Expect(launch_as::broker::GenerateBrokerPassword(password) == ERROR_SUCCESS,
            L"Could not generate a disposable password for the missing-account check.") ||
        !Expect(registration.ResetPassword(account.name(), password) != ERROR_SUCCESS,
            L"Broker password reset recreated a missing enrolled account.") ||
        !Expect(launch_as::broker::CreateBrokerManagedLocalAccount(account.name(), password) ==
                    ERROR_SUCCESS,
            L"Could not recreate the account with its original name."))
    {
        return 1;
    }
    password.Clear();
    account.MarkCreated();
    std::vector<std::wstring> accounts;
    if (!Expect(registration.Delete(account.name()) == ERROR_ACCESS_DENIED,
            L"Broker deleted a replacement account with a different SID.") ||
        !Expect(!IsAccountDisabled(account.name()),
            L"Broker disabled a replacement account with a different SID.") ||
        !Expect(registration.List(accounts) == ERROR_SUCCESS && accounts.empty(),
            L"Broker listed an enrollment whose account SID had changed.") ||
        !Expect(registration.TakeOver(account.name(), false) == ERROR_ACCESS_DENIED,
            L"Broker reclaimed a replacement account without --force.") ||
        !Expect(registration.TakeOver(account.name(), true) == ERROR_SUCCESS,
            L"Forced takeover did not claim the replacement account.") ||
        !Expect(registration.Delete(account.name()) == ERROR_SUCCESS,
            L"Could not delete the taken-over replacement account.") ||
        !Expect(
            AccountDoesNotExist(account.name()), L"Delete did not remove the taken-over account."))
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
        privilegedRegistration.Create(privilegedAccount.name());
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
