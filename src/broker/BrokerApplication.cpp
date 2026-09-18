// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerApplication.h"

#include "BrokerAudit.h"
#include "BrokerCallerPolicy.h"
#include "BrokerLogonToken.h"
#include "BrokerPassword.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <cwchar>
#include <sddl.h>
#include <utility>

namespace launch_as::broker
{
namespace
{

constexpr std::size_t MaximumConcurrentSessions = 4;
constexpr std::size_t MaximumConcurrentSessionsPerAccount = 2;

using LocalString = LocalAllocation<PWSTR>;

[[nodiscard]] std::wstring AuditCallerSid(const BrokerCallerIdentity& caller)
{
    if (caller.userSid.empty() || !IsValidSid(const_cast<BYTE*>(caller.userSid.data())))
    {
        return L"unknown";
    }
    LocalString value;
    if (!ConvertSidToStringSidW(const_cast<BYTE*>(caller.userSid.data()), value.address()))
    {
        return L"unknown";
    }
    return value.get();
}

[[nodiscard]] std::wstring AuditProfileId(std::wstring_view fieldName, std::wstring_view profileId)
{
    const std::wstring_view value = IsValidProfileId(profileId) ? profileId : L"<invalid>";
    return std::wstring(fieldName) + L"=" + std::wstring(value);
}

void AuditRequest(BrokerAuditEvent event, WORD type, const BrokerRequest& request,
    const BrokerCallerIdentity& caller, DWORD result, DWORD processId = 0)
{
    const std::vector<std::wstring> fields {
        L"requestId=" + request.requestId,
        L"operation=" + std::wstring(RequestOperationName(request.operation)),
        AuditProfileId(L"account", request.profileId),
        L"callerSid=" + AuditCallerSid(caller),
        L"callerSession=" + std::to_wstring(caller.sessionId),
        L"result=" + std::wstring(result == ERROR_SUCCESS ? L"allowed" : L"rejected"),
        L"processId=" + std::to_wstring(processId),
        L"win32Error=" + std::to_wstring(result),
    };
    static_cast<void>(WriteBrokerAuditEvent(type, event, fields));
}

} // namespace

BrokerApplication::BrokerApplication(
    std::wstring_view enrollmentDirectory, std::vector<BYTE> authorizedCallerSid)
    : authorizedCallerSid_(std::move(authorizedCallerSid)), registration_(enrollmentDirectory)
{
}

const std::vector<BYTE>& BrokerApplication::authorizedCallerSid() const noexcept
{
    return authorizedCallerSid_;
}

bool BrokerApplication::AccountNameLess::operator()(
    const std::wstring& left, const std::wstring& right) const noexcept
{
    return _wcsicmp(left.c_str(), right.c_str()) < 0;
}

bool BrokerApplication::TryReserveSession(std::wstring_view accountName)
{
    std::lock_guard lock(sessionMutex_);
    if (sessionCount_ >= MaximumConcurrentSessions)
    {
        return false;
    }
    const auto existing = sessionsByAccount_.find(std::wstring(accountName));
    if (existing != sessionsByAccount_.end() &&
        existing->second >= MaximumConcurrentSessionsPerAccount)
    {
        return false;
    }
    ++sessionsByAccount_[std::wstring(accountName)];
    ++sessionCount_;
    return true;
}

void BrokerApplication::ReleaseSession(std::wstring_view accountName)
{
    std::lock_guard lock(sessionMutex_);
    const auto existing = sessionsByAccount_.find(std::wstring(accountName));
    if (existing == sessionsByAccount_.end() || existing->second == 0)
    {
        return;
    }
    --existing->second;
    --sessionCount_;
    if (existing->second == 0)
    {
        sessionsByAccount_.erase(existing);
    }
}

bool BrokerApplication::HasActiveSession(std::wstring_view accountName)
{
    std::lock_guard lock(sessionMutex_);
    const auto existing = sessionsByAccount_.find(std::wstring(accountName));
    return existing != sessionsByAccount_.end() && existing->second != 0;
}

DWORD BrokerApplication::Configure(const BrokerRequest& request, const BrokerCallerIdentity& caller,
    std::vector<std::wstring>& accounts)
{
    const auto complete = [&](DWORD result)
    {
        AuditRequest(result == ERROR_SUCCESS ? BrokerAuditEvent::ConfigurationChanged
                                             : BrokerAuditEvent::ConfigurationRejected,
            result == ERROR_SUCCESS ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE,
            request,
            caller,
            result);
        return result;
    };
    if (!IsAuthorizedCaller(authorizedCallerSid_, caller.userSid))
    {
        return complete(ERROR_ACCESS_DENIED);
    }
    std::lock_guard launchLock(launchMutex_);
    if (request.operation == RequestOperation::List)
    {
        return complete(registration_.List(accounts));
    }
    if (!request.confirmed)
    {
        return complete(ERROR_CANCELLED);
    }
    if (!caller.isElevated)
    {
        return complete(ERROR_ELEVATION_REQUIRED);
    }
    if (request.operation == RequestOperation::Create)
    {
        return complete(registration_.Create(request.profileId));
    }
    if (request.operation == RequestOperation::TakeOver)
    {
        return complete(registration_.TakeOver(request.profileId, request.force));
    }
    if (request.operation == RequestOperation::Forget)
    {
        return complete(registration_.Forget(request.profileId));
    }
    if (request.operation == RequestOperation::Delete)
    {
        return complete(HasActiveSession(request.profileId)
                            ? ERROR_BUSY
                            : registration_.Delete(request.profileId));
    }
    return complete(ERROR_INVALID_PARAMETER);
}

DWORD BrokerApplication::Launch(
    const BrokerRequest& request, const BrokerCallerIdentity& caller, BrokerChildProcess& child)
{
    bool sessionReserved = false;
    const auto complete = [&](DWORD result)
    {
        if (result != ERROR_SUCCESS && sessionReserved)
        {
            ReleaseSession(request.profileId);
            sessionReserved = false;
        }
        AuditRequest(result == ERROR_SUCCESS ? BrokerAuditEvent::LaunchAllowed
                                             : BrokerAuditEvent::LaunchRejected,
            result == ERROR_SUCCESS ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE,
            request,
            caller,
            result,
            child.processId());
        return result;
    };
    if (request.operation != RequestOperation::ConsoleLaunch ||
        !IsAuthorizedCaller(authorizedCallerSid_, caller.userSid))
    {
        return complete(ERROR_ACCESS_DENIED);
    }
    if (request.arguments.empty())
    {
        return complete(ERROR_INVALID_PARAMETER);
    }
    if (!TryReserveSession(request.profileId))
    {
        return complete(ERROR_BUSY);
    }
    sessionReserved = true;
    std::lock_guard launchLock(launchMutex_);
    SecurePassword password;
    const DWORD passwordError = GenerateBrokerPassword(password);
    if (passwordError != ERROR_SUCCESS)
    {
        return complete(passwordError);
    }
    const DWORD resetError = registration_.ResetPassword(request.profileId, password);
    if (resetError != ERROR_SUCCESS)
    {
        password.Clear();
        return complete(resetError);
    }
    BrokerLogonToken token;
    const DWORD logonError = LogOnBrokerAccount(request.profileId, password, token);
    password.Clear();
    if (logonError != ERROR_SUCCESS)
    {
        return complete(logonError);
    }
    std::vector<std::wstring> conhostArguments {
        L"--internal-pseudoconsole-host",
        L"--size",
        std::to_wstring(request.console.columns),
        std::to_wstring(request.console.rows),
    };
    if (request.console.inheritCursor)
    {
        conhostArguments.emplace_back(L"--inherit-cursor");
    }
    conhostArguments.insert(conhostArguments.end(),
        {L"--pipe-in",
            request.console.pipeIn,
            L"--pipe-out",
            request.console.pipeOut,
            L"--pipe-resize",
            request.console.pipeResize,
            L"--"});
    conhostArguments.insert(
        conhostArguments.end(), request.arguments.begin(), request.arguments.end());
    const DWORD launchError = LaunchBrokerConsoleHost(
        token.get(), request.profileId, conhostArguments, request.workingDirectory, child);
    if (launchError != ERROR_SUCCESS)
    {
        return complete(launchError);
    }
    const DWORD validationError = ValidateChildLogonSid(child.process(), caller.logonSid);
    if (validationError != ERROR_SUCCESS)
    {
        static_cast<void>(child.TerminateAndWaitForExit());
        return complete(validationError);
    }
    const DWORD resumeError = child.Resume();
    if (resumeError != ERROR_SUCCESS)
    {
        static_cast<void>(child.TerminateAndWaitForExit());
    }
    return complete(resumeError);
}

void BrokerApplication::FinishSession(const BrokerRequest& request, bool processTreeExited)
{
    ReleaseSession(request.profileId);
    if (!processTreeExited)
    {
        const std::array<std::wstring, 3> fields {
            L"operation=launch",
            AuditProfileId(L"profileId", request.profileId),
            L"reason=process_tree_not_confirmed",
        };
        static_cast<void>(WriteBrokerAuditEvent(
            EVENTLOG_ERROR_TYPE, BrokerAuditEvent::SessionTeardownFailed, fields));
    }
}

} // namespace launch_as::broker
