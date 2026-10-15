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
    const BrokerCallerIdentity& caller, DWORD result, DWORD processId = 0,
    std::wstring_view readScopePath = {})
{
    const std::vector<std::wstring> fields {
        L"requestId=" + request.requestId,
        L"operation=" + std::wstring(RequestOperationName(request.operation)),
        AuditProfileId(L"account", request.profileId),
        L"callerSid=" + AuditCallerSid(caller),
        L"callerSession=" + std::to_wstring(caller.sessionId),
        L"restrictAccess=" + std::wstring(request.restrictAccess ? L"true" : L"false"),
        L"lowIntegrity=" + std::wstring(request.lowIntegrity ? L"true" : L"false"),
        L"log=" + std::wstring(request.log ? L"true" : L"false"),
        L"result=" + std::wstring(result == ERROR_SUCCESS ? L"allowed" : L"rejected"),
        L"processId=" + std::to_wstring(processId),
        L"win32Error=" + std::to_wstring(result),
        L"readScopePath=" + std::wstring(readScopePath),
    };
    static_cast<void>(WriteBrokerAuditEvent(type, event, fields));
}

void LogLaunchAction(std::wstring_view requestId, std::wstring_view account,
    std::wstring_view action, std::wstring_view path = {}, DWORD error = ERROR_SUCCESS)
{
    const std::array<std::wstring, 5> fields {
        L"requestId=" + std::wstring(requestId),
        L"account=" + std::wstring(account),
        L"action=" + std::wstring(action),
        L"path=" + std::wstring(path),
        L"win32Error=" + std::to_wstring(error)
    };
    static_cast<void>(WriteBrokerAuditEvent(
        error == ERROR_SUCCESS ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE,
        BrokerAuditEvent::LaunchDiagnostic,
        fields));
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

void BrokerApplication::ScopeLog::Join(std::wstring_view requestId)
{
    std::lock_guard lock(mutex);
    lastRequest = requestId;
    requests.emplace(requestId);
}

void BrokerApplication::ScopeLog::Leave(std::wstring_view requestId)
{
    std::lock_guard lock(mutex);
    requests.erase(std::wstring(requestId));
}

void BrokerApplication::ScopeLog::Record(
    std::wstring_view account, std::wstring_view action, std::wstring_view path, DWORD error)
{
    std::lock_guard lock(mutex);
    for (const auto& requestId : requests)
    {
        LogLaunchAction(requestId, account, action, path, error);
    }
    if (requests.empty() && !lastRequest.empty())
    {
        // Keep Event Log tracing after the final logging client leaves an otherwise live scope.
        LogLaunchAction(lastRequest, account, action, path, error);
    }
}

bool BrokerApplication::TryReserveSession(const BrokerRequest& request, BrokerReadScope*& readScope)
{
    const auto& accountName = request.profileId;
    std::lock_guard lock(sessionMutex_);
    if (sessionCount_ >= MaximumConcurrentSessions)
    {
        return false;
    }
    const auto existing = sessionsByAccount_.find(std::wstring(accountName));
    if (existing != sessionsByAccount_.end() &&
        (existing->second.count >= MaximumConcurrentSessionsPerAccount ||
            (existing->second.readScope != nullptr) != request.restrictAccess))
    {
        return false;
    }
    auto& sessions = sessionsByAccount_[std::wstring(accountName)];
    if (request.restrictAccess && !sessions.readScope)
    {
        sessions.readScope = std::make_unique<BrokerReadScope>();
    }
    // A failed restoration retains the scope and blocks reuse until restoration succeeds.
    if (sessions.count == 0 && sessions.readScope && sessions.readScope->Restore() != ERROR_SUCCESS)
    {
        return false;
    }
    if (sessions.readScope)
    {
        if (sessions.count == 0)
        {
            sessions.log = std::make_shared<ScopeLog>();
        }
        if (request.log)
        {
            sessions.log->Join(request.requestId);
        }
        sessions.readScope->SetObserver(
            [log = sessions.log, account = accountName](
                std::wstring_view action, std::wstring_view path, DWORD error)
            { log->Record(account, action, path, error); });
    }
    readScope = sessions.readScope.get();
    ++sessions.count;
    ++sessionCount_;
    return true;
}

DWORD BrokerApplication::ReleaseSession(const BrokerRequest& request)
{
    std::lock_guard lock(sessionMutex_);
    const auto existing = sessionsByAccount_.find(request.profileId);
    if (existing == sessionsByAccount_.end() || existing->second.count == 0)
    {
        return ERROR_SUCCESS;
    }
    --existing->second.count;
    --sessionCount_;
    if (existing->second.count == 0)
    {
        if (existing->second.readScope)
        {
            const DWORD error = existing->second.readScope->Restore();
            if (error != ERROR_SUCCESS)
            {
                existing->second.log->Leave(request.requestId);
                return error;
            }
        }
        sessionsByAccount_.erase(existing);
    }
    else if (existing->second.log)
    {
        existing->second.log->Leave(request.requestId);
    }
    return ERROR_SUCCESS;
}

bool BrokerApplication::HasActiveSession(std::wstring_view accountName)
{
    std::lock_guard lock(sessionMutex_);
    const auto existing = sessionsByAccount_.find(std::wstring(accountName));
    return existing != sessionsByAccount_.end();
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
    const BrokerRequest& request, const BrokerCallerIdentity& caller, BrokerSession& session)
{
    BrokerChildProcess& child = session.child;
    BrokerReadScope* readScope = nullptr;
    bool sessionReserved = false;
    const auto complete = [&](DWORD result)
    {
        const std::wstring scopePath =
            result != ERROR_SUCCESS && readScope != nullptr ? readScope->failurePath() : L"";
        if (result != ERROR_SUCCESS && sessionReserved)
        {
            child.TerminateAndWaitForExitConfirmed();
            const DWORD restoreError = ReleaseSession(request);
            if (restoreError != ERROR_SUCCESS)
            {
                result = restoreError;
            }
            sessionReserved = false;
        }
        if (request.log)
        {
            LogLaunchAction(request.requestId,
                request.profileId,
                result == ERROR_SUCCESS ? L"launch.started" : L"launch.failed",
                request.workingDirectory,
                result);
        }
        AuditRequest(result == ERROR_SUCCESS ? BrokerAuditEvent::LaunchAllowed
                                             : BrokerAuditEvent::LaunchRejected,
            result == ERROR_SUCCESS ? EVENTLOG_INFORMATION_TYPE : EVENTLOG_WARNING_TYPE,
            request,
            caller,
            result,
            child.processId(),
            scopePath);
        return result;
    };
    if ((request.operation != RequestOperation::ConsoleLaunch &&
            request.operation != RequestOperation::InteractiveLaunch) ||
        !IsAuthorizedCaller(authorizedCallerSid_, caller.userSid))
    {
        return complete(ERROR_ACCESS_DENIED);
    }
    if (request.arguments.empty())
    {
        return complete(ERROR_INVALID_PARAMETER);
    }
    if (!TryReserveSession(request, readScope))
    {
        return complete(ERROR_BUSY);
    }
    sessionReserved = true;
    std::lock_guard launchLock(launchMutex_);
    if (request.log)
    {
        LogLaunchAction(
            request.requestId, request.profileId, L"launch.begin", request.workingDirectory);
    }
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
    const DWORD logonError =
        LogOnBrokerAccount(request.profileId, password, token, request.restrictAccess);
    password.Clear();
    if (logonError != ERROR_SUCCESS)
    {
        return complete(logonError);
    }
    if (request.log)
    {
        LogLaunchAction(request.requestId, request.profileId, L"launch.account_logged_on");
    }
    if (request.operation == RequestOperation::InteractiveLaunch)
    {
        InteractiveDesktopLeaseConnection lease;
        const DWORD launchError = LaunchBrokerInteractiveProcess(token.get(),
            request.profileId,
            request.arguments,
            request.workingDirectory,
            caller.sessionId,
            request.interactive.leasePipe,
            request.interactive.nonce,
            caller.logonSid,
            child,
            lease,
            request.lowIntegrity,
            readScope);
        if (launchError != ERROR_SUCCESS)
        {
            return complete(launchError);
        }
        const DWORD resumeError = child.Resume();
        if (resumeError != ERROR_SUCCESS)
        {
            child.TerminateAndWaitForExitConfirmed();
            return complete(resumeError);
        }
        session.desktopLease = std::move(lease);
        return complete(ERROR_SUCCESS);
    }
    std::vector<std::wstring> conhostArguments {
        L"--internal-pseudoconsole-host",
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
    const DWORD launchError = LaunchBrokerConsoleHost(token.get(),
        request.profileId,
        conhostArguments,
        request.workingDirectory,
        child,
        request.lowIntegrity,
        readScope);
    if (launchError != ERROR_SUCCESS)
    {
        return complete(launchError);
    }
    const DWORD validationError = ValidateChildLogonSid(child.process(), caller.logonSid);
    if (validationError != ERROR_SUCCESS)
    {
        child.TerminateAndWaitForExitConfirmed();
        return complete(validationError);
    }
    const DWORD resumeError = child.Resume();
    if (resumeError != ERROR_SUCCESS)
    {
        child.TerminateAndWaitForExitConfirmed();
    }
    return complete(resumeError);
}

DWORD BrokerApplication::FinishSession(
    const BrokerRequest& request, BrokerSession& session, bool processTreeExited)
{
    if (!processTreeExited)
    {
        const std::array<std::wstring, 4> fields {
            L"operation=launch",
            AuditProfileId(L"profileId", request.profileId),
            L"reason=process_tree_not_confirmed",
            L"win32Error=" + std::to_wstring(ERROR_BUSY),
        };
        static_cast<void>(WriteBrokerAuditEvent(
            EVENTLOG_ERROR_TYPE, BrokerAuditEvent::SessionTeardownFailed, fields));
        return ERROR_BUSY;
    }
    DWORD leaseError = ERROR_SUCCESS;
    if (request.operation == RequestOperation::InteractiveLaunch)
    {
        leaseError = ReleaseInteractiveDesktopLease(session.desktopLease);
    }
    const DWORD restoreError = ReleaseSession(request);
    if (restoreError != ERROR_SUCCESS)
    {
        leaseError = restoreError;
    }
    if (request.log)
    {
        LogLaunchAction(request.requestId, request.profileId, L"session.closed", {}, leaseError);
    }
    if (leaseError != ERROR_SUCCESS)
    {
        const std::array<std::wstring, 4> fields {
            L"operation=launch",
            AuditProfileId(L"profileId", request.profileId),
            L"reason=lease_release_failed",
            L"win32Error=" + std::to_wstring(leaseError),
        };
        static_cast<void>(WriteBrokerAuditEvent(
            EVENTLOG_ERROR_TYPE, BrokerAuditEvent::SessionTeardownFailed, fields));
    }
    return leaseError;
}

} // namespace launch_as::broker
