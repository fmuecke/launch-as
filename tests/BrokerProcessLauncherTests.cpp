// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"
#include "InteractiveDesktopLeaseClient.h"
#include "TestSupport.h"

#include <Windows.h>
#include <array>
#include <atomic>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace
{

[[nodiscard]] bool HasNoThreadToken()
{
    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
    {
        CloseHandle(token);
        return false;
    }
    return GetLastError() == ERROR_NO_TOKEN;
}

[[nodiscard]] bool TcbHasState(HANDLE token, bool enabled)
{
    LUID tcb {};
    if (!LookupPrivilegeValueW(nullptr, SE_TCB_NAME, &tcb))
    {
        return false;
    }
    DWORD required = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return false;
    }
    std::vector<BYTE> storage(required);
    if (!GetTokenInformation(token, TokenPrivileges, storage.data(), required, &required))
    {
        return false;
    }
    const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(storage.data());
    for (DWORD index = 0; index < privileges->PrivilegeCount; ++index)
    {
        const auto& privilege = privileges->Privileges[index];
        if (privilege.Luid.LowPart == tcb.LowPart && privilege.Luid.HighPart == tcb.HighPart)
        {
            return ((privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0) == enabled;
        }
    }
    return false;
}

HANDLE assignmentsEntered = nullptr;
HANDLE assignmentsContinue = nullptr;
std::atomic<int> assignmentCount = 0;
std::atomic<bool> assignmentScopesValid = true;

void ObserveSessionAssignment()
{
    HANDLE token = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
    {
        assignmentScopesValid = false;
    }
    else
    {
        if (!TcbHasState(token, true))
        {
            assignmentScopesValid = false;
        }
        CloseHandle(token);
    }
    if (++assignmentCount == 2)
    {
        SetEvent(assignmentsEntered);
    }
    if (WaitForSingleObject(assignmentsContinue, 10'000) != WAIT_OBJECT_0)
    {
        assignmentScopesValid = false;
    }
}

// Run only as SYSTEM in a fresh Sandbox. The host suite never requires SeTcbPrivilege.
[[nodiscard]] bool TestSessionPrivilegeScope()
{
    HANDLE processToken = nullptr;
    if (!Expect(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &processToken),
            L"Could not open the privilege-test process token."))
    {
        return false;
    }
    if (!Expect(TcbHasState(processToken, true),
            L"This test requires the default SYSTEM state with TCB initially enabled.") ||
        !Expect(launch_as::broker::DisableBrokerProcessTcbPrivilege() == ERROR_SUCCESS &&
                    TcbHasState(processToken, false),
            L"Broker initialization did not disable process TCB while retaining the privilege."))
    {
        CloseHandle(processToken);
        return false;
    }
    assignmentsEntered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    assignmentsContinue = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    bool workersSucceeded[2] {};
    auto worker = [&](int index)
    {
        HANDLE target = nullptr;
        if (!DuplicateTokenEx(processToken,
                TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                nullptr,
                SecurityImpersonation,
                TokenPrimary,
                &target))
        {
            return;
        }
        DWORD sessionId = MAXDWORD;
        DWORD bytes = 0;
        const BOOL read =
            GetTokenInformation(target, TokenSessionId, &sessionId, sizeof(sessionId), &bytes);
        launch_as::broker::SetBrokerSessionAssignmentObserverForTesting(ObserveSessionAssignment);
        const DWORD error = launch_as::broker::SetBrokerTokenSessionId(target, sessionId);
        launch_as::broker::SetBrokerSessionAssignmentObserverForTesting(nullptr);
        DWORD assignedSessionId = MAXDWORD;
        const BOOL assigned = GetTokenInformation(
            target, TokenSessionId, &assignedSessionId, sizeof(assignedSessionId), &bytes);
        std::wcerr << L"session assignment worker " << index << L": error=" << error << L", before="
                   << sessionId << L", after=" << assignedSessionId << L", reverted="
                   << HasNoThreadToken() << L'\n';
        workersSucceeded[index] = read && assigned && assignedSessionId == sessionId &&
                                  error == ERROR_SUCCESS && HasNoThreadToken();
        CloseHandle(target);
    };
    std::thread first(worker, 0);
    std::thread second(worker, 1);
    const bool overlapped = WaitForSingleObject(assignmentsEntered, 10'000) == WAIT_OBJECT_0;
    const bool processUnchanged = TcbHasState(processToken, false) && HasNoThreadToken();
    std::wcerr << L"process TCB stayed disabled=" << processUnchanged << L'\n';
    SetEvent(assignmentsContinue);
    first.join();
    second.join();
    CloseHandle(assignmentsEntered);
    CloseHandle(assignmentsContinue);
    HANDLE queryOnlyTarget = nullptr;
    const BOOL duplicated = DuplicateTokenEx(
        processToken, TOKEN_QUERY, nullptr, SecurityImpersonation, TokenPrimary, &queryOnlyTarget);
    const DWORD failureError = launch_as::broker::SetBrokerTokenSessionId(queryOnlyTarget, 0);
    const bool failureRestored = HasNoThreadToken() && TcbHasState(processToken, false);
    if (queryOnlyTarget != nullptr)
    {
        CloseHandle(queryOnlyTarget);
    }
    CloseHandle(processToken);
    return Expect(overlapped && assignmentCount == 2 && assignmentScopesValid,
               L"Concurrent assignments did not each enable a private thread privilege.") &&
           Expect(processUnchanged && workersSucceeded[0] && workersSucceeded[1],
               L"Session assignment leaked TCB to the process or retained a thread token.") &&
           Expect(duplicated && failureError == ERROR_ACCESS_DENIED && failureRestored,
               L"Failed session assignment did not preserve its error and revert impersonation.");
}

// Invoked only by installed-service acceptance inside the disposable guest.
[[nodiscard]] bool TestInstalledServiceTcbDisabled()
{
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager != nullptr
                            ? OpenServiceW(manager, L"launch-as-broker", SERVICE_QUERY_STATUS)
                            : nullptr;
    SERVICE_STATUS_PROCESS status {};
    DWORD bytes = 0;
    const bool running = service != nullptr &&
                         QueryServiceStatusEx(service,
                             SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<BYTE*>(&status),
                             sizeof(status),
                             &bytes) &&
                         status.dwCurrentState == SERVICE_RUNNING;
    if (service != nullptr)
    {
        CloseServiceHandle(service);
    }
    if (manager != nullptr)
    {
        CloseServiceHandle(manager);
    }
    HANDLE process = running
                         ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, status.dwProcessId)
                         : nullptr;
    HANDLE token = nullptr;
    const bool disabled = process != nullptr && OpenProcessToken(process, TOKEN_QUERY, &token) &&
                          TcbHasState(token, false);
    if (token != nullptr)
    {
        CloseHandle(token);
    }
    if (process != nullptr)
    {
        CloseHandle(process);
    }
    return Expect(disabled, L"Installed broker must retain TCB in its process token, disabled.");
}

[[nodiscard]] bool TestSessionAssignmentRejectsImpersonation()
{
    if (!ImpersonateSelf(SecurityImpersonation))
    {
        return false;
    }
    const DWORD error = launch_as::broker::SetBrokerTokenSessionId(nullptr, 0);
    const bool identityRetained = !HasNoThreadToken();
    const BOOL reverted = RevertToSelf();
    return Expect(error == ERROR_BAD_IMPERSONATION_LEVEL && identityRetained && reverted,
        L"Session assignment replaced an existing impersonation identity.");
}

[[nodiscard]] bool TestWorkingDirectoryValidation()
{
    constexpr std::array rejectedPaths {
        L"relative",
        L"C:relative",
        L"\\rooted",
        L"/rooted",
        L"\\\\server\\share",
        L"//server/share",
        L"\\\\?\\C:\\Windows",
        L"//?/C:/Windows",
        L"\\\\.\\C:\\Windows",
        L"//./C:/Windows",
    };
    for (const wchar_t* path : rejectedPaths)
    {
        std::wstring resolved = L"must be cleared";
        if (!Expect(launch_as::broker::ResolveBrokerWorkingDirectory(path, resolved) ==
                        ERROR_BAD_PATHNAME,
                L"The broker accepted a relative, network, or device working directory.") ||
            !Expect(resolved.empty(), L"A rejected working directory left a resolved path."))
        {
            return false;
        }
    }

    std::error_code pathError;
    const std::filesystem::path currentDirectory = std::filesystem::current_path(pathError);
    if (!Expect(!pathError, L"Could not resolve the current directory for path validation."))
    {
        return false;
    }
    const std::filesystem::path expectedDirectory =
        std::filesystem::canonical(currentDirectory, pathError);
    if (!Expect(!pathError, L"Could not canonicalize the expected working directory."))
    {
        return false;
    }

    std::wstring resolved;
    const std::filesystem::path nonCanonicalDirectory = currentDirectory / L".";
    return Expect(launch_as::broker::ResolveBrokerWorkingDirectory(
                      nonCanonicalDirectory.native(), resolved) == ERROR_SUCCESS,
               L"The broker rejected an existing local working directory.") &&
           Expect(resolved == expectedDirectory.native(),
               L"The broker did not canonicalize the working directory.");
}

[[nodiscard]] bool TestJobTerminationConfirmsActiveProcessZero()
{
    launch_as::broker::BrokerChildProcess child;
    if (!Expect(launch_as::broker::CreateBrokerJob(child) == ERROR_SUCCESS,
            L"Could not create the broker termination-test job."))
    {
        return false;
    }

    wchar_t systemDirectory[MAX_PATH] {};
    const UINT directoryLength = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (!Expect(directoryLength > 0 && directoryLength < MAX_PATH,
            L"Could not resolve the system directory for the broker termination test."))
    {
        return false;
    }
    const std::wstring executable = std::wstring(systemDirectory) + L"\\cmd.exe";
    std::wstring commandLine = L"\"" + executable + L"\" /d /c timeout /t 30 /nobreak >nul";
    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo {};
    if (!Expect(CreateProcessW(executable.c_str(),
                    commandLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW | CREATE_SUSPENDED,
                    nullptr,
                    nullptr,
                    &startupInfo,
                    &processInfo),
            L"Could not create the broker termination-test process."))
    {
        return false;
    }

    const bool assigned = AssignProcessToJobObject(child.job(), processInfo.hProcess) != FALSE;
    HANDLE observedJob = nullptr;
    const bool duplicated = assigned && DuplicateHandle(GetCurrentProcess(),
                                            child.job(),
                                            GetCurrentProcess(),
                                            &observedJob,
                                            0,
                                            FALSE,
                                            DUPLICATE_SAME_ACCESS) != FALSE;
    const bool resumed = assigned && ResumeThread(processInfo.hThread) != static_cast<DWORD>(-1);
    const bool terminated = duplicated && resumed && child.TerminateAndWaitForExit();
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting {};
    const bool queried = terminated && QueryInformationJobObject(observedJob,
                                           JobObjectBasicAccountingInformation,
                                           &accounting,
                                           sizeof(accounting),
                                           nullptr) != FALSE;
    const bool processExited =
        terminated && WaitForSingleObject(processInfo.hProcess, 5'000) == WAIT_OBJECT_0;
    if (!terminated)
    {
        TerminateProcess(processInfo.hProcess, ERROR_CANCELLED);
        static_cast<void>(WaitForSingleObject(processInfo.hProcess, INFINITE));
    }
    if (observedJob != nullptr)
    {
        CloseHandle(observedJob);
    }
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    return Expect(assigned, L"Could not assign the termination-test process to the broker job.") &&
           Expect(duplicated, L"Could not retain the termination-test Job for inspection.") &&
           Expect(resumed, L"Could not resume the broker termination-test process.") &&
           Expect(terminated, L"The broker could not confirm that its Job process tree exited.") &&
           Expect(queried && accounting.ActiveProcesses == 0,
               L"The broker finished teardown while the Job still had active processes.") &&
           Expect(
               processExited, L"The process assigned to the terminated broker Job did not exit.");
}

[[nodiscard]] bool TestUnconfirmedTeardownRetainsJobUntilConfirmation()
{
    launch_as::broker::BrokerChildProcess child;
    if (!Expect(launch_as::broker::LaunchDelayedBrokerChildForTesting(child) == ERROR_SUCCESS,
            L"Could not launch the broker teardown-failure test child."))
    {
        return false;
    }
    launch_as::broker::SetBrokerJobQueryFailureForTesting(true);
    const ULONGLONG start = GetTickCount64();
    const bool treeExited = child.TerminateAndWaitForExit();
    const ULONGLONG elapsed = GetTickCount64() - start;
    const bool jobAndProcessRetained = child.job() != nullptr && child.process() != nullptr;
    const bool processExited =
        child.process() != nullptr && WaitForSingleObject(child.process(), 0) == WAIT_OBJECT_0;
    launch_as::broker::SetBrokerJobQueryFailureForTesting(false);
    const bool confirmedAfterRecovery = child.TerminateAndWaitForExit();
    return Expect(!treeExited,
               L"The broker reported an unqueryable Job process tree as terminated.") &&
           Expect(elapsed < 1'000,
               L"The broker did not return promptly after failing to query its Job process "
               L"tree.") &&
           Expect(jobAndProcessRetained,
               L"An unconfirmed teardown released its Job or process handle.") &&
           Expect(processExited,
               L"The injected query failure did not exercise a terminated child process.") &&
           Expect(confirmedAfterRecovery && child.job() == nullptr,
               L"The broker did not release the Job after exit was confirmed.");
}

[[nodiscard]] bool TestInteractiveLaunchRejectsIncompleteInputs()
{
    launch_as::broker::BrokerChildProcess child;
    launch_as::broker::InteractiveDesktopLeaseConnection lease;
    const std::vector<std::wstring> arguments;
    const std::vector<BYTE> callerLogonSid;
    return Expect(launch_as::broker::LaunchBrokerInteractiveProcess(
                      nullptr, {}, arguments, {}, 0, {}, {}, callerLogonSid, child, lease) ==
                      ERROR_INVALID_PARAMETER,
               L"The broker accepted an incomplete interactive launch request.") &&
           Expect(!child, L"A rejected interactive launch retained a child process.") &&
           Expect(!lease, L"A rejected interactive launch retained a desktop lease.");
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount == 2 && std::wstring_view(arguments[1]) == L"--service-privilege")
    {
        if (!TestInstalledServiceTcbDisabled())
        {
            return 1;
        }
        std::cout << "Installed broker process TCB is disabled\n";
        return 0;
    }
    if (argumentCount == 2 && std::wstring_view(arguments[1]) == L"--session-privilege")
    {
        if (!TestSessionPrivilegeScope())
        {
            return 1;
        }
        std::cout << "Broker session privilege tests passed\n";
        return 0;
    }
    if (!TestSessionAssignmentRejectsImpersonation())
    {
        return 1;
    }
    if (!TestWorkingDirectoryValidation() || !TestJobTerminationConfirmsActiveProcessZero() ||
        !TestUnconfirmedTeardownRetainsJobUntilConfirmation() ||
        !TestInteractiveLaunchRejectsIncompleteInputs())
    {
        return 1;
    }
    launch_as::broker::BrokerChildProcess child;
    if (!Expect(launch_as::broker::CreateBrokerJob(child) == ERROR_SUCCESS,
            L"Could not create the broker job."))
    {
        return 1;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    if (!Expect(
            QueryInformationJobObject(
                child.job(), JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr),
            L"Could not query the broker job limits."))
    {
        return 1;
    }
    if (!Expect((limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0,
            L"The broker job does not kill children when it closes."))
    {
        return 1;
    }
    if (!Expect(child.Resume() == ERROR_INVALID_HANDLE,
            L"The broker resumed a child that was not created."))
    {
        return 1;
    }
    HANDLE token = nullptr;
    if (!Expect(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token),
            L"Could not open the current process token."))
    {
        return 1;
    }
    std::vector<BYTE> currentLogonSid;
    const DWORD logonSidError = launch_as::broker::GetTokenLogonSid(token, currentLogonSid);
    CloseHandle(token);
    if (!Expect(logonSidError == ERROR_SUCCESS, L"Could not read the current logon SID."))
    {
        return 1;
    }
    return Expect(launch_as::broker::ValidateChildLogonSid(GetCurrentProcess(), currentLogonSid) ==
                      ERROR_ACCESS_DENIED,
               L"The broker accepted a child sharing the caller logon SID.")
               ? 0
               : 1;
}
