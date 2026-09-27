// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "Win32Support.h"

#include <Windows.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

class InteractiveDesktopLeaseConnection;

class BrokerChildProcess final
{
  public:
    BrokerChildProcess() = default;
    ~BrokerChildProcess();

    BrokerChildProcess(const BrokerChildProcess&) = delete;
    BrokerChildProcess& operator=(const BrokerChildProcess&) = delete;

    [[nodiscard]] HANDLE job() const noexcept;
    [[nodiscard]] HANDLE process() const noexcept;
    [[nodiscard]] DWORD processId() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept;
    [[nodiscard]] DWORD Resume() noexcept;
    [[nodiscard]] bool ReadPseudoConsoleHostResult(
        DWORD& childExitCode, std::wstring& diagnostics) noexcept;
    [[nodiscard]] bool TerminateAndWaitForExit() noexcept;
    void TerminateAndWaitForExitConfirmed() noexcept;
    [[nodiscard]] bool WaitForProcessTreeExit(DWORD timeoutMilliseconds) const noexcept;

  private:
    void Reset() noexcept;
    // Loads the account profile, creates the process suspended, and assigns it to the job. On
    // success this object owns the process, its thread, and the loaded profile.
    [[nodiscard]] DWORD CreateSuspendedInJob(HANDLE token, std::wstring_view accountName,
        const std::wstring& executable, std::vector<wchar_t>& commandLine,
        const std::wstring& directory, BOOL inheritHandles, DWORD creationFlags,
        STARTUPINFOW& startupInfo);

    UniqueHandle job_;
    UniqueHandle process_;
    UniqueHandle thread_;
    UniqueHandle profileToken_;
    HANDLE profile_ = nullptr;
    UniqueHandle exitReport_;
    UniqueHandle diagnostics_;

    friend DWORD CreateBrokerJob(BrokerChildProcess& child);
    friend DWORD LaunchBrokerConsoleHost(HANDLE token, std::wstring_view accountName,
        std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
        BrokerChildProcess& child);
    friend DWORD LaunchBrokerInteractiveProcess(HANDLE token, std::wstring_view accountName,
        std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
        DWORD targetSessionId, std::wstring_view leasePipeName, std::wstring_view leaseNonce,
        const std::vector<BYTE>& callerLogonSid, BrokerChildProcess& child,
        InteractiveDesktopLeaseConnection& lease);
#ifdef LAUNCH_AS_TESTING
    friend DWORD LaunchBrokerChildForTesting(std::wstring_view command, BrokerChildProcess& child);
    friend DWORD LaunchQuickBrokerChildForTesting(BrokerChildProcess& child);
#endif
};

[[nodiscard]] DWORD CreateBrokerJob(BrokerChildProcess& child);
[[nodiscard]] DWORD ResolveBrokerWorkingDirectory(
    std::wstring_view workingDirectory, std::wstring& resolvedDirectory);
[[nodiscard]] DWORD LaunchBrokerConsoleHost(HANDLE token, std::wstring_view accountName,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    BrokerChildProcess& child);
[[nodiscard]] DWORD LaunchBrokerInteractiveProcess(HANDLE token, std::wstring_view accountName,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    DWORD targetSessionId, std::wstring_view leasePipeName, std::wstring_view leaseNonce,
    const std::vector<BYTE>& callerLogonSid, BrokerChildProcess& child,
    InteractiveDesktopLeaseConnection& lease);
[[nodiscard]] DWORD GetTokenLogonSid(HANDLE token, std::vector<BYTE>& logonSid);
[[nodiscard]] DWORD ValidateChildLogonSid(HANDLE process, const std::vector<BYTE>& callerLogonSid);
[[nodiscard]] DWORD SetBrokerTokenSessionId(HANDLE token, DWORD sessionId);
// Call once during service initialization, before starting any request workers.
[[nodiscard]] DWORD DisableBrokerProcessTcbPrivilege();

#ifdef LAUNCH_AS_TESTING
void SetBrokerSessionAssignmentObserverForTesting(void (*observer)()) noexcept;
void SetBrokerJobQueryFailureForTesting(bool fail) noexcept;
[[nodiscard]] DWORD LaunchQuickBrokerChildForTesting(BrokerChildProcess& child);
[[nodiscard]] DWORD LaunchDelayedBrokerChildForTesting(BrokerChildProcess& child);
#endif

} // namespace launch_as::broker
