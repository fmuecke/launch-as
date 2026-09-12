// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

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

  private:
    void Reset() noexcept;
    void SetProcess(HANDLE process, HANDLE thread) noexcept;
    void SetUserProfile(HANDLE token, HANDLE profile) noexcept;
    void SetPseudoConsoleHostReports(HANDLE exitReport, HANDLE diagnostics) noexcept;

    HANDLE job_ = nullptr;
    HANDLE process_ = nullptr;
    HANDLE thread_ = nullptr;
    HANDLE profileToken_ = nullptr;
    HANDLE profile_ = nullptr;
    HANDLE exitReport_ = nullptr;
    HANDLE diagnostics_ = nullptr;

    friend DWORD CreateBrokerJob(BrokerChildProcess& child);
    friend DWORD LaunchBrokerConsoleHost(HANDLE token, std::wstring_view accountName,
        std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
        BrokerChildProcess& child);
    friend DWORD LaunchFixedBrokerProbe(HANDLE token, BrokerChildProcess& child);
};

[[nodiscard]] DWORD CreateBrokerJob(BrokerChildProcess& child);
[[nodiscard]] DWORD ResolveBrokerWorkingDirectory(
    std::wstring_view workingDirectory, std::wstring& resolvedDirectory);
[[nodiscard]] DWORD LaunchBrokerConsoleHost(HANDLE token, std::wstring_view accountName,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    BrokerChildProcess& child);
[[nodiscard]] DWORD LaunchFixedBrokerProbe(HANDLE token, BrokerChildProcess& child);
[[nodiscard]] DWORD GetTokenLogonSid(HANDLE token, std::vector<BYTE>& logonSid);
[[nodiscard]] DWORD ValidateChildLogonSid(HANDLE process, const std::vector<BYTE>& callerLogonSid);

#ifdef LAUNCH_AS_TESTING
void SetBrokerJobQueryFailureForTesting(bool fail) noexcept;
#endif

} // namespace launch_as::broker
