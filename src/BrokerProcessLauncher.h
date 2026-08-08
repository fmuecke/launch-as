// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>

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
    void Reset() noexcept;

  private:
    void SetProcess(HANDLE process, HANDLE thread) noexcept;

    HANDLE job_ = nullptr;
    HANDLE process_ = nullptr;
    HANDLE thread_ = nullptr;

    friend DWORD CreateBrokerJob(BrokerChildProcess& child);
    friend DWORD LaunchFixedBrokerProbe(HANDLE token, BrokerChildProcess& child);
};

[[nodiscard]] DWORD CreateBrokerJob(BrokerChildProcess& child);
[[nodiscard]] DWORD LaunchFixedBrokerProbe(HANDLE token, BrokerChildProcess& child);

} // namespace launch_as::broker
