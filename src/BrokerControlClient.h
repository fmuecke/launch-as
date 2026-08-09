// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "TerminalBridge.h"
#include "Win32Support.h"

#include <Windows.h>
#include <span>
#include <string>
#include <string_view>

namespace launch_as
{

class BrokerControlConnection final
{
  public:
    BrokerControlConnection() = default;

    BrokerControlConnection(const BrokerControlConnection&) = delete;
    BrokerControlConnection& operator=(const BrokerControlConnection&) = delete;

    [[nodiscard]] HANDLE get() const noexcept;
    [[nodiscard]] std::wstring_view requestId() const noexcept;
    void SetRequestId(std::wstring value);
    void Reset(HANDLE pipe = nullptr) noexcept;

  private:
    UniqueHandle pipe_;
    std::wstring requestId_;
};

[[nodiscard]] DWORD LaunchBrokerConsole(std::wstring_view profileId,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    const TerminalPipeNames& pipes, COORD terminalSize, BrokerControlConnection& connection,
    DWORD& processId);
[[nodiscard]] DWORD WaitForBrokerConsoleExit(BrokerControlConnection& connection, DWORD& exitCode);

} // namespace launch_as
