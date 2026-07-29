// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <stop_token>
#include <string>

namespace launch_as
{

inline constexpr COORD DefaultTerminalSize {120, 30};
inline constexpr DWORD RelayBufferBytes = 16 * 1024;
inline constexpr DWORD OutputDrainGraceMilliseconds = 250;

[[nodiscard]] bool IsUsableHandle(HANDLE handle) noexcept;
void RelayInput(HANDLE source, HANDLE destination) noexcept;
void RelayOutput(
    HANDLE source, HANDLE destination, std::stop_token stopToken = std::stop_token {}) noexcept;
[[nodiscard]] COORD CurrentTerminalSize(HANDLE output) noexcept;
[[nodiscard]] bool SupportsTerminalCursorInheritance(HANDLE input, HANDLE output) noexcept;

class TerminalMode final
{
  public:
    TerminalMode() = default;
    ~TerminalMode();

    TerminalMode(const TerminalMode&) = delete;
    TerminalMode& operator=(const TerminalMode&) = delete;
    TerminalMode(TerminalMode&&) = delete;
    TerminalMode& operator=(TerminalMode&&) = delete;

    [[nodiscard]] bool Configure(HANDLE input, HANDLE output, std::wstring& error);
    void Restore() noexcept;

  private:
    HANDLE input_ = nullptr;
    HANDLE output_ = nullptr;
    DWORD originalInputMode_ = 0;
    DWORD originalOutputMode_ = 0;
    UINT originalInputCodePage_ = 0;
    UINT originalOutputCodePage_ = 0;
    bool inputModeChanged_ = false;
    bool outputModeChanged_ = false;
    bool inputCodePageChanged_ = false;
    bool outputCodePageChanged_ = false;
};

} // namespace launch_as
