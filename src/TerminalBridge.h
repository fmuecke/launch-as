// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "Win32Support.h"

#include <Windows.h>
#include <string>
#include <thread>

namespace launch_as
{

class TerminalBridge final
{
  public:
    TerminalBridge() = default;
    ~TerminalBridge();

    TerminalBridge(const TerminalBridge&) = delete;
    TerminalBridge& operator=(const TerminalBridge&) = delete;
    TerminalBridge(TerminalBridge&&) = delete;
    TerminalBridge& operator=(TerminalBridge&&) = delete;

    [[nodiscard]] bool Initialize(STARTUPINFOW& childStartupInformation, std::wstring& error);
    [[nodiscard]] bool PrepareChildProcessCreation(std::wstring& error);
    [[nodiscard]] bool CompleteChildProcessCreation(bool processCreated, std::wstring& error);
    [[nodiscard]] bool Start(std::wstring& error);
    void Stop() noexcept;

    [[nodiscard]] COORD terminalSize() const noexcept;
    [[nodiscard]] bool supportsCursorInheritance() const noexcept;

  private:
    [[nodiscard]] bool ConfigureTerminal(std::wstring& error);
    void RestoreTerminal() noexcept;

    UniqueHandle childInputRead_;
    UniqueHandle childOutputWrite_;
    UniqueHandle inputWrite_;
    UniqueHandle outputRead_;
    UniqueHandle outputCompleteEvent_;
    HANDLE parentInput_ = nullptr;
    HANDLE parentOutput_ = nullptr;
    DWORD originalInputMode_ = 0;
    DWORD originalOutputMode_ = 0;
    UINT originalInputCodePage_ = 0;
    UINT originalOutputCodePage_ = 0;
    bool inputModeChanged_ = false;
    bool outputModeChanged_ = false;
    bool inputCodePageChanged_ = false;
    bool outputCodePageChanged_ = false;
    bool childHandlesInheritable_ = false;
    bool childProcessCreated_ = false;
    bool started_ = false;
    std::jthread inputRelay_;
    std::jthread outputRelay_;
};

} // namespace launch_as
