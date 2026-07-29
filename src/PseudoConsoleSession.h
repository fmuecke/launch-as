// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "TerminalIO.h"
#include "Win32Support.h"

#include <Windows.h>
#include <cstddef>
#include <string>
#include <thread>
#include <vector>

namespace launch_as
{

class PseudoConsoleSession final
{
  public:
    PseudoConsoleSession() = default;
    ~PseudoConsoleSession();

    PseudoConsoleSession(const PseudoConsoleSession&) = delete;
    PseudoConsoleSession& operator=(const PseudoConsoleSession&) = delete;
    PseudoConsoleSession(PseudoConsoleSession&&) = delete;
    PseudoConsoleSession& operator=(PseudoConsoleSession&&) = delete;

    [[nodiscard]] bool Initialize(
        COORD terminalSize, bool inheritCursor, HANDLE resizeInput, std::wstring& error);
    [[nodiscard]] STARTUPINFOW* startupInfo() noexcept;
    [[nodiscard]] HANDLE inputRelayCompleteEvent() const noexcept;
    [[nodiscard]] bool StartRelays(std::wstring& error);
    void StopRelays() noexcept;

  private:
    using CreatePseudoConsoleFunction = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
    using ResizePseudoConsoleFunction = HRESULT(WINAPI*)(HPCON, COORD);
    using ClosePseudoConsoleFunction = void(WINAPI*)(HPCON);

    struct Api
    {
        CreatePseudoConsoleFunction create = nullptr;
        ResizePseudoConsoleFunction resize = nullptr;
        ClosePseudoConsoleFunction close = nullptr;
    };

    [[nodiscard]] bool LoadApi(std::wstring& error);
    void ClosePseudoConsole() noexcept;

    Api api_;
    HPCON pseudoConsole_ = nullptr;
    STARTUPINFOEXW startupInfo_ {};
    std::vector<std::byte> attributeListStorage_;
    UniqueHandle inputWrite_;
    UniqueHandle outputRead_;
    UniqueHandle inputRelayCompleteEvent_;
    UniqueHandle outputCompleteEvent_;
    HANDLE parentInput_ = nullptr;
    HANDLE parentOutput_ = nullptr;
    HANDLE resizeInput_ = nullptr;
    TerminalMode terminalMode_;
    bool relaysStarted_ = false;
    std::jthread inputRelay_;
    std::jthread outputRelay_;
    std::jthread resizeRelay_;
};

} // namespace launch_as
