// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#pragma once

#include "Win32Support.h"

#include <Windows.h>
#include <cstddef>
#include <string>
#include <thread>
#include <vector>

namespace sandbox_launcher
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

    [[nodiscard]] bool Initialize(COORD terminalSize, bool inheritCursor, std::wstring& error);
    [[nodiscard]] STARTUPINFOW* startupInfo() noexcept;
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
    [[nodiscard]] COORD CurrentTerminalSize() const noexcept;
    [[nodiscard]] bool ConfigureTerminal(std::wstring& error);
    void RestoreTerminal() noexcept;
    void ClosePseudoConsole() noexcept;

    Api api_;
    HPCON pseudoConsole_ = nullptr;
    STARTUPINFOEXW startupInfo_ {};
    std::vector<std::byte> attributeListStorage_;
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
    bool resizeSupported_ = false;
    bool relaysStarted_ = false;
    std::jthread inputRelay_;
    std::jthread outputRelay_;
    std::jthread resizeRelay_;
};

} // namespace sandbox_launcher
