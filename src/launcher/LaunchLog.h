// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <filesystem>
#include <span>
#include <string>

namespace launch_as
{
// The caller owns the text file. Broker diagnostics are collected by request ID from
// the existing event source, never by allowing SYSTEM to write a caller-selected path.
class LaunchLog final
{
  public:
    [[nodiscard]] DWORD Start(std::wstring_view requestId);
    void Record(std::wstring_view action, DWORD error) noexcept;
    void Collect() noexcept;
    void Finish() noexcept;

  private:
    [[nodiscard]] DWORD Append(std::wstring_view component, std::span<const std::wstring> fields);
    std::filesystem::path path_;
    std::wstring requestId_;
    ULONGLONG lastRecord_ = 0;
    bool completed_ = false;
    bool collectionFailed_ = false;
};
} // namespace launch_as
