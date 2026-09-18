// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <span>
#include <string>
#include <vector>

namespace launch_as::broker
{

class SecurePassword final
{
  public:
    SecurePassword() = default;
    ~SecurePassword();

    SecurePassword(const SecurePassword&) = delete;
    SecurePassword& operator=(const SecurePassword&) = delete;

    [[nodiscard]] std::span<const wchar_t> characters() const noexcept
    {
        return {characters_.data(), length_};
    }
    [[nodiscard]] const wchar_t* c_str() const noexcept
    {
        return characters_.empty() ? L"" : characters_.data();
    }
    void Clear() noexcept;

  private:
    [[nodiscard]] bool Assign(const BYTE* bytes, DWORD byteCount);

    std::vector<wchar_t> characters_;
    std::size_t length_ = 0;

    friend DWORD GenerateBrokerPassword(SecurePassword& password);
};

[[nodiscard]] DWORD GenerateBrokerPassword(SecurePassword& password);

} // namespace launch_as::broker
