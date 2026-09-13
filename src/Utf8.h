// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <limits>
#include <string>
#include <string_view>

namespace launch_as
{

[[nodiscard]] inline bool IsValidUtf16(std::wstring_view input)
{
    if (input.empty())
    {
        return true;
    }
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return false;
    }
    return WideCharToMultiByte(CP_UTF8,
               WC_ERR_INVALID_CHARS,
               input.data(),
               static_cast<int>(input.size()),
               nullptr,
               0,
               nullptr,
               nullptr) > 0;
}

[[nodiscard]] inline bool WideToUtf8(std::wstring_view input, std::string& output)
{
    output.clear();
    if (input.empty())
    {
        return true;
    }
    if (!IsValidUtf16(input))
    {
        return false;
    }
    const int byteCount = WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS,
        input.data(),
        static_cast<int>(input.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (byteCount <= 0)
    {
        return false;
    }
    output.resize(static_cast<std::size_t>(byteCount));
    return WideCharToMultiByte(CP_UTF8,
               WC_ERR_INVALID_CHARS,
               input.data(),
               static_cast<int>(input.size()),
               output.data(),
               byteCount,
               nullptr,
               nullptr) == byteCount;
}

[[nodiscard]] inline bool Utf8ToWide(std::string_view input, std::wstring& output)
{
    output.clear();
    if (input.empty())
    {
        return true;
    }
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return false;
    }
    const int characterCount = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (characterCount <= 0)
    {
        return false;
    }
    output.resize(static_cast<std::size_t>(characterCount));
    return MultiByteToWideChar(CP_UTF8,
               MB_ERR_INVALID_CHARS,
               input.data(),
               static_cast<int>(input.size()),
               output.data(),
               characterCount) == characterCount;
}

} // namespace launch_as
