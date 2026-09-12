// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <cwchar>
#include <limits>

namespace
{

[[nodiscard]] bool ParseDword(const wchar_t* text, DWORD& value) noexcept
{
    wchar_t* end = nullptr;
    const unsigned long parsed = std::wcstoul(text, &end, 10);
    if (end == text || *end != L'\0' || parsed > std::numeric_limits<DWORD>::max())
    {
        return false;
    }
    value = static_cast<DWORD>(parsed);
    return true;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    DWORD delayMilliseconds = 0;
    DWORD exitCode = 0;
    if (argumentCount != 3 || !ParseDword(arguments[1], delayMilliseconds) ||
        !ParseDword(arguments[2], exitCode))
    {
        return 1;
    }
    Sleep(delayMilliseconds);
    return static_cast<int>(exitCode);
}
