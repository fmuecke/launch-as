// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "Win32Support.h"

#include <iterator>
#include <objbase.h>
#include <string>

namespace launch_as
{
std::wstring FormatWindowsError(DWORD error)
{
    wchar_t* rawMessage = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<wchar_t*>(&rawMessage),
        0,
        nullptr);
    LocalAllocation<void*> messageBuffer(rawMessage);

    if (length == 0 || rawMessage == nullptr)
    {
        return L"Windows error " + std::to_wstring(error);
    }

    std::wstring message(rawMessage, length);
    while (!message.empty() &&
           (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' '))
    {
        message.pop_back();
    }
    return message + L" (" + std::to_wstring(error) + L")";
}

DWORD QueryTokenInformation(
    HANDLE token, TOKEN_INFORMATION_CLASS informationClass, std::vector<BYTE>& buffer)
{
    buffer.clear();
    DWORD bytes = 0;
    GetTokenInformation(token, informationClass, nullptr, 0, &bytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
    {
        return sizeError == ERROR_SUCCESS ? ERROR_INVALID_DATA : sizeError;
    }
    buffer.resize(bytes);
    if (!GetTokenInformation(token, informationClass, buffer.data(), bytes, &bytes))
    {
        const DWORD readError = GetLastError();
        buffer.clear();
        return readError;
    }
    return ERROR_SUCCESS;
}

bool CreateGuidString(std::wstring& text)
{
    text.clear();
    GUID identifier {};
    if (FAILED(CoCreateGuid(&identifier)))
    {
        return false;
    }
    wchar_t formatted[39] {};
    if (StringFromGUID2(identifier, formatted, static_cast<int>(std::size(formatted))) != 39)
    {
        return false;
    }
    text.assign(formatted + 1, 36);
    return true;
}

} // namespace launch_as
