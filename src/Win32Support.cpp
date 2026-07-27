// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "Win32Support.h"

#include <string>

namespace launch_as
{
namespace
{

class LocalBuffer final
{
  public:
    explicit LocalBuffer(void* value) noexcept : value_(value) {}

    ~LocalBuffer()
    {
        if (value_ != nullptr)
        {
            LocalFree(value_);
        }
    }

    LocalBuffer(const LocalBuffer&) = delete;
    LocalBuffer& operator=(const LocalBuffer&) = delete;

  private:
    void* value_;
};

} // namespace

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
    LocalBuffer messageBuffer(rawMessage);

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

} // namespace launch_as
