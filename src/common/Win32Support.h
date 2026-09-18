// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <string>
#include <utility>

namespace launch_as
{

class UniqueHandle final
{
  public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE value) noexcept : value_(value) {}

    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}

    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other)
        {
            reset(std::exchange(other.value_, nullptr));
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return value_; }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

    void reset(HANDLE value = nullptr) noexcept
    {
        if (*this)
        {
            CloseHandle(value_);
        }
        value_ = value;
    }

  private:
    HANDLE value_ = nullptr;
};

template <typename T> class LocalAllocation final
{
  public:
    explicit LocalAllocation(T value = nullptr) noexcept : value_(value) {}
    ~LocalAllocation() { reset(); }

    LocalAllocation(const LocalAllocation&) = delete;
    LocalAllocation& operator=(const LocalAllocation&) = delete;

    LocalAllocation(LocalAllocation&& other) noexcept : value_(std::exchange(other.value_, nullptr))
    {
    }

    LocalAllocation& operator=(LocalAllocation&& other) noexcept
    {
        if (this != &other)
        {
            reset(std::exchange(other.value_, nullptr));
        }
        return *this;
    }

    [[nodiscard]] T get() const noexcept { return value_; }
    [[nodiscard]] T* address() noexcept { return &value_; }

    void reset(T value = nullptr) noexcept
    {
        if (value_ != nullptr)
        {
            LocalFree(value_);
        }
        value_ = value;
    }

  private:
    T value_ = nullptr;
};

[[nodiscard]] std::wstring FormatWindowsError(DWORD error);

} // namespace launch_as
