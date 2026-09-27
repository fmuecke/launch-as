// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <array>
#include <filesystem>
#include <iostream>

[[nodiscard]] inline bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

namespace launch_as::test
{

class TemporaryDirectory final
{
  public:
    TemporaryDirectory()
    {
        std::array<wchar_t, MAX_PATH> temporaryPath {};
        const DWORD length =
            GetTempPathW(static_cast<DWORD>(temporaryPath.size()), temporaryPath.data());
        if (length == 0 || length >= temporaryPath.size())
        {
            return;
        }
        std::array<wchar_t, MAX_PATH> uniquePath {};
        if (GetTempFileNameW(temporaryPath.data(), L"las", 0, uniquePath.data()) == 0 ||
            !DeleteFileW(uniquePath.data()) || !CreateDirectoryW(uniquePath.data(), nullptr))
        {
            return;
        }
        path_ = uniquePath.data();
        created_ = true;
    }

    ~TemporaryDirectory()
    {
        if (created_)
        {
            std::error_code error;
            std::filesystem::remove_all(path_, error);
        }
    }

    [[nodiscard]] bool created() const noexcept { return created_; }
    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

  private:
    std::filesystem::path path_;
    bool created_ = false;
};

// Inheritable standard handles for a child started with STARTF_USESTDHANDLES. The CRT needs a
// valid stream in every slot; unset slots leave the child's stdin/stderr unusable. Input reads
// from NUL, and errors reach this process's stderr (or NUL if it has none), so child diagnostics
// land in the test log. Returns nullptr on failure; the caller owns the handle.
[[nodiscard]] inline HANDLE OpenInheritableNul(DWORD access)
{
    SECURITY_ATTRIBUTES inheritable {.nLength = sizeof(inheritable), .bInheritHandle = TRUE};
    const HANDLE nul = CreateFileW(L"NUL",
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &inheritable,
        OPEN_EXISTING,
        0,
        nullptr);
    return nul == INVALID_HANDLE_VALUE ? nullptr : nul;
}

[[nodiscard]] inline HANDLE DuplicateInheritableStandardError()
{
    const HANDLE source = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE duplicate = nullptr;
    if (source != nullptr && source != INVALID_HANDLE_VALUE &&
        DuplicateHandle(GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &duplicate,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS))
    {
        return duplicate;
    }
    return OpenInheritableNul(GENERIC_WRITE);
}

} // namespace launch_as::test
