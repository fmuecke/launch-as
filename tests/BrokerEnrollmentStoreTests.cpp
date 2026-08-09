// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerEnrollmentStore.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <string>
#include <vector>

namespace
{

class TemporaryDirectory final
{
  public:
    TemporaryDirectory()
    {
        std::array<wchar_t, MAX_PATH> temporaryPath {};
        const DWORD pathLength =
            GetTempPathW(static_cast<DWORD>(temporaryPath.size()), temporaryPath.data());
        if (pathLength == 0 || pathLength >= temporaryPath.size())
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
    }

    ~TemporaryDirectory()
    {
        for (const wchar_t* fileName :
            {L"First.enrollment", L"Second.enrollment", L"Corrupt.enrollment"})
        {
            DeleteFileW((path_ + L"\\" + fileName).c_str());
        }
        RemoveDirectoryW(path_.c_str());
    }

    [[nodiscard]] bool created() const noexcept { return !path_.empty(); }
    [[nodiscard]] const std::wstring& path() const noexcept { return path_; }

  private:
    std::wstring path_;
};

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] bool CreateEmptyFile(std::wstring_view path)
{
    const std::wstring filePath(path);
    const HANDLE file = CreateFileW(
        filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    CloseHandle(file);
    return true;
}

[[nodiscard]] bool CreateBuiltinUsersSid(std::vector<BYTE>& sid)
{
    sid.resize(SECURITY_MAX_SID_SIZE);
    DWORD sidBytes = static_cast<DWORD>(sid.size());
    if (!CreateWellKnownSid(WinBuiltinUsersSid, nullptr, sid.data(), &sidBytes))
    {
        sid.clear();
        return false;
    }
    sid.resize(sidBytes);
    return true;
}

} // namespace

int wmain()
{
    TemporaryDirectory directory;
    std::vector<BYTE> accountSid;
    if (!Expect(directory.created(), L"Could not create the temporary enrollment directory.") ||
        !Expect(CreateBuiltinUsersSid(accountSid), L"Could not create a test SID."))
    {
        return 1;
    }

    launch_as::broker::EnrollmentStore store(directory.path());
    std::vector<BYTE> loadedSid;
    std::vector<std::wstring> accounts;
    if (!Expect(store.Store(L"Second", accountSid) == ERROR_SUCCESS,
            L"Could not store the second enrollment.") ||
        !Expect(store.Store(L"First", accountSid) == ERROR_SUCCESS,
            L"Could not store the first enrollment.") ||
        !Expect(store.Load(L"First", loadedSid) == ERROR_SUCCESS &&
                    EqualSid(accountSid.data(), loadedSid.data()) != FALSE,
            L"Stored enrollment did not retain its SID.") ||
        !Expect(store.List(accounts) == ERROR_SUCCESS &&
                    accounts == std::vector<std::wstring> {L"First", L"Second"},
            L"Enrollment list was not complete and sorted.") ||
        !Expect(store.Store(L"bad/name", accountSid) == ERROR_INVALID_PARAMETER,
            L"Enrollment store accepted an invalid account name.") ||
        !Expect(CreateEmptyFile(directory.path() + L"\\Corrupt.enrollment"),
            L"Could not create a corrupt enrollment record.") ||
        !Expect(store.Load(L"Corrupt", loadedSid) == ERROR_HANDLE_EOF,
            L"Enrollment store accepted a truncated record."))
    {
        return 1;
    }
    return 0;
}
