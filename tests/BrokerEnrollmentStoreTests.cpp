// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerEnrollmentStore.h"
#include "TestSupport.h"

#include <Windows.h>
#include <array>
#include <bcrypt.h>
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
            {L"First.enrollment",
                L"Legacy.enrollment",
                L"Second.enrollment",
                L"Corrupt.enrollment",
                L"Tampered.enrollment",
                L"enrollment.key"})
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

// Flips the last byte of the file, which always lands inside the trailing HMAC tag regardless of
// the stored SID's length, without hardcoding the on-disk record layout.
[[nodiscard]] bool FlipLastByte(std::wstring_view path)
{
    const std::wstring filePath(path);
    HANDLE file = CreateFileW(filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    LARGE_INTEGER fileSize {};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0)
    {
        CloseHandle(file);
        return false;
    }
    LARGE_INTEGER lastByteOffset {};
    lastByteOffset.QuadPart = fileSize.QuadPart - 1;
    BYTE value = 0;
    DWORD transferred = 0;
    const bool read = SetFilePointerEx(file, lastByteOffset, nullptr, FILE_BEGIN) != FALSE &&
                      ReadFile(file, &value, 1, &transferred, nullptr) != FALSE && transferred == 1;
    if (!read)
    {
        CloseHandle(file);
        return false;
    }
    value = static_cast<BYTE>(~value);
    const bool wrote = SetFilePointerEx(file, lastByteOffset, nullptr, FILE_BEGIN) != FALSE &&
                       WriteFile(file, &value, 1, &transferred, nullptr) != FALSE &&
                       transferred == 1;
    CloseHandle(file);
    return wrote;
}

struct LegacyRecordHeader
{
    DWORD magic = 0x4553414C; // LASE
    DWORD version = 2;
    DWORD sidBytes = 0;
};

[[nodiscard]] bool WriteLegacyEnrollmentRecord(
    std::wstring_view directory, const std::vector<BYTE>& accountSid)
{
    std::array<BYTE, 32> machineKey {};
    HANDLE keyFile = CreateFileW((std::wstring(directory) + L"\\enrollment.key").c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (keyFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    DWORD keyBytes = 0;
    const bool readKey = ReadFile(keyFile,
                             machineKey.data(),
                             static_cast<DWORD>(machineKey.size()),
                             &keyBytes,
                             nullptr) != FALSE &&
                         keyBytes == machineKey.size();
    CloseHandle(keyFile);
    if (!readKey)
    {
        SecureZeroMemory(machineKey.data(), machineKey.size());
        return false;
    }

    const LegacyRecordHeader header {.sidBytes = static_cast<DWORD>(accountSid.size())};
    std::array<BYTE, 32> tag {};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status >= 0)
    {
        status = BCryptCreateHash(algorithm,
            &hash,
            nullptr,
            0,
            machineKey.data(),
            static_cast<ULONG>(machineKey.size()),
            0);
    }
    if (status >= 0)
    {
        status = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<LegacyRecordHeader*>(&header)),
            static_cast<ULONG>(sizeof(header)),
            0);
    }
    if (status >= 0)
    {
        status = BCryptHashData(
            hash, const_cast<PUCHAR>(accountSid.data()), static_cast<ULONG>(accountSid.size()), 0);
    }
    if (status >= 0)
    {
        status = BCryptFinishHash(hash, tag.data(), static_cast<ULONG>(tag.size()), 0);
    }
    if (hash != nullptr)
    {
        BCryptDestroyHash(hash);
    }
    if (algorithm != nullptr)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    SecureZeroMemory(machineKey.data(), machineKey.size());
    if (status < 0)
    {
        return false;
    }

    HANDLE recordFile = CreateFileW((std::wstring(directory) + L"\\Legacy.enrollment").c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (recordFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    DWORD bytesWritten = 0;
    const bool wroteHeader =
        WriteFile(recordFile, &header, sizeof(header), &bytesWritten, nullptr) != FALSE &&
        bytesWritten == sizeof(header);
    const bool wroteSid = wroteHeader &&
                          WriteFile(recordFile,
                              accountSid.data(),
                              static_cast<DWORD>(accountSid.size()),
                              &bytesWritten,
                              nullptr) != FALSE &&
                          bytesWritten == accountSid.size();
    const bool wroteTag =
        wroteSid &&
        WriteFile(recordFile, tag.data(), static_cast<DWORD>(tag.size()), &bytesWritten, nullptr) !=
            FALSE &&
        bytesWritten == tag.size();
    CloseHandle(recordFile);
    return wroteTag;
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
    launch_as::broker::EnrollmentRecord loadedRecord;
    std::vector<std::wstring> accounts;
    if (!Expect(store.Store(L"Second", accountSid) == ERROR_SUCCESS,
            L"Could not store the second enrollment.") ||
        !Expect(store.Store(L"First", accountSid) == ERROR_SUCCESS,
            L"Could not store the first enrollment.") ||
        !Expect(store.Load(L"First", loadedRecord) == ERROR_SUCCESS &&
                    !loadedRecord.brokerManaged &&
                    EqualSid(accountSid.data(), loadedRecord.accountSid.data()) != FALSE,
            L"Stored external enrollment did not retain its SID and ownership.") ||
        !Expect(WriteLegacyEnrollmentRecord(directory.path(), accountSid),
            L"Could not write an authenticated legacy enrollment record.") ||
        !Expect(store.Load(L"Legacy", loadedRecord) == ERROR_SUCCESS &&
                    !loadedRecord.brokerManaged &&
                    EqualSid(accountSid.data(), loadedRecord.accountSid.data()) != FALSE,
            L"Legacy enrollment was not retained as external.") ||
        !Expect(store.List(accounts) == ERROR_SUCCESS &&
                    accounts == std::vector<std::wstring> {L"First", L"Legacy", L"Second"},
            L"Enrollment list was not complete and sorted.") ||
        !Expect(store.Store(L"bad/name", accountSid) == ERROR_INVALID_PARAMETER,
            L"Enrollment store accepted an invalid account name.") ||
        !Expect(CreateEmptyFile(directory.path() + L"\\Corrupt.enrollment"),
            L"Could not create a corrupt enrollment record.") ||
        !Expect(store.Load(L"Corrupt", loadedSid) == ERROR_HANDLE_EOF,
            L"Enrollment store accepted a truncated record.") ||
        !Expect(store.Store(L"Tampered", accountSid, true) == ERROR_SUCCESS,
            L"Could not store the tamper-test enrollment.") ||
        !Expect(
            store.Load(L"Tampered", loadedRecord) == ERROR_SUCCESS && loadedRecord.brokerManaged,
            L"Stored broker-managed enrollment did not retain its ownership.") ||
        !Expect(FlipLastByte(directory.path() + L"\\Tampered.enrollment"),
            L"Could not tamper with the stored enrollment record.") ||
        !Expect(store.Load(L"Tampered", loadedSid) != ERROR_SUCCESS,
            L"Enrollment store accepted a tampered record."))
    {
        return 1;
    }
    return 0;
}
