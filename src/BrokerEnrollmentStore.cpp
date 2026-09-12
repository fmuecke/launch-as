// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerEnrollmentStore.h"

#include "BrokerAccountProvisioner.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <string>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr DWORD RecordMagic = 0x4553414C; // LASE
// Bumped from 1: the record now carries a trailing HMAC tag, so a v1 record fails the version
// check and is treated as absent rather than silently trusted without a tag.
constexpr DWORD RecordVersion = 2;
constexpr wchar_t RecordExtension[] = L".enrollment";
constexpr wchar_t MachineKeyFileName[] = L"\\enrollment.key";
constexpr std::size_t MachineKeyBytes = 32;
constexpr std::size_t RecordTagBytes = 32; // HMAC-SHA256 digest size

struct RecordHeader
{
    DWORD magic = RecordMagic;
    DWORD version = RecordVersion;
    DWORD sidBytes = 0;
};

[[nodiscard]] DWORD ReadExactly(HANDLE file, void* buffer, DWORD bytes)
{
    DWORD bytesRead = 0;
    if (!ReadFile(file, buffer, bytes, &bytesRead, nullptr))
    {
        const DWORD readError = GetLastError();
        return readError;
    }
    return bytesRead == bytes ? ERROR_SUCCESS : ERROR_HANDLE_EOF;
}

[[nodiscard]] DWORD WriteExactly(HANDLE file, const void* buffer, DWORD bytes)
{
    DWORD bytesWritten = 0;
    if (!WriteFile(file, buffer, bytes, &bytesWritten, nullptr))
    {
        const DWORD writeError = GetLastError();
        return writeError;
    }
    return bytesWritten == bytes ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
}

[[nodiscard]] DWORD GenerateMachineKey(std::array<BYTE, MachineKeyBytes>& key)
{
    const NTSTATUS status = BCryptGenRandom(
        nullptr, key.data(), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status >= 0 ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}

[[nodiscard]] DWORD WriteMachineKeyFile(
    const std::wstring& path, const std::array<BYTE, MachineKeyBytes>& key)
{
    const std::wstring temporaryPath = path + L".tmp";
    HANDLE rawFile = CreateFileW(temporaryPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (rawFile == INVALID_HANDLE_VALUE)
    {
        return GetLastError();
    }
    DWORD writeError = WriteExactly(rawFile, key.data(), static_cast<DWORD>(key.size()));
    if (writeError == ERROR_SUCCESS && !FlushFileBuffers(rawFile))
    {
        writeError = GetLastError();
    }
    CloseHandle(rawFile);
    if (writeError != ERROR_SUCCESS)
    {
        DeleteFileW(temporaryPath.c_str());
        return writeError;
    }
    if (!MoveFileExW(temporaryPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING))
    {
        const DWORD moveError = GetLastError();
        DeleteFileW(temporaryPath.c_str());
        return moveError;
    }
    return ERROR_SUCCESS;
}

// The enrollment records themselves carry no secret; the HMAC over them is only as good as this
// key staying inside the SYSTEM/Administrators-only directory the records already live in.
[[nodiscard]] DWORD LoadOrCreateMachineKey(
    const std::wstring& path, std::array<BYTE, MachineKeyBytes>& key)
{
    const auto fail = [&key](DWORD error)
    {
        SecureZeroMemory(key.data(), key.size());
        return error;
    };
    HANDLE rawFile = CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (rawFile != INVALID_HANDLE_VALUE)
    {
        const DWORD readError = ReadExactly(rawFile, key.data(), static_cast<DWORD>(key.size()));
        CloseHandle(rawFile);
        return readError == ERROR_SUCCESS ? ERROR_SUCCESS : fail(readError);
    }
    const DWORD openError = GetLastError();
    if (openError != ERROR_FILE_NOT_FOUND)
    {
        return fail(openError);
    }
    const DWORD generateError = GenerateMachineKey(key);
    if (generateError != ERROR_SUCCESS)
    {
        return fail(generateError);
    }
    const DWORD writeError = WriteMachineKeyFile(path, key);
    return writeError == ERROR_SUCCESS ? ERROR_SUCCESS : fail(writeError);
}

[[nodiscard]] DWORD ComputeRecordTag(const std::array<BYTE, MachineKeyBytes>& key,
    const RecordHeader& header, const std::vector<BYTE>& accountSid,
    std::array<BYTE, RecordTagBytes>& tag)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0)
    {
        return ERROR_GEN_FAILURE;
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(algorithm,
        &hash,
        nullptr,
        0,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0);
    if (status >= 0)
    {
        status = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<RecordHeader*>(&header)),
            static_cast<ULONG>(sizeof(header)),
            0);
    }
    if (status >= 0 && !accountSid.empty())
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
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status >= 0 ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
}

[[nodiscard]] bool ConstantTimeEqual(
    const std::array<BYTE, RecordTagBytes>& a, const std::array<BYTE, RecordTagBytes>& b) noexcept
{
    BYTE difference = 0;
    for (std::size_t index = 0; index < a.size(); ++index)
    {
        difference |= static_cast<BYTE>(a[index] ^ b[index]);
    }
    return difference == 0;
}

} // namespace

EnrollmentStore::EnrollmentStore(std::wstring_view directory) : directory_(directory) {}

DWORD EnrollmentStore::Store(
    std::wstring_view accountName, const std::vector<BYTE>& accountSid) const
{
    if (!IsValidBrokerAccountName(accountName) || accountSid.empty() ||
        !IsValidSid(const_cast<BYTE*>(accountSid.data())))
    {
        return ERROR_INVALID_PARAMETER;
    }
    std::array<BYTE, MachineKeyBytes> machineKey {};
    const DWORD keyError = LoadOrCreateMachineKey(MachineKeyPath(), machineKey);
    if (keyError != ERROR_SUCCESS)
    {
        return keyError;
    }
    const RecordHeader header {.sidBytes = static_cast<DWORD>(accountSid.size())};
    std::array<BYTE, RecordTagBytes> tag {};
    const DWORD tagError = ComputeRecordTag(machineKey, header, accountSid, tag);
    SecureZeroMemory(machineKey.data(), machineKey.size());
    if (tagError != ERROR_SUCCESS)
    {
        return tagError;
    }

    const std::wstring path = RecordPath(accountName);
    const std::wstring temporaryPath = path + L".tmp";
    HANDLE rawFile = CreateFileW(temporaryPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (rawFile == INVALID_HANDLE_VALUE)
    {
        const DWORD createError = GetLastError();
        return createError;
    }
    const auto closeFile = [&rawFile]
    {
        if (rawFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(rawFile);
            rawFile = INVALID_HANDLE_VALUE;
        }
    };
    DWORD writeError = WriteExactly(rawFile, &header, sizeof(header));
    if (writeError == ERROR_SUCCESS)
    {
        writeError = WriteExactly(rawFile, accountSid.data(), header.sidBytes);
    }
    if (writeError == ERROR_SUCCESS)
    {
        writeError = WriteExactly(rawFile, tag.data(), static_cast<DWORD>(tag.size()));
    }
    if (writeError == ERROR_SUCCESS && !FlushFileBuffers(rawFile))
    {
        writeError = GetLastError();
    }
    closeFile();
    if (writeError != ERROR_SUCCESS)
    {
        DeleteFileW(temporaryPath.c_str());
        return writeError;
    }
    if (!MoveFileExW(temporaryPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING))
    {
        const DWORD moveError = GetLastError();
        DeleteFileW(temporaryPath.c_str());
        return moveError;
    }
    return ERROR_SUCCESS;
}

DWORD EnrollmentStore::Load(std::wstring_view accountName, std::vector<BYTE>& accountSid) const
{
    accountSid.clear();
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }
    HANDLE rawFile = CreateFileW(RecordPath(accountName).c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (rawFile == INVALID_HANDLE_VALUE)
    {
        const DWORD openError = GetLastError();
        return openError;
    }
    const auto closeFile = [&rawFile] { CloseHandle(rawFile); };
    RecordHeader header {};
    DWORD readError = ReadExactly(rawFile, &header, sizeof(header));
    if (readError != ERROR_SUCCESS || header.magic != RecordMagic ||
        header.version != RecordVersion || header.sidBytes == 0 ||
        header.sidBytes > SECURITY_MAX_SID_SIZE)
    {
        closeFile();
        return readError == ERROR_SUCCESS ? ERROR_INVALID_DATA : readError;
    }
    std::vector<BYTE> sid(header.sidBytes);
    readError = ReadExactly(rawFile, sid.data(), header.sidBytes);
    std::array<BYTE, RecordTagBytes> storedTag {};
    if (readError == ERROR_SUCCESS)
    {
        readError = ReadExactly(rawFile, storedTag.data(), static_cast<DWORD>(storedTag.size()));
    }
    closeFile();
    if (readError != ERROR_SUCCESS || !IsValidSid(sid.data()) ||
        GetLengthSid(sid.data()) != sid.size())
    {
        return readError == ERROR_SUCCESS ? ERROR_INVALID_SID : readError;
    }

    std::array<BYTE, MachineKeyBytes> machineKey {};
    const DWORD keyError = LoadOrCreateMachineKey(MachineKeyPath(), machineKey);
    if (keyError != ERROR_SUCCESS)
    {
        return keyError;
    }
    std::array<BYTE, RecordTagBytes> expectedTag {};
    const DWORD tagError = ComputeRecordTag(machineKey, header, sid, expectedTag);
    SecureZeroMemory(machineKey.data(), machineKey.size());
    if (tagError != ERROR_SUCCESS)
    {
        return tagError;
    }
    if (!ConstantTimeEqual(storedTag, expectedTag))
    {
        return ERROR_ACCESS_DENIED;
    }

    accountSid = std::move(sid);
    return ERROR_SUCCESS;
}

DWORD EnrollmentStore::Remove(std::wstring_view accountName) const
{
    if (!IsValidBrokerAccountName(accountName))
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (DeleteFileW(RecordPath(accountName).c_str()))
    {
        return ERROR_SUCCESS;
    }
    const DWORD removeError = GetLastError();
    return removeError == ERROR_FILE_NOT_FOUND ? ERROR_NOT_FOUND : removeError;
}

DWORD EnrollmentStore::List(std::vector<std::wstring>& accountNames) const
{
    accountNames.clear();
    const std::wstring search = directory_ + L"\\*" + RecordExtension;
    WIN32_FIND_DATAW file {};
    HANDLE find = FindFirstFileW(search.c_str(), &file);
    if (find == INVALID_HANDLE_VALUE)
    {
        const DWORD findError = GetLastError();
        return findError == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : findError;
    }
    do
    {
        const std::wstring_view name(file.cFileName);
        const std::size_t extensionOffset = name.size() - std::size(RecordExtension) + 1;
        const std::wstring_view accountName = name.substr(0, extensionOffset);
        if ((file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
            IsValidBrokerAccountName(accountName))
        {
            accountNames.emplace_back(accountName);
        }
    } while (FindNextFileW(find, &file));
    const DWORD findError = GetLastError();
    FindClose(find);
    if (findError != ERROR_NO_MORE_FILES)
    {
        accountNames.clear();
        return findError;
    }
    std::sort(accountNames.begin(), accountNames.end());
    return ERROR_SUCCESS;
}

std::wstring EnrollmentStore::RecordPath(std::wstring_view accountName) const
{
    return directory_ + L"\\" + std::wstring(accountName) + RecordExtension;
}

std::wstring EnrollmentStore::MachineKeyPath() const { return directory_ + MachineKeyFileName; }

} // namespace launch_as::broker
