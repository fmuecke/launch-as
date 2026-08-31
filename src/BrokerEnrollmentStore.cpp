// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerEnrollmentStore.h"

#include "BrokerAccountProvisioner.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr DWORD RecordMagic = 0x4553414C; // LASE
constexpr DWORD RecordVersion = 1;
constexpr wchar_t RecordExtension[] = L".enrollment";

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
    const RecordHeader header {.sidBytes = static_cast<DWORD>(accountSid.size())};
    DWORD writeError = WriteExactly(rawFile, &header, sizeof(header));
    if (writeError == ERROR_SUCCESS)
    {
        writeError = WriteExactly(rawFile, accountSid.data(), header.sidBytes);
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
    accountSid.resize(header.sidBytes);
    readError = ReadExactly(rawFile, accountSid.data(), header.sidBytes);
    closeFile();
    if (readError != ERROR_SUCCESS || !IsValidSid(accountSid.data()) ||
        GetLengthSid(accountSid.data()) != accountSid.size())
    {
        accountSid.clear();
        return readError == ERROR_SUCCESS ? ERROR_INVALID_SID : readError;
    }
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

} // namespace launch_as::broker
