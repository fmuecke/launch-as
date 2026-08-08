// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerCredentialStore.h"

#include <Lmcons.h>
#include <Wincrypt.h>
#include <algorithm>
#include <limits>
#include <new>
#include <utility>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr DWORD MaximumCredentialBytes = 64 * 1024;

class LocalData final
{
  public:
    LocalData() = default;
    ~LocalData()
    {
        if (value_.pbData != nullptr)
        {
            SecureZeroMemory(value_.pbData, value_.cbData);
            LocalFree(value_.pbData);
        }
    }

    LocalData(const LocalData&) = delete;
    LocalData& operator=(const LocalData&) = delete;

    [[nodiscard]] DATA_BLOB* address() noexcept { return &value_; }
    [[nodiscard]] const DATA_BLOB& get() const noexcept { return value_; }

  private:
    DATA_BLOB value_ {};
};

[[nodiscard]] DWORD EnsureDirectory(std::wstring_view directory)
{
    if (CreateDirectoryW(directory.data(), nullptr))
    {
        return ERROR_SUCCESS;
    }
    const DWORD directoryError = GetLastError();
    return directoryError == ERROR_ALREADY_EXISTS ? ERROR_SUCCESS : directoryError;
}

[[nodiscard]] DATA_BLOB ProfileEntropy(std::wstring_view profileId)
{
    return {
        .cbData = static_cast<DWORD>(profileId.size() * sizeof(wchar_t)),
        .pbData = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(profileId.data())),
    };
}

} // namespace

SecurePassword::~SecurePassword() { Clear(); }

void SecurePassword::Clear() noexcept
{
    if (!characters_.empty())
    {
        SecureZeroMemory(characters_.data(), characters_.size() * sizeof(wchar_t));
        characters_.clear();
    }
    length_ = 0;
}

bool SecurePassword::Assign(const BYTE* bytes, DWORD byteCount)
{
    if (bytes == nullptr || byteCount == 0 || byteCount % sizeof(wchar_t) != 0)
    {
        return false;
    }
    const auto* first = reinterpret_cast<const wchar_t*>(bytes);
    Clear();
    try
    {
        length_ = byteCount / sizeof(wchar_t);
        characters_.assign(first, first + length_);
        characters_.push_back(L'\0');
    }
    catch (...)
    {
        Clear();
        throw;
    }
    return true;
}

CredentialStore::CredentialStore(std::wstring_view directory) : directory_(directory) {}

DWORD CredentialStore::Store(std::wstring_view profileId, std::span<const wchar_t> password) const
{
    if (!IsValidProfileId(profileId) || password.empty() ||
        password.size_bytes() > std::numeric_limits<DWORD>::max())
    {
        return ERROR_INVALID_PARAMETER;
    }

    try
    {
        const DWORD directoryError = EnsureDirectory(directory_);
        if (directoryError != ERROR_SUCCESS)
        {
            return directoryError;
        }

        DATA_BLOB input {
            .cbData = static_cast<DWORD>(password.size_bytes()),
            .pbData = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(password.data())),
        };
        DATA_BLOB entropy = ProfileEntropy(profileId);
        LocalData encrypted;
        if (!CryptProtectData(&input,
                L"launch-as broker credential",
                &entropy,
                nullptr,
                nullptr,
                CRYPTPROTECT_UI_FORBIDDEN,
                encrypted.address()))
        {
            const DWORD protectError = GetLastError();
            return protectError;
        }
        if (encrypted.get().cbData == 0 || encrypted.get().cbData > MaximumCredentialBytes)
        {
            return ERROR_INVALID_DATA;
        }

        const std::wstring temporaryPath = BlobPath(profileId) + L".tmp";
        const std::wstring destinationPath = BlobPath(profileId);
        HANDLE rawFile = CreateFileW(temporaryPath.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_HIDDEN,
            nullptr);
        const DWORD createError = rawFile == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        if (rawFile == INVALID_HANDLE_VALUE)
        {
            return createError;
        }

        DWORD bytesWritten = 0;
        const BOOL wroteBlob = WriteFile(
            rawFile, encrypted.get().pbData, encrypted.get().cbData, &bytesWritten, nullptr);
        const DWORD writeError = wroteBlob ? ERROR_SUCCESS : GetLastError();
        const BOOL flushed =
            wroteBlob && bytesWritten == encrypted.get().cbData && FlushFileBuffers(rawFile);
        const DWORD flushError = flushed ? ERROR_SUCCESS : GetLastError();
        CloseHandle(rawFile);
        if (!wroteBlob || bytesWritten != encrypted.get().cbData)
        {
            return wroteBlob ? ERROR_WRITE_FAULT : writeError;
        }
        if (!flushed)
        {
            return flushError;
        }
        if (!MoveFileExW(temporaryPath.c_str(),
                destinationPath.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            const DWORD moveError = GetLastError();
            return moveError;
        }
        return ERROR_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

DWORD CredentialStore::Load(std::wstring_view profileId, SecurePassword& password) const
{
    password.Clear();
    if (!IsValidProfileId(profileId))
    {
        return ERROR_INVALID_PARAMETER;
    }

    try
    {
        HANDLE rawFile = CreateFileW(BlobPath(profileId).c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
        const DWORD openError = rawFile == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        if (rawFile == INVALID_HANDLE_VALUE)
        {
            return openError;
        }
        LARGE_INTEGER fileSize {};
        const BOOL sized = GetFileSizeEx(rawFile, &fileSize);
        const DWORD sizeError = sized ? ERROR_SUCCESS : GetLastError();
        if (!sized || fileSize.QuadPart <= 0 || fileSize.QuadPart > MaximumCredentialBytes)
        {
            CloseHandle(rawFile);
            return sized ? ERROR_INVALID_DATA : sizeError;
        }
        std::vector<BYTE> encrypted(static_cast<std::size_t>(fileSize.QuadPart));
        DWORD bytesRead = 0;
        const BOOL readBlob = ReadFile(
            rawFile, encrypted.data(), static_cast<DWORD>(encrypted.size()), &bytesRead, nullptr);
        const DWORD readError = readBlob ? ERROR_SUCCESS : GetLastError();
        CloseHandle(rawFile);
        if (!readBlob || bytesRead != encrypted.size())
        {
            return readBlob ? ERROR_INVALID_DATA : readError;
        }

        DATA_BLOB input {
            .cbData = static_cast<DWORD>(encrypted.size()),
            .pbData = encrypted.data(),
        };
        DATA_BLOB entropy = ProfileEntropy(profileId);
        LocalData plaintext;
        if (!CryptUnprotectData(&input,
                nullptr,
                &entropy,
                nullptr,
                nullptr,
                CRYPTPROTECT_UI_FORBIDDEN,
                plaintext.address()))
        {
            const DWORD unprotectError = GetLastError();
            return unprotectError;
        }
        if (!password.Assign(plaintext.get().pbData, plaintext.get().cbData))
        {
            return ERROR_INVALID_DATA;
        }
        return ERROR_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

DWORD CredentialStore::Remove(std::wstring_view profileId) const
{
    if (!IsValidProfileId(profileId))
    {
        return ERROR_INVALID_PARAMETER;
    }
    const std::wstring blobPath = BlobPath(profileId);
    if (DeleteFileW(blobPath.c_str()))
    {
        return ERROR_SUCCESS;
    }
    const DWORD deleteError = GetLastError();
    return deleteError == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : deleteError;
}

bool CredentialStore::Exists(std::wstring_view profileId) const
{
    if (!IsValidProfileId(profileId))
    {
        return false;
    }
    const DWORD attributes = GetFileAttributesW(BlobPath(profileId).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

DWORD CredentialStore::List(std::vector<std::wstring>& profileIds) const
{
    profileIds.clear();
    WIN32_FIND_DATAW entry {};
    const std::wstring pattern = directory_ + L"\\*.blob";
    HANDLE rawFind = FindFirstFileW(pattern.c_str(), &entry);
    if (rawFind == INVALID_HANDLE_VALUE)
    {
        const DWORD findError = GetLastError();
        return findError == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : findError;
    }
    do
    {
        const std::wstring_view name(entry.cFileName);
        constexpr std::wstring_view extension = L".blob";
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
            name.size() > extension.size() && name.ends_with(extension))
        {
            const std::wstring_view profileId = name.substr(0, name.size() - extension.size());
            if (IsValidProfileId(profileId))
            {
                profileIds.emplace_back(profileId);
            }
        }
    } while (FindNextFileW(rawFind, &entry));
    const DWORD findError = GetLastError();
    FindClose(rawFind);
    if (findError != ERROR_NO_MORE_FILES)
    {
        profileIds.clear();
        return findError;
    }
    std::ranges::sort(profileIds);
    return ERROR_SUCCESS;
}

bool CredentialStore::IsValidProfileId(std::wstring_view profileId) const noexcept
{
    constexpr std::wstring_view invalidCharacters = L"\\/[]:;|=,+*?<>\"";
    return !profileId.empty() && profileId.size() <= UNLEN &&
           profileId.find_first_of(invalidCharacters) == std::wstring_view::npos;
}

std::wstring CredentialStore::BlobPath(std::wstring_view profileId) const
{
    return directory_ + L"\\" + std::wstring(profileId) + L".blob";
}

} // namespace launch_as::broker
