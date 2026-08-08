// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerCredentialStore.h"
#include "Win32Support.h"

#include <Windows.h>
#include <algorithm>
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
        const DWORD length =
            GetTempPathW(static_cast<DWORD>(temporaryPath.size()), temporaryPath.data());
        if (length == 0 || length >= temporaryPath.size())
        {
            return;
        }
        path_ = std::wstring(temporaryPath.data(), length) + L"launch-as-credential-test-" +
                std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
        created_ = CreateDirectoryW(path_.c_str(), nullptr) != FALSE;
    }

    ~TemporaryDirectory()
    {
        if (created_)
        {
            DeleteFileW((path_ + L"\\agent-sandbox.blob").c_str());
            DeleteFileW((path_ + L"\\agent-sandbox.blob.tmp").c_str());
            RemoveDirectoryW(path_.c_str());
        }
    }

    [[nodiscard]] bool created() const noexcept { return created_; }
    [[nodiscard]] std::wstring_view path() const noexcept { return path_; }

  private:
    std::wstring path_;
    bool created_ = false;
};

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] std::vector<BYTE> ReadBlob(std::wstring_view path)
{
    launch_as::UniqueHandle file(
        CreateFileW(path.data(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!file)
    {
        return {};
    }
    LARGE_INTEGER size {};
    if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 || size.QuadPart > 64 * 1024)
    {
        return {};
    }
    std::vector<BYTE> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(
            file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &bytesRead, nullptr) ||
        bytesRead != bytes.size())
    {
        return {};
    }
    return bytes;
}

} // namespace

int wmain()
{
    TemporaryDirectory directory;
    if (!Expect(directory.created(), L"Could not create the disposable credential directory."))
    {
        return 1;
    }

    const std::array password {
        L'g',
        L'a',
        L't',
        L'e',
        L'w',
        L'a',
        L'y',
        L'-',
        L's',
        L'e',
        L'c',
        L'r',
        L'e',
        L't',
        L'-',
        L'9',
        L'8',
        L'3',
        L'!'
    };
    launch_as::broker::CredentialStore store(directory.path());
    if (!Expect(store.Store(L"agent-sandbox", password) == ERROR_SUCCESS,
            L"Could not protect the credential."))
    {
        return 1;
    }

    const std::vector<BYTE> blob =
        ReadBlob(std::wstring(directory.path()) + L"\\agent-sandbox.blob");
    const auto* passwordBytes = reinterpret_cast<const BYTE*>(password.data());
    if (!Expect(!blob.empty(), L"Credential blob was not written.") ||
        !Expect(std::search(
                    blob.begin(), blob.end(), passwordBytes, passwordBytes + sizeof(password)) ==
                    blob.end(),
            L"Credential blob contains the plaintext password."))
    {
        return 1;
    }

    launch_as::broker::SecurePassword loadedPassword;
    if (!Expect(store.Load(L"agent-sandbox", loadedPassword) == ERROR_SUCCESS,
            L"Could not unprotect the credential.") ||
        !Expect(std::ranges::equal(loadedPassword.characters(), password),
            L"Unprotected credential did not match the stored password."))
    {
        return 1;
    }
    return 0;
}
