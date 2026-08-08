// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

class SecurePassword;
[[nodiscard]] DWORD GenerateBrokerPassword(SecurePassword& password);

class SecurePassword final
{
  public:
    SecurePassword() = default;
    ~SecurePassword();

    SecurePassword(const SecurePassword&) = delete;
    SecurePassword& operator=(const SecurePassword&) = delete;

    [[nodiscard]] std::span<const wchar_t> characters() const noexcept
    {
        return {characters_.data(), length_};
    }
    [[nodiscard]] const wchar_t* c_str() const noexcept
    {
        return characters_.empty() ? L"" : characters_.data();
    }
    void Clear() noexcept;

  private:
    [[nodiscard]] bool Assign(const BYTE* bytes, DWORD byteCount);

    std::vector<wchar_t> characters_;
    std::size_t length_ = 0;

    friend class CredentialStore;
    friend DWORD GenerateBrokerPassword(SecurePassword& password);
};

class CredentialStore final
{
  public:
    explicit CredentialStore(std::wstring_view directory);

    [[nodiscard]] DWORD Store(std::wstring_view profileId, std::span<const wchar_t> password) const;
    [[nodiscard]] DWORD Load(std::wstring_view profileId, SecurePassword& password) const;
    [[nodiscard]] DWORD Remove(std::wstring_view profileId) const;
    [[nodiscard]] bool Exists(std::wstring_view profileId) const;
    [[nodiscard]] DWORD List(std::vector<std::wstring>& profileIds) const;

  private:
    [[nodiscard]] bool IsValidProfileId(std::wstring_view profileId) const noexcept;
    [[nodiscard]] std::wstring BlobPath(std::wstring_view profileId) const;

    std::wstring directory_;
};

} // namespace launch_as::broker
