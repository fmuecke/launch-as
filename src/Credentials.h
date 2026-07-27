// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "LauncherOptions.h"

#include <Windows.h>
#include <cstddef>
#include <vector>

namespace launch_as
{

struct AccountIdentity;

class SecretBuffer final
{
  public:
    SecretBuffer();
    ~SecretBuffer();

    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;
    SecretBuffer(SecretBuffer&&) = delete;
    SecretBuffer& operator=(SecretBuffer&&) = delete;

    [[nodiscard]] wchar_t* data() noexcept;
    [[nodiscard]] const wchar_t* data() const noexcept;
    [[nodiscard]] std::size_t capacity() const noexcept;
    [[nodiscard]] DWORD byte_size() const noexcept;

    bool set_length(std::size_t length) noexcept;
    bool assign_bytes(const BYTE* bytes, DWORD byteCount);
    void clear() noexcept;

  private:
    std::vector<wchar_t> characters_;
    std::size_t length_ = 0;
};

enum class StoredCredentialResult
{
    Success,
    NotFound,
    Error
};

[[nodiscard]] ExitCode RegisterCredential(const AccountIdentity& account);
[[nodiscard]] ExitCode RegisterCredentialFromStandardInput(const AccountIdentity& account);
[[nodiscard]] ExitCode CredentialStatus(const AccountIdentity& account);
[[nodiscard]] StoredCredentialResult LoadStoredPassword(
    const AccountIdentity& account, SecretBuffer& password);
[[nodiscard]] bool SaveCredential(const AccountIdentity& account, const SecretBuffer& password);
[[nodiscard]] ExitCode ForgetCredential(const AccountIdentity& account);

} // namespace launch_as
