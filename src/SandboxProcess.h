// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#pragma once

#include "LauncherOptions.h"

#include <Windows.h>
#include <optional>
#include <string>

namespace sandbox_launcher
{

struct AccountIdentity
{
    std::wstring username;
    std::wstring qualifiedUsername;
    std::wstring sid;
    std::wstring testCredentialTag;
};

[[nodiscard]] std::optional<AccountIdentity> ResolveLocalAccount(const std::wstring& username);
[[nodiscard]] bool ValidateNonAdministrativeToken(HANDLE token, const AccountIdentity& account);
[[nodiscard]] bool ValidateRunPaths(const Options& options);
[[nodiscard]] ExitCode RunSandboxProcess(const AccountIdentity& account, const Options& options);

} // namespace sandbox_launcher
