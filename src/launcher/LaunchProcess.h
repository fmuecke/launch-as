// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "LauncherOptions.h"

#include <Windows.h>
#include <optional>
#include <string>

namespace launch_as
{

struct AccountIdentity
{
    std::wstring username;
    std::wstring qualifiedUsername;
    std::wstring sid;
};

[[nodiscard]] std::optional<AccountIdentity> ResolveLocalAccount(const std::wstring& username);
[[nodiscard]] bool ValidateRunPaths(const Options& options);
[[nodiscard]] ExitCode RunBrokerConsole(const AccountIdentity& account, const Options& options);
[[nodiscard]] ExitCode RunBrokerInteractive(const AccountIdentity& account, const Options& options);

} // namespace launch_as
