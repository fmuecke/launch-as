// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#pragma once

#include "Credentials.h"

namespace sandbox_launcher
{

struct AccountIdentity;

enum class CredentialPromptResult
{
    Success,
    Cancelled,
    Error
};

[[nodiscard]] CredentialPromptResult PromptForPassword(const AccountIdentity& account,
                                                       SecretBuffer& password,
                                                       bool offerPersistence, bool& persist);
[[nodiscard]] bool ReadPasswordFromStandardInput(SecretBuffer& password);

} // namespace sandbox_launcher
