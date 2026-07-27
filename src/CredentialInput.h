// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "Credentials.h"

namespace launch_as
{

struct AccountIdentity;

enum class CredentialPromptResult
{
    Success,
    Cancelled,
    Error
};

[[nodiscard]] CredentialPromptResult PromptForPassword(
    const AccountIdentity& account, SecretBuffer& password, bool offerPersistence, bool& persist);
[[nodiscard]] bool ReadPasswordFromStandardInput(SecretBuffer& password);

} // namespace launch_as
