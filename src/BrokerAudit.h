// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <span>
#include <string>

namespace launch_as::broker
{

enum class BrokerAuditEvent : DWORD
{
    LaunchAllowed = 1,
    LaunchRejected = 2,
    ConfigurationChanged = 3,
    ConfigurationRejected = 4,
    ControlPipeCreationFailed = 5,
};

[[nodiscard]] DWORD RegisterBrokerEventSource();
[[nodiscard]] DWORD UnregisterBrokerEventSource();
[[nodiscard]] DWORD WriteBrokerAuditEvent(
    WORD type, BrokerAuditEvent event, std::span<const std::wstring> fields);

} // namespace launch_as::broker
