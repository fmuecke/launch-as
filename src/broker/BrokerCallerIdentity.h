// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <vector>

namespace launch_as::broker
{

struct BrokerCallerIdentity
{
    std::vector<BYTE> userSid;
    std::vector<BYTE> logonSid;
    DWORD sessionId = 0;
    bool isElevated = false;
};

} // namespace launch_as::broker
