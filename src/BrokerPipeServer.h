// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerProtocol.h"

#include <Windows.h>
#include <vector>

namespace launch_as::broker
{

using RegisterRequestHandler = DWORD (*)(void* context);
struct BrokerCallerIdentity
{
    std::vector<BYTE> userSid;
    DWORD sessionId = 0;
    DWORD integrityLevel = 0;
};
using LaunchRequestHandler = DWORD (*)(
    void* context, const BrokerRequest& request, const BrokerCallerIdentity& caller);

void ServeControlPipeRequest(HANDLE pipe, HANDLE stopEvent,
    RegisterRequestHandler registerRequestHandler = nullptr, void* registrationContext = nullptr,
    LaunchRequestHandler launchRequestHandler = nullptr, void* launchContext = nullptr);

} // namespace launch_as::broker
