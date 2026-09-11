// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerProcessLauncher.h"
#include "BrokerProtocol.h"

#include <Windows.h>
#include <vector>

namespace launch_as::broker
{

struct BrokerCallerIdentity
{
    std::vector<BYTE> userSid;
    std::vector<BYTE> logonSid;
    DWORD sessionId = 0;
    DWORD integrityLevel = 0;
    bool isElevated = false;
};
using ConfigurationRequestHandler = DWORD (*)(void* context, const BrokerRequest& request,
    const BrokerCallerIdentity& caller, std::vector<std::wstring>& accounts);
using LaunchRequestHandler = DWORD (*)(void* context, const BrokerRequest& request,
    const BrokerCallerIdentity& caller, BrokerChildProcess& child);
using SessionFinishedHandler = void (*)(void* context, const BrokerRequest& request);

void ServeControlPipeRequest(HANDLE pipe, HANDLE stopEvent,
    ConfigurationRequestHandler configurationRequestHandler = nullptr,
    void* configurationContext = nullptr, LaunchRequestHandler launchRequestHandler = nullptr,
    void* launchContext = nullptr, SessionFinishedHandler sessionFinishedHandler = nullptr,
    void* sessionFinishedContext = nullptr);

} // namespace launch_as::broker
