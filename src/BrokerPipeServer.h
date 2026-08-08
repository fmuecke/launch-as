// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>

namespace launch_as::broker
{

using RegisterRequestHandler = DWORD (*)(void* context);

void ServeControlPipeRequest(HANDLE pipe, HANDLE stopEvent,
    RegisterRequestHandler registerRequestHandler = nullptr, void* registrationContext = nullptr);

} // namespace launch_as::broker
