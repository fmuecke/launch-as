// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAdminCli.h"
#include "BrokerServiceRuntime.h"

#include <Windows.h>

int wmain(int argumentCount, wchar_t* arguments[])
{
    return argumentCount > 1 ? RunBrokerAdminCli(argumentCount, arguments) : RunBrokerService();
}
