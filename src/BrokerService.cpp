// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerServiceRuntime.h"
#include "LicenseHeader.h"

#include <Windows.h>
#include <string_view>

int wmain(int argumentCount, wchar_t* arguments[])
{
    launch_as::ConfigureUserFacingOutput();
    if (argumentCount == 2 && std::wstring_view(arguments[1]) == L"--license")
    {
        launch_as::PrintLicenseHeader();
        return ERROR_SUCCESS;
    }
    return RunBrokerService();
}
