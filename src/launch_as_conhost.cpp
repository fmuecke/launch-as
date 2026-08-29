// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LauncherOptions.h"
#include "LicenseHeader.h"
#include "PseudoConsoleHost.h"

#include <cstddef>
#include <iostream>
#include <span>
#include <string_view>

int wmain(int argumentCount, wchar_t* arguments[])
{
    launch_as::ConfigureUserFacingOutput();

    if (argumentCount == 2 && std::wstring_view(arguments[1]) == L"--license")
    {
        launch_as::PrintLicenseHeader();
        return static_cast<int>(launch_as::ExitSuccess);
    }

    const std::span argumentsView(arguments, static_cast<std::size_t>(argumentCount));
    if (!launch_as::IsPseudoConsoleHostInvocation(argumentsView))
    {
        launch_as::PrintLicenseHeader();
        std::wcerr << L"launch-as-conhost accepts only the broker pseudoconsole invocation.\n";
        return static_cast<int>(launch_as::ExitUsage);
    }
    return static_cast<int>(launch_as::RunPseudoConsoleHost(argumentsView));
}
