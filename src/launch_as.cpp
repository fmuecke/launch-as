// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LaunchProcess.h"
#include "LauncherOptions.h"
#include "LauncherVersion.h"
#include "PseudoConsoleHost.h"

#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <span>

namespace
{

void ConfigureUserFacingOutput()
{
    static_cast<void>(_setmode(_fileno(stdout), _O_U8TEXT));
    static_cast<void>(_setmode(_fileno(stderr), _O_U8TEXT));
}

void PrintLicenseHeader()
{
    std::wcerr << L"\nlaunch-as v" << launch_as::LauncherVersion
               << L" - Launcher for repeatable least-privilege execution on Windows\n"
               << L"Copyright (C) 2026 Florian Mücke\n"
               << L"This program comes with ABSOLUTELY NO WARRANTY.\n"
               //<< L"This is free software, and you are welcome to redistribute it under the\n"
               //<< L"terms of the GNU General Public License version 3; see LICENSE for details.\n"
               << std::endl;
}

} // namespace

int wmain(int argc, wchar_t* argv[])
{
    using namespace launch_as;

    ConfigureUserFacingOutput();

    const std::span arguments(argv, static_cast<std::size_t>(argc));
    if (IsPseudoConsoleHostInvocation(arguments))
    {
        return static_cast<int>(RunPseudoConsoleHost(arguments));
    }

    const auto options = ParseOptions(arguments);
    if (!options)
    {
        PrintLicenseHeader();
        PrintUsage();
        return static_cast<int>(ExitUsage);
    }
    if (!ValidateRunPaths(*options))
    {
        return static_cast<int>(ExitFailure);
    }

    auto account = ResolveLocalAccount(options->username);
    if (!account)
    {
        return static_cast<int>(ExitFailure);
    }
    return static_cast<int>(RunBrokerConsole(*account, *options));
}
