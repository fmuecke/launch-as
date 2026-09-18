// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LaunchProcess.h"
#include "LauncherOptions.h"
#include "LicenseHeader.h"

#include <cstddef>
#include <span>
#include <string_view>

int wmain(int argc, wchar_t* argv[])
{
    using namespace launch_as;

    ConfigureUserFacingOutput();

    const std::span arguments(argv, static_cast<std::size_t>(argc));
    if (arguments.size() == 2 && std::wstring_view(arguments[1]) == L"--license")
    {
        PrintLicenseHeader();
        return static_cast<int>(ExitSuccess);
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
