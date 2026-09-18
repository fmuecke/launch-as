// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LicenseHeader.h"

#include "LauncherVersion.h"

#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <iostream>

namespace launch_as
{

void ConfigureUserFacingOutput()
{
    static_cast<void>(_setmode(_fileno(stdout), _O_U8TEXT));
    static_cast<void>(_setmode(_fileno(stderr), _O_U8TEXT));
}

void PrintLicenseHeader()
{
    std::wcerr
        << L"\nlaunch-as v" << LauncherVersion << L" - Least-privilege Launcher\n"
        << L"Copyright (C) 2026 Florian Mücke - This program comes with ABSOLUTELY NO WARRANTY.\n"
        << L"This is free software - you are welcome to redistribute it under the\n"
        << L"terms of the GNU General Public License version 3; see LICENSE for details.\n"

        << std::endl;
}

} // namespace launch_as
