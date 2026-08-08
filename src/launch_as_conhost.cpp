// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LauncherOptions.h"
#include "PseudoConsoleHost.h"

#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <span>

int wmain(int argumentCount, wchar_t* arguments[])
{
    static_cast<void>(_setmode(_fileno(stdout), _O_U8TEXT));
    static_cast<void>(_setmode(_fileno(stderr), _O_U8TEXT));

    const std::span argumentsView(arguments, static_cast<std::size_t>(argumentCount));
    if (!launch_as::IsPseudoConsoleHostInvocation(argumentsView))
    {
        std::wcerr << L"launch-as-conhost accepts only the broker pseudoconsole invocation.\n";
        return static_cast<int>(launch_as::ExitUsage);
    }
    return static_cast<int>(launch_as::RunPseudoConsoleHost(argumentsView));
}
