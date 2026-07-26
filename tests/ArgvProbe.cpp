// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#include "CommandLineTestArguments.h"

#include <cstddef>
#include <iostream>
#include <string_view>

int wmain(int argc, wchar_t* argv[])
{
    const auto actualCount = static_cast<std::size_t>(argc - 1);
    if (actualCount != CommandLineTestArguments.size())
    {
        std::wcerr << L"Expected " << CommandLineTestArguments.size() << L" arguments, received "
                   << actualCount << L".\n";
        return 1;
    }

    for (std::size_t index = 0; index < CommandLineTestArguments.size(); ++index)
    {
        const std::wstring_view actual(argv[index + 1]);
        if (actual != CommandLineTestArguments[index])
        {
            std::wcerr << L"Argument " << index << L" did not round-trip.\n";
            return static_cast<int>(index + 2);
        }
    }
    return 0;
}
