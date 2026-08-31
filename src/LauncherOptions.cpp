// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LauncherOptions.h"

#include <cstddef>
#include <iostream>
#include <optional>
#include <string_view>

namespace launch_as
{
namespace
{

} // namespace

void PrintUsage()
{
    std::wcerr << LR"usage(Usage:
  launch-as.exe [run] --user <enrolled-local-user>
                      [--working-directory <directory>]
                      -- <absolute-executable> [arguments...]

  Starts a console session through launch-as-broker. Enroll the account first with the
  elevated launch-as-admin command. The client never accepts or stores passwords.

)usage";
    std::wcerr << std::endl;
}

std::optional<Options> ParseOptions(std::span<wchar_t*> arguments)
{
    if (arguments.size() < 2)
    {
        return std::nullopt;
    }

    const bool explicitRun = std::wstring_view(arguments[1]) == L"run";
    const std::size_t firstOptionIndex = explicitRun ? 2 : 1;

    Options options;
    bool processArgumentsStarted = false;
    for (std::size_t index = firstOptionIndex; index < arguments.size(); ++index)
    {
        const std::wstring_view name(arguments[index]);
        if (name == L"--")
        {
            processArgumentsStarted = true;
            for (++index; index < arguments.size(); ++index)
            {
                options.processArguments.emplace_back(arguments[index]);
            }
            break;
        }
        if (index + 1 >= arguments.size())
        {
            return std::nullopt;
        }
        const std::wstring_view value(arguments[++index]);

        if (name == L"--user")
        {
            options.username = value;
        }
        else if (name == L"--working-directory")
        {
            options.workingDirectory = value;
        }
        else
        {
            return std::nullopt;
        }
    }

    if (options.username.empty() || options.username.find_first_of(L"\\/@") != std::wstring::npos)
    {
        return std::nullopt;
    }
    if (!processArgumentsStarted || options.processArguments.empty())
    {
        return std::nullopt;
    }
    options.executablePath = options.processArguments.front();
    options.processArguments.erase(options.processArguments.begin());
    return options;
}

} // namespace launch_as
