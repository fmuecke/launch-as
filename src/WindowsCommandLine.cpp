// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "WindowsCommandLine.h"

#include <cstddef>
#include <stdexcept>

namespace launch_as
{

std::wstring QuoteWindowsCommandLineArgument(std::wstring_view argument)
{
    if (argument.empty())
    {
        return L"\"\"";
    }
    if (argument.find_first_of(L" \t\n\v\"") == std::wstring_view::npos)
    {
        return std::wstring(argument);
    }

    std::wstring quoted;
    quoted.push_back(L'"');
    std::size_t backslashes = 0;
    for (const wchar_t character : argument)
    {
        if (character == L'\\')
        {
            ++backslashes;
            continue;
        }

        if (character == L'"')
        {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(L'"');
            backslashes = 0;
            continue;
        }

        quoted.append(backslashes, L'\\');
        backslashes = 0;
        quoted.push_back(character);
    }
    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

std::wstring BuildWindowsCommandLine(
    std::wstring_view executable, std::span<const std::wstring> arguments)
{
    if (executable.find(L'"') != std::wstring_view::npos)
    {
        throw std::invalid_argument("The executable path cannot contain a quote.");
    }

    // argv[0] has different parsing rules from the remaining arguments: backslashes are
    // literal and a quote terminates the quoted executable name. Always quote the token and
    // reject embedded quotes above rather than applying the general argument escaping rules.
    std::wstring commandLine;
    commandLine.reserve(executable.size() + 2);
    commandLine.push_back(L'"');
    commandLine.append(executable);
    commandLine.push_back(L'"');
    for (const std::wstring& argument : arguments)
    {
        commandLine.push_back(L' ');
        commandLine += QuoteWindowsCommandLineArgument(argument);
    }
    return commandLine;
}

} // namespace launch_as
