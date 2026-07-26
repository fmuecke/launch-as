// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#include "LauncherOptions.h"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace sandbox_launcher
{
namespace
{

constexpr std::size_t MaximumTestCredentialTagCharacters = 64;

[[nodiscard]] std::optional<Command> ParseCommand(std::wstring_view value)
{
    if (value == L"register")
    {
        return Command::Register;
    }
    if (value == L"run")
    {
        return Command::Run;
    }
    if (value == L"status")
    {
        return Command::Status;
    }
    if (value == L"forget")
    {
        return Command::Forget;
    }
    return std::nullopt;
}

} // namespace

void PrintUsage()
{
    std::wcerr << L"Usage:\n"
               << L"  ClaudeSandboxLauncher.exe register --user <local-user>\n"
               << L"  ClaudeSandboxLauncher.exe status --user <local-user>\n"
               << L"  ClaudeSandboxLauncher.exe forget --user <local-user>\n"
               << L"  ClaudeSandboxLauncher.exe run --user <local-user>"
                  L" [--working-directory <directory>] [--new-console]"
                  L" -- <absolute-executable> [arguments...]\n";
#ifndef NDEBUG
    std::wcerr << L"Credential commands used by tests also accept:"
                  L" --test-credential-tag <tag>\n";
#endif
}

std::optional<Options> ParseOptions(std::span<wchar_t*> arguments)
{
    if (arguments.size() < 2)
    {
        return std::nullopt;
    }

    const auto command = ParseCommand(arguments[1]);
    if (!command)
    {
        return std::nullopt;
    }

    Options options{ .command = *command };
    bool processArgumentsStarted = false;
    for (std::size_t index = 2; index < arguments.size(); ++index)
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
        if (name == L"--new-console")
        {
            options.newConsole = true;
            continue;
        }
        if (index + 1 >= arguments.size())
        {
            return std::nullopt;
        }
        const std::wstring value(arguments[++index]);

        if (name == L"--user")
        {
            options.username = value;
        }
        else if (name == L"--test-credential-tag")
        {
            if (options.testCredentialTagSpecified)
            {
                return std::nullopt;
            }
            options.testCredentialTagSpecified = true;
            options.testCredentialTag = value;
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

    if (options.username.empty())
    {
        return std::nullopt;
    }
    if (options.username.find_first_of(L"\\/@") != std::wstring::npos)
    {
        return std::nullopt;
    }
    if (options.testCredentialTagSpecified)
    {
        if (options.testCredentialTag.empty())
        {
            return std::nullopt;
        }
        const bool validTag =
            options.testCredentialTag.size() <= MaximumTestCredentialTagCharacters &&
            std::all_of(options.testCredentialTag.begin(),
                        options.testCredentialTag.end(),
                        [](wchar_t character)
                        {
                            return (character >= L'a' && character <= L'z') ||
                                   (character >= L'A' && character <= L'Z') ||
                                   (character >= L'0' && character <= L'9') || character == L'-' ||
                                   character == L'_' || character == L'.';
                        });
        if (!validTag)
        {
            return std::nullopt;
        }
    }
    if (*command == Command::Run)
    {
        if (!processArgumentsStarted || options.processArguments.empty())
        {
            return std::nullopt;
        }
        options.executablePath = options.processArguments.front();
        options.processArguments.erase(options.processArguments.begin());
    }
    else if (processArgumentsStarted || !options.workingDirectory.empty() || options.newConsole)
    {
        return std::nullopt;
    }
    return options;
}

} // namespace sandbox_launcher
