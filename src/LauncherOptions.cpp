// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LauncherOptions.h"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <optional>
#include <string_view>

namespace launch_as
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

[[nodiscard]] std::optional<CredentialMode> ParseCredentialMode(std::wstring_view value)
{
    if (value == L"auto")
    {
        return CredentialMode::Auto;
    }
    if (value == L"stored")
    {
        return CredentialMode::Stored;
    }
    if (value == L"prompt")
    {
        return CredentialMode::Prompt;
    }
    return std::nullopt;
}

} // namespace

void PrintUsage()
{
    std::wcerr << L"Usage:\n"
               << L"  launch-as.exe register --user <local-user>"
                  L" [--password-stdin]\n"
               << L"  launch-as.exe status --user <local-user>\n"
               << L"  launch-as.exe forget --user <local-user>\n"
               << L"  launch-as.exe [run] --user <local-user>"
                  L" [--credential-mode <auto|stored|prompt>]"
                  L" [--working-directory <directory>] [--new-console|--terminal]"
                  L" -- <absolute-executable> [arguments...]\n";
#ifndef NDEBUG
    std::wcerr << L"Credential commands used by tests also accept:"
                  L" --test-credential-tag <tag>\n";
#endif
    std::wcerr << std::endl;
}

std::optional<Options> ParseOptions(std::span<wchar_t*> arguments)
{
    if (arguments.size() < 2)
    {
        return std::nullopt;
    }

    const auto parsedCommand = ParseCommand(arguments[1]);
    const Command command = parsedCommand.value_or(Command::Run);
    const std::size_t firstOptionIndex = parsedCommand ? 2 : 1;

    Options options {.command = command};
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
        if (name == L"--new-console" || name == L"--terminal")
        {
            if (options.launchModeSpecified)
            {
                return std::nullopt;
            }
            options.launchMode =
                name == L"--new-console" ? LaunchMode::NewConsole : LaunchMode::Terminal;
            options.launchModeSpecified = true;
            continue;
        }
        if (name == L"--password-stdin")
        {
            if (options.passwordFromStdin)
            {
                return std::nullopt;
            }
            options.passwordFromStdin = true;
            continue;
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
        else if (name == L"--credential-mode")
        {
            if (options.credentialModeSpecified)
            {
                return std::nullopt;
            }
            const auto credentialMode = ParseCredentialMode(value);
            if (!credentialMode)
            {
                return std::nullopt;
            }
            options.credentialMode = *credentialMode;
            options.credentialModeSpecified = true;
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

    if (options.username.empty() || options.username.find_first_of(L"\\/@") != std::wstring::npos)
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
    if (command == Command::Run)
    {
        if (options.passwordFromStdin || !processArgumentsStarted ||
            options.processArguments.empty())
        {
            return std::nullopt;
        }
        options.executablePath = options.processArguments.front();
        options.processArguments.erase(options.processArguments.begin());
    }
    else if (processArgumentsStarted || options.credentialModeSpecified ||
             !options.workingDirectory.empty() || options.launchModeSpecified ||
             (options.passwordFromStdin && command != Command::Register))
    {
        return std::nullopt;
    }
    return options;
}

} // namespace launch_as
