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
  launch-as.exe [run] --user <launch-as-user>
                      [--mode console|interactive]
                      [--working-directory <directory>]
                      [--restrict-access] [--low-integrity] [--log]
                      [--appcontainer-experimental [--appcontainer-capability <name-or-SID>]...]
                      -- <absolute-executable> [arguments...]

  Starts a console session by default, or a GUI process on the caller's shared desktop in
  interactive mode, through launch-as-broker. Create or take over the account first with the
  elevated launch-as-admin command. The client never accepts or stores passwords.
  --restrict-access uses a write-restricted token and temporarily denies other local folders.
  Read access remains available to Windows, Program Files, the profile, and working directory.
  Account ACLs are checked on each launch and restored when its last session closes.
  Individual file DACLs stay unchanged; file-ID opens and loose ancestor files are unrestricted.
  --low-integrity lowers token integrity and persistently labels the target user's profile
  and working directory Low, where account permissions allow.
  --log appends launch steps and folder deny/exclusion decisions to
  %LOCALAPPDATA%\launch-as\launch-as.log for the caller.
  --appcontainer-experimental confines the console command and descendants, with zero capabilities by default.
  Repeat --appcontainer-capability to grant Windows capability names or S-1-15-3-... SIDs.
  Grants propagate through the profile and workspace using the managed account's metadata rights.
  Existing files the account cannot update need owner preparation; protected ACLs are preserved.
  Integrity labels are unchanged. The container SID is printed for permission setup.
  The printed container identity depends on account, workspace and capabilities.
  Loopback access must be prepared separately; network capabilities can enable DNS-service access.
  AppContainer requires console mode and cannot combine with --restrict-access or --low-integrity.

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
    bool modeSeen = false;
    for (std::size_t index = firstOptionIndex; index < arguments.size(); ++index)
    {
        const std::wstring_view name(arguments[index]);
        if (name == L"--appcontainer-experimental")
        {
            if (options.appContainer.enabled)
            {
                return std::nullopt;
            }
            options.appContainer.enabled = true;
            continue;
        }
        if (name == L"--")
        {
            processArgumentsStarted = true;
            for (++index; index < arguments.size(); ++index)
            {
                options.processArguments.emplace_back(arguments[index]);
            }
            break;
        }
        if (name == L"--log")
        {
            if (options.log)
            {
                return std::nullopt;
            }
            options.log = true;
            continue;
        }
        if (name == L"--restrict-access")
        {
            if (options.restrictAccess)
            {
                return std::nullopt;
            }
            options.restrictAccess = true;
            continue;
        }
        if (name == L"--low-integrity")
        {
            if (options.lowIntegrity)
            {
                return std::nullopt;
            }
            options.lowIntegrity = true;
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
        else if (name == L"--appcontainer-capability")
        {
            options.appContainer.capabilities.emplace_back(value);
        }
        else if (name == L"--working-directory")
        {
            options.workingDirectory = value;
        }
        else if (name == L"--mode" && !modeSeen)
        {
            modeSeen = true;
            if (value == L"console")
            {
                options.sessionMode = SessionMode::Console;
            }
            else if (value == L"interactive")
            {
                options.sessionMode = SessionMode::Interactive;
            }
            else
            {
                return std::nullopt;
            }
        }
        else
        {
            return std::nullopt;
        }
    }

    if (!IsValidAppContainerOptions(options.appContainer) ||
        (options.appContainer.enabled && (options.sessionMode != SessionMode::Console ||
                                             options.lowIntegrity || options.restrictAccess)) ||
        options.username.empty() || options.username.find_first_of(L"\\/@") != std::wstring::npos)
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
