// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "Credentials.h"
#include "LaunchProcess.h"
#include "LauncherOptions.h"
#include "PseudoConsoleHost.h"

#include <cstddef>
#include <span>

int wmain(int argc, wchar_t* argv[])
{
    using namespace launch_as;

    const std::span arguments(argv, static_cast<std::size_t>(argc));
    if (IsPseudoConsoleHostInvocation(arguments))
    {
        return static_cast<int>(RunPseudoConsoleHost(arguments));
    }

    const auto options = ParseOptions(arguments);
    if (!options)
    {
        PrintUsage();
        return static_cast<int>(ExitUsage);
    }
    if (options->command == Command::Run && !ValidateRunPaths(*options))
    {
        return static_cast<int>(ExitFailure);
    }

    auto account = ResolveLocalAccount(options->username);
    if (!account)
    {
        return static_cast<int>(ExitFailure);
    }
    account->testCredentialTag = options->testCredentialTag;

    ExitCode exitCode = ExitFailure;
    switch (options->command)
    {
    case Command::Register:
        exitCode = options->passwordFromStdin ? RegisterCredentialFromStandardInput(*account)
                                              : RegisterCredential(*account);
        break;
    case Command::Run:
        exitCode = RunProcessAsUser(*account, *options);
        break;
    case Command::Status:
        exitCode = CredentialStatus(*account);
        break;
    case Command::Forget:
        exitCode = ForgetCredential(*account);
        break;
    }
    return static_cast<int>(exitCode);
}
