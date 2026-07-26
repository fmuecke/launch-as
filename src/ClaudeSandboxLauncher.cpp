// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: MIT
// Part of claude-win-sandbox: https://github.com/fmuecke/claude-win-sandbox

#include "Credentials.h"
#include "LauncherOptions.h"
#include "SandboxProcess.h"

#include <cstddef>
#include <span>

int wmain(int argc, wchar_t* argv[])
{
    using namespace sandbox_launcher;

    const auto options = ParseOptions(std::span<wchar_t*>(argv, static_cast<std::size_t>(argc)));
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
        exitCode = RunSandboxProcess(*account, *options);
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
