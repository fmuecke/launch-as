// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LauncherOptions.h"
#include "TestSupport.h"

#include <array>
#include <span>

namespace
{

template <std::size_t Size>
[[nodiscard]] auto Parse(const std::array<const wchar_t*, Size>& arguments)
{
    std::array<wchar_t*, Size> mutableArguments {};
    for (std::size_t index = 0; index < Size; ++index)
    {
        mutableArguments[index] = const_cast<wchar_t*>(arguments[index]);
    }
    return launch_as::ParseOptions(std::span(mutableArguments));
}

} // namespace

int wmain()
{
    for (const auto* retired : {L"--restrict-reads", L"--restrict-writes"})
    {
        if (!Expect(!Parse(std::array {
                        L"launch-as.exe",
                        L"--user",
                        L"LaunchAsUser",
                        retired,
                        L"--",
                        L"C:\\Windows\\System32\\cmd.exe"
                    }),
                L"A retired restriction flag was accepted."))
        {
            return 1;
        }
    }
    for (const auto* mode : {L"console", L"interactive"})
    {
        const auto access = Parse(std::array {
            L"launch-as.exe",
            L"--user",
            L"LaunchAsUser",
            L"--mode",
            mode,
            L"--restrict-access",
            L"--",
            L"C:\\Windows\\System32\\cmd.exe"
        });
        const auto low = Parse(std::array {
            L"launch-as.exe",
            L"--user",
            L"LaunchAsUser",
            L"--mode",
            mode,
            L"--low-integrity",
            L"--",
            L"C:\\Windows\\System32\\cmd.exe"
        });
        const auto combined = Parse(std::array {
            L"launch-as.exe",
            L"--user",
            L"LaunchAsUser",
            L"--mode",
            mode,
            L"--restrict-access",
            L"--low-integrity",
            L"--log",
            L"--",
            L"C:\\Windows\\System32\\cmd.exe"
        });
        if (!Expect(access && access->restrictAccess && !access->lowIntegrity && !access->log,
                L"Access restriction was not independent of Low integrity and logging.") ||
            !Expect(low && low->lowIntegrity && !low->restrictAccess,
                L"Low integrity was not independent of access restriction.") ||
            !Expect(combined && combined->restrictAccess && combined->lowIntegrity && combined->log,
                L"Combined launch controls were rejected."))
        {
            return 1;
        }
    }
    const auto logged = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--log",
        L"--",
        L"C:\\Windows\\System32\\cmd.exe"
    });
    if (!Expect(logged && logged->log && !logged->restrictAccess && !logged->lowIntegrity,
            L"Logging must be independent of launch restrictions."))
    {
        return 1;
    }
    for (const auto* flag : {L"--restrict-access", L"--low-integrity", L"--log"})
    {
        if (!Expect(!Parse(std::array {
                        L"launch-as.exe",
                        L"--user",
                        L"LaunchAsUser",
                        flag,
                        flag,
                        L"--",
                        L"C:\\Windows\\System32\\cmd.exe"
                    }),
                L"A repeated launch control was accepted."))
        {
            return 1;
        }
    }
    const auto defaultConsole = Parse(std::array {
        L"launch-as.exe", L"--user", L"LaunchAsUser", L"--", L"C:\\Windows\\System32\\cmd.exe"
    });
    const auto explicitConsole = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--mode",
        L"console",
        L"--",
        L"C:\\Windows\\System32\\cmd.exe"
    });
    const auto interactive = Parse(std::array {
        L"launch-as.exe",
        L"run",
        L"--mode",
        L"interactive",
        L"--user",
        L"LaunchAsUser",
        L"--",
        L"C:\\Windows\\System32\\notepad.exe"
    });
    const auto unknownMode = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--mode",
        L"detached",
        L"--",
        L"C:\\Windows\\System32\\notepad.exe"
    });
    const auto repeatedMode = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--mode",
        L"interactive",
        L"--mode",
        L"console",
        L"--",
        L"C:\\Windows\\System32\\notepad.exe"
    });

    return Expect(defaultConsole && !defaultConsole->restrictAccess &&
                      !defaultConsole->lowIntegrity &&
                      defaultConsole->sessionMode == launch_as::SessionMode::Console,
               L"The default launcher mode was not console.") &&
                   Expect(explicitConsole &&
                              explicitConsole->sessionMode == launch_as::SessionMode::Console,
                       L"Explicit console mode was rejected.") &&
                   Expect(interactive &&
                              interactive->sessionMode == launch_as::SessionMode::Interactive,
                       L"Interactive mode was rejected.") &&
                   Expect(!unknownMode, L"An unknown launcher mode was accepted.") &&
                   Expect(!repeatedMode, L"A repeated launcher mode was accepted.")
               ? 0
               : 1;
}
