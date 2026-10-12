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
    const auto lowIntegrity = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--low-integrity",
        L"--",
        L"C:\\Windows\\System32\\cmd.exe"
    });
    const auto combined = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--low-integrity",
        L"--restrict-writes",
        L"--mode",
        L"interactive",
        L"--",
        L"C:\\Windows\\System32\\cmd.exe"
    });
    const auto repeatedIntegrity = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--low-integrity",
        L"--low-integrity",
        L"--",
        L"C:\\Windows\\System32\\cmd.exe"
    });
    if (!Expect(lowIntegrity && lowIntegrity->lowIntegrity && !lowIntegrity->restrictWrites,
            L"Low integrity was not independent of write restriction.") ||
        !Expect(combined && combined->lowIntegrity && combined->restrictWrites &&
                    combined->sessionMode == launch_as::SessionMode::Interactive,
            L"Combined interactive restrictions were rejected.") ||
        !Expect(!repeatedIntegrity, L"Repeated Low integrity was accepted."))
    {
        return 1;
    }
    const auto restricted = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--restrict-writes",
        L"--",
        L"C:\\Windows\\System32\\cmd.exe"
    });
    const auto repeatedRestriction = Parse(std::array {
        L"launch-as.exe",
        L"--user",
        L"LaunchAsUser",
        L"--restrict-writes",
        L"--restrict-writes",
        L"--",
        L"C:\\Windows\\System32\\cmd.exe"
    });
    if (!Expect(restricted && restricted->restrictWrites && !restricted->lowIntegrity,
            L"Write restriction was not independent of Low integrity.") ||
        !Expect(!repeatedRestriction, L"Repeated write restriction was accepted."))
    {
        return 1;
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

    return Expect(defaultConsole && !defaultConsole->restrictWrites &&
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
