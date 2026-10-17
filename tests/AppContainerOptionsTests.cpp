// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "AppContainerOptions.h"
#include "BrokerProtocol.h"
#include "PseudoConsoleHostInvocation.h"
#include "TestSupport.h"

#include <array>

int wmain()
{
    using namespace launch_as;
    AppContainerOptions options {true, {L"internetClient", L"S-1-15-3-4"}};
    if (!Expect(IsValidAppContainerOptions(options), L"Valid capabilities rejected."))
    {
        return 1;
    }
    for (const auto* value : {L"", L"bad name", L"☃"})
    {
        if (!Expect(
                !IsValidAppContainerOptions({true, {value}}), L"Malformed capability accepted."))
        {
            return 1;
        }
    }
    if (!Expect(!IsValidAppContainerOptions({false, {L"internetClient"}}),
            L"Disabled capabilities accepted.") ||
        !Expect(!IsValidAppContainerOptions({true, {L"internetClient", L"internetClient"}}),
            L"Duplicate accepted.") ||
        !Expect(!IsValidAppContainerOptions({true, {std::wstring(129, L'x')}}),
            L"Long capability accepted."))
    {
        return 1;
    }
    AppContainerOptions many {true, {}};
    for (int index = 0; index < 33; ++index)
    {
        many.capabilities.push_back(L"cap" + std::to_wstring(index));
    }
    if (!Expect(!IsValidAppContainerOptions(many), L"Capability count was not bounded."))
    {
        return 1;
    }

    std::string wire;
    const std::array<std::wstring, 1> command {L"C:\\Windows\\System32\\cmd.exe"};
    if (!Expect(broker::BuildConsoleLaunchRequest(L"123e4567-e89b-12d3-a456-426614174000",
                    L"LaunchAsUser",
                    command,
                    L"C:\\repo",
                    L"\\\\.\\pipe\\launch-as-123-in",
                    L"\\\\.\\pipe\\launch-as-123-out",
                    L"\\\\.\\pipe\\launch-as-123-resize",
                    false,
                    wire,
                    false,
                    false,
                    false,
                    options),
            L"Capability request serialization failed."))
    {
        return 1;
    }
    broker::BrokerRequest parsed;
    if (!Expect(broker::ParseBrokerRequest(wire, parsed) == broker::ParseResult::Success &&
                    parsed.appContainer.enabled &&
                    parsed.appContainer.capabilities == options.capabilities,
            L"Capabilities did not survive the wire."))
    {
        return 1;
    }
    std::array<const wchar_t*, 14> arguments {
        L"host.exe",
        L"--internal-pseudoconsole-host",
        L"--appcontainer",
        L"--appcontainer-capability",
        L"internetClient",
        L"--pipe-in",
        L"in",
        L"--pipe-out",
        L"out",
        L"--pipe-resize",
        L"resize",
        L"--",
        L"C:\\agent.exe",
        L"--appcontainer-capability"
    };
    std::array<wchar_t*, arguments.size()> mutableArguments {};
    for (std::size_t index = 0; index < arguments.size(); ++index)
    {
        mutableArguments[index] = const_cast<wchar_t*>(arguments[index]);
    }
    PseudoConsoleHostInvocation invocation;
    if (!Expect(ParsePseudoConsoleHostInvocation(mutableArguments, invocation) &&
                    invocation.appContainer.enabled &&
                    invocation.appContainer.capabilities ==
                        std::vector<std::wstring> {L"internetClient"} &&
                    invocation.processArguments ==
                        std::vector<std::wstring> {L"--appcontainer-capability"},
            L"Internal invocation or child argument boundary was lost."))
    {
        return 1;
    }
    return 0;
}
