// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerControlClient.h"
#include "BrokerProtocol.h"
#include "TestSupport.h"

#include <array>
#include <string>

int wmain()
{
    constexpr std::wstring_view requestId = L"123e4567-e89b-12d3-a456-426614174000";
    constexpr std::wstring_view nonce = L"6f9619ff-8b86-d011-b42d-00c04fc964ff";
    constexpr std::wstring_view leasePipe =
        L"\\\\.\\pipe\\launch-as-interactive-6f9619ff8b86d011b42d00c04fc964ff";
    const std::array arguments {
        std::wstring(L"C:\\Windows\\System32\\notepad.exe"), std::wstring(L"C:\\work item.txt")
    };
    std::string encoded;
    launch_as::broker::BrokerRequest parsed;

    const bool built = launch_as::BuildInteractiveLaunchRequest(
        requestId, L"LaunchAsUser", arguments, L"C:\\work", leasePipe, nonce, encoded);
    launch_as::BrokerControlConnection invalidConnection;
    DWORD invalidProcessId = 42;
    const DWORD invalidLaunch = launch_as::LaunchBrokerInteractive(
        L"LaunchAsUser", {}, L"C:\\work", leasePipe, nonce, invalidConnection, invalidProcessId);

    return Expect(built, L"The interactive launch request was not built.") &&
                   Expect(launch_as::broker::ParseBrokerRequest(encoded, parsed) ==
                              launch_as::broker::ParseResult::Success,
                       L"The interactive launch request was rejected by the broker parser.") &&
                   Expect(
                       parsed.operation == launch_as::broker::RequestOperation::InteractiveLaunch &&
                           parsed.requestId == requestId && parsed.profileId == L"LaunchAsUser" &&
                           parsed.arguments.size() == 2 &&
                           parsed.arguments[1] == L"C:\\work item.txt" &&
                           parsed.workingDirectory == L"C:\\work" &&
                           parsed.interactive.leasePipe == leasePipe &&
                           parsed.interactive.nonce == nonce,
                       L"The interactive launch request did not preserve its public fields.") &&
                   Expect(encoded.find("sessionId") == std::string::npos &&
                              encoded.find("callerSid") == std::string::npos &&
                              encoded.find("logonSid") == std::string::npos,
                       L"The interactive launch request serialized caller identity.") &&
                   Expect(invalidLaunch == ERROR_INVALID_PARAMETER && invalidProcessId == 0 &&
                              invalidConnection.get() == nullptr,
                       L"An invalid interactive launch reached the broker path.")
               ? 0
               : 1;
}
