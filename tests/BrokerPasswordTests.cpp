// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerPassword.h"
#include "TestSupport.h"

#include <Windows.h>
#include <algorithm>
#include <iostream>
#include <string_view>

namespace
{

[[nodiscard]] bool ContainsAny(std::span<const wchar_t> password, std::wstring_view characters)
{
    return std::ranges::any_of(password,
        [characters](wchar_t character)
        { return characters.find(character) != std::wstring_view::npos; });
}

} // namespace

int wmain()
{
    launch_as::broker::SecurePassword password;
    if (!Expect(launch_as::broker::GenerateBrokerPassword(password) == ERROR_SUCCESS,
            L"Could not generate a broker password."))
    {
        return 1;
    }

    constexpr std::wstring_view allowed =
        L"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@";
    const std::span<const wchar_t> characters = password.characters();
    const bool valid = characters.size() == 32 &&
                       std::ranges::all_of(characters,
                           [allowed](wchar_t character)
                           { return allowed.find(character) != std::wstring_view::npos; }) &&
                       ContainsAny(characters, L"ABCDEFGHJKLMNPQRSTUVWXYZ") &&
                       ContainsAny(characters, L"abcdefghijkmnopqrstuvwxyz") &&
                       ContainsAny(characters, L"23456789") &&
                       ContainsAny(characters, L"!#$%&*+-=?@");
    password.Clear();
    return Expect(
               valid, L"Generated broker password did not meet the fixed account-password policy.")
               ? 0
               : 1;
}
