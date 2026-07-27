// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <array>
#include <string_view>

inline constexpr std::array<std::wstring_view, 8> CommandLineTestArguments {
    L"",
    L"plain",
    L"with space",
    L"quote\"inside",
    L"trailing\\",
    L"two\\\\trailing\\\\",
    L"slash\\\"quote",
    L"\t"
};
