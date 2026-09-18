// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <cstdint>

namespace launch_as
{

using ExitCode = std::uint32_t;

inline constexpr ExitCode ExitSuccess = 0;      // ERROR_SUCCESS
inline constexpr ExitCode ExitFailure = 1;      // ERROR_INVALID_FUNCTION
inline constexpr ExitCode ExitUsage = 87;       // ERROR_INVALID_PARAMETER
inline constexpr ExitCode ExitCancelled = 1223; // ERROR_CANCELLED

} // namespace launch_as
