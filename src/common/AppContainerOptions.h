// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as
{

struct AppContainerOptions
{
    bool enabled = false;
    std::vector<std::wstring> capabilities;
};

// Names are resolved by Windows; arbitrary names can describe custom capabilities.
[[nodiscard]] inline bool IsAppContainerCapability(std::wstring_view value)
{
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(),
               value.end(),
               [](wchar_t character)
               {
                   return (character >= L'a' && character <= L'z') ||
                          (character >= L'A' && character <= L'Z') ||
                          (character >= L'0' && character <= L'9') || character == L'-' ||
                          character == L'_' || character == L'.';
               });
}

[[nodiscard]] inline bool IsValidAppContainerOptions(const AppContainerOptions& options)
{
    if ((!options.enabled && !options.capabilities.empty()) || options.capabilities.size() > 32)
    {
        return false;
    }
    for (std::size_t index = 0; index < options.capabilities.size(); ++index)
    {
        if (!IsAppContainerCapability(options.capabilities[index]) ||
            std::find(options.capabilities.begin(),
                options.capabilities.begin() + index,
                options.capabilities[index]) != options.capabilities.begin() + index)
        {
            return false;
        }
    }
    return true;
}

} // namespace launch_as
