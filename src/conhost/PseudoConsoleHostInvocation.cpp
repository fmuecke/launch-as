// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "PseudoConsoleHostInvocation.h"

#include <string_view>

namespace launch_as
{
namespace
{

constexpr std::wstring_view HostArgument = L"--internal-pseudoconsole-host";
constexpr std::wstring_view InheritCursorArgument = L"--inherit-cursor";
constexpr std::wstring_view PipeInArgument = L"--pipe-in";
constexpr std::wstring_view PipeOutArgument = L"--pipe-out";
constexpr std::wstring_view PipeResizeArgument = L"--pipe-resize";

} // namespace

bool IsPseudoConsoleHostInvocation(std::span<wchar_t*> arguments) noexcept
{
    return arguments.size() >= 2 && std::wstring_view(arguments[1]) == HostArgument;
}

bool ParsePseudoConsoleHostInvocation(
    std::span<wchar_t*> arguments, PseudoConsoleHostInvocation& invocation)
{
    if (arguments.size() < 4 || std::wstring_view(arguments[1]) != HostArgument)
    {
        return false;
    }

    std::size_t separatorIndex = 2;
    invocation.inheritCursor =
        std::wstring_view(arguments[separatorIndex]) == InheritCursorArgument;
    if (invocation.inheritCursor)
    {
        ++separatorIndex;
    }
    for (;
        separatorIndex < arguments.size() && std::wstring_view(arguments[separatorIndex]) != L"--";
        separatorIndex += 2)
    {
        if (separatorIndex + 1 >= arguments.size())
        {
            return false;
        }
        const std::wstring_view name(arguments[separatorIndex]);
        const std::wstring_view value(arguments[separatorIndex + 1]);
        if (value.empty())
        {
            return false;
        }
        if (name == PipeInArgument && invocation.pipeIn.empty())
        {
            invocation.pipeIn = value;
        }
        else if (name == PipeOutArgument && invocation.pipeOut.empty())
        {
            invocation.pipeOut = value;
        }
        else if (name == PipeResizeArgument && invocation.pipeResize.empty())
        {
            invocation.pipeResize = value;
        }
        else
        {
            return false;
        }
    }
    if (arguments.size() <= separatorIndex + 1 ||
        std::wstring_view(arguments[separatorIndex]) != L"--")
    {
        return false;
    }

    invocation.executable = arguments[separatorIndex + 1];
    for (std::size_t index = separatorIndex + 2; index < arguments.size(); ++index)
    {
        invocation.processArguments.emplace_back(arguments[index]);
    }
    return !invocation.pipeIn.empty() && !invocation.pipeOut.empty() &&
           !invocation.pipeResize.empty();
}

} // namespace launch_as
