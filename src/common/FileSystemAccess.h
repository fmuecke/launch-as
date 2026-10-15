// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once
#include "Win32Support.h"

#include <string_view>
namespace launch_as
{
// Open one component relative to a pinned parent; never follow a reparse point.
[[nodiscard]] DWORD OpenRelativeFile(
    HANDLE parent, std::wstring_view name, DWORD access, UniqueHandle& object);
[[nodiscard]] DWORD ReopenPinnedFile(HANDLE object, DWORD access, UniqueHandle& reopened);
// Change this pinned object's DACL only, without propagating ACEs into child trees.
[[nodiscard]] DWORD SetObjectDacl(HANDLE object, PACL dacl, SECURITY_DESCRIPTOR_CONTROL control);
[[nodiscard]] DWORD SetObjectLabel(HANDLE object, PACL label);
} // namespace launch_as
