// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <string>
#include <winternl.h>

namespace launch_as::test
{

[[nodiscard]] inline HANDLE OpenSessionNamedObjectDirectory()
{
    DWORD sessionId = MAXDWORD;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId))
    {
        return nullptr;
    }
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    using OpenDirectory = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    const auto openDirectory =
        ntdll != nullptr
            ? reinterpret_cast<OpenDirectory>(GetProcAddress(ntdll, "NtOpenDirectoryObject"))
            : nullptr;
    if (openDirectory == nullptr)
    {
        return nullptr;
    }
    const std::wstring path = L"\\Sessions\\" + std::to_wstring(sessionId) + L"\\BaseNamedObjects";
    UNICODE_STRING name {};
    name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
    name.MaximumLength = name.Length;
    name.Buffer = const_cast<PWSTR>(path.data());
    OBJECT_ATTRIBUTES attributes {};
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    HANDLE directory = nullptr;
    return openDirectory(&directory, READ_CONTROL, &attributes) >= 0 ? directory : nullptr;
}

inline BOOL ReadInteractiveObjectSecurity(HANDLE object, bool kernelObject,
    SECURITY_INFORMATION* information, PSECURITY_DESCRIPTOR descriptor, DWORD bytes,
    DWORD* required)
{
    return kernelObject ? GetKernelObjectSecurity(object, *information, descriptor, bytes, required)
                        : GetUserObjectSecurity(object, information, descriptor, bytes, required);
}

} // namespace launch_as::test
