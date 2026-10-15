// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "FileSystemAccess.h"

#include <winternl.h>
namespace launch_as
{
namespace
{
DWORD SetObjectSecurity(
    HANDLE object, SECURITY_INFORMATION information, PSECURITY_DESCRIPTOR descriptor)
{
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return GetLastError();
    }
    using SetSecurityObject = NTSTATUS(NTAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
    const auto setSecurity =
        reinterpret_cast<SetSecurityObject>(GetProcAddress(ntdll, "NtSetSecurityObject"));
    if (setSecurity == nullptr)
    {
        return GetLastError();
    }
    const auto statusToError = reinterpret_cast<decltype(&RtlNtStatusToDosError)>(
        GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    if (statusToError == nullptr)
    {
        return GetLastError();
    }
    const NTSTATUS status = setSecurity(object, information, descriptor);
    return status < 0 ? statusToError(status) : ERROR_SUCCESS;
}
DWORD OpenPinnedRelative(HANDLE parent, std::wstring_view name, DWORD access, UniqueHandle& object)
{
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return GetLastError();
    }
    const auto createFile =
        reinterpret_cast<decltype(&NtCreateFile)>(GetProcAddress(ntdll, "NtCreateFile"));
    if (createFile == nullptr)
    {
        return GetLastError();
    }
    const auto statusToError = reinterpret_cast<decltype(&RtlNtStatusToDosError)>(
        GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    if (statusToError == nullptr)
    {
        return GetLastError();
    }
    UNICODE_STRING component {};
    component.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    component.MaximumLength = component.Length;
    component.Buffer = const_cast<PWSTR>(name.data());
    OBJECT_ATTRIBUTES attributes {};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &component;
    // Preserve the enumerated spelling, including in case-sensitive directories.
    IO_STATUS_BLOCK statusBlock {};
    HANDLE rawObject = nullptr;
    const NTSTATUS status = createFile(&rawObject,
        access | SYNCHRONIZE,
        &attributes,
        &statusBlock,
        nullptr,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr,
        0);
    if (status < 0)
    {
        return statusToError(status);
    }
    object.reset(rawObject);
    return ERROR_SUCCESS;
}
} // namespace

DWORD OpenRelativeFile(HANDLE parent, std::wstring_view name, DWORD access, UniqueHandle& object)
{
    // Exactly one component: no intermediate path can traverse a newly introduced junction.
    if (name.empty() || name == L"." || name == L".." ||
        name.find_first_of(L"\\/:") != std::wstring_view::npos || name.size() > 32'767)
    {
        return ERROR_BAD_PATHNAME;
    }
    return OpenPinnedRelative(parent, name, access, object);
}

DWORD ReopenPinnedFile(HANDLE object, DWORD access, UniqueHandle& reopened)
{
    // An empty native name reopens RootDirectory itself without resolving its ancestors.
    return OpenPinnedRelative(object, L"", access, reopened);
}

DWORD SetObjectDacl(HANDLE object, PACL dacl, SECURITY_DESCRIPTOR_CONTROL control)
{
    // The set-only REQ bit tells the kernel to retain the AUTO_INHERITED state. We preserve
    // existing inherited ACEs and add only non-inheritable denies, so no tree walk is needed.
    if ((control & SE_DACL_AUTO_INHERITED) != 0)
    {
        control |= SE_DACL_AUTO_INHERIT_REQ;
    }
    SECURITY_DESCRIPTOR descriptor {};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, dacl, FALSE) ||
        !SetSecurityDescriptorControl(&descriptor,
            SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ,
            control & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ)))
    {
        return GetLastError();
    }
    const SECURITY_INFORMATION information =
        DACL_SECURITY_INFORMATION |
        ((control & SE_DACL_PROTECTED) != 0 ? PROTECTED_DACL_SECURITY_INFORMATION
                                            : UNPROTECTED_DACL_SECURITY_INFORMATION);
    return SetObjectSecurity(object, information, &descriptor);
}

DWORD SetObjectLabel(HANDLE object, PACL label)
{
    SECURITY_DESCRIPTOR descriptor {};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorSacl(&descriptor, TRUE, label, FALSE))
    {
        return GetLastError();
    }
    return SetObjectSecurity(object, LABEL_SECURITY_INFORMATION, &descriptor);
}

} // namespace launch_as
