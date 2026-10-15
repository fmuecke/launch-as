// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerReadScope.h"

#include "FileSystemAccess.h"

#include <Aclapi.h>
#include <algorithm>
#include <array>
#include <filesystem>
#include <mutex>
#include <shlobj.h>
#include <winternl.h>

namespace launch_as::broker
{
namespace
{
// Different accounts can share the same base folders. Serialize complete ACL operations
// so one account's read/modify/write cannot resurrect another account's removed deny.
std::mutex readScopeMutex;
#ifdef LAUNCH_AS_TESTING
thread_local DWORD (*volumeProbeForTesting)(std::wstring_view, UINT&) = nullptr;
#endif

constexpr DWORD AncestorDeny = FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY |
                               FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;

bool Within(std::wstring_view path, std::wstring_view root)
{
    return path == root ||
           (path.size() > root.size() && path.starts_with(root) && path[root.size()] == L'\\');
}

DWORD OpenVolumeRoot(const std::wstring& path, UniqueHandle& object, DWORD& flags, UINT& driveType)
{
    driveType = GetDriveTypeW(path.c_str());
#ifdef LAUNCH_AS_TESTING
    if (volumeProbeForTesting != nullptr)
    {
        const DWORD error = volumeProbeForTesting(path, driveType);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
    }
#endif
    object.reset(CreateFileW(path.c_str(),
        READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!object)
    {
        return GetLastError();
    }
    if (!GetVolumeInformationByHandleW(
            object.get(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0))
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

DWORD CanonicalName(HANDLE object, std::wstring& name)
{
    std::vector<wchar_t> buffer(32'768);
    const DWORD length = GetFinalPathNameByHandleW(
        object, buffer.data(), static_cast<DWORD>(buffer.size()), VOLUME_NAME_GUID);
    if (length == 0)
    {
        return GetLastError();
    }
    if (length >= buffer.size())
    {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    name.assign(buffer.data(), length);
    while (name.ends_with(L'\\'))
    {
        name.pop_back();
    }
    return ERROR_SUCCESS;
}

DWORD CanonicalDirectory(std::wstring_view directory, std::wstring& name)
{
    auto path = std::filesystem::path(directory).lexically_normal();
    if (path.filename().empty())
    {
        path = path.parent_path();
    }
    if (!path.is_absolute() || path == path.root_path() || path.native().starts_with(L"\\\\") ||
        path.native().find(L':', 2) != std::wstring::npos)
    {
        return ERROR_BAD_PATHNAME;
    }
    UniqueHandle parent(CreateFileW(path.root_path().c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!parent)
    {
        return GetLastError();
    }
    // Validate every component, so a caller cannot exempt a junction's unexpected target.
    for (const auto& component : path.relative_path())
    {
        UniqueHandle child;
        const DWORD error =
            OpenRelativeFile(parent.get(), component.native(), FILE_READ_ATTRIBUTES, child);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
        FILE_ATTRIBUTE_TAG_INFO attributes {};
        if (!GetFileInformationByHandleEx(
                child.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)))
        {
            return GetLastError();
        }
        if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return ERROR_ACCESS_DENIED;
        }
        if ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            return ERROR_DIRECTORY;
        }
        parent = std::move(child);
    }
    return CanonicalName(parent.get(), name);
}

bool IsAccessAce(const void* raw, PSID sid, DWORD mask, bool grant = false)
{
    const auto* ace = static_cast<const ACCESS_DENIED_ACE*>(raw);
    return ace->Header.AceType == (grant ? ACCESS_ALLOWED_ACE_TYPE : ACCESS_DENIED_ACE_TYPE) &&
           ace->Header.AceFlags == 0 && ace->Mask == mask &&
           EqualSid(const_cast<DWORD*>(&ace->SidStart), sid);
}
} // namespace

BrokerReadScope::~BrokerReadScope() { static_cast<void>(Restore()); }

void BrokerReadScope::SetObserver(Observer observer)
{
    std::lock_guard lock(readScopeMutex);
    observer_ = std::move(observer);
}

DWORD BrokerReadScope::SetAccess(Entry& entry, DWORD mask, bool readableRoot)
{
    const bool wantTraverse = !entry.namespaceDirectory && (readableRoot || mask == AncestorDeny);
    if (mask == 0 && entry.addedMask == 0 && !entry.addedOwnerDeny && !entry.addedTraverseGrant &&
        !wantTraverse)
    {
        return ERROR_SUCCESS;
    }
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    PACL original = nullptr;
    PSID owner = nullptr;
    DWORD error = GetSecurityInfo(entry.object.get(),
        entry.namespaceDirectory ? SE_KERNEL_OBJECT : SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
        &owner,
        nullptr,
        &original,
        nullptr,
        descriptor.address());
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    // Null DACLs cannot be made selective without also changing everyone else's permissions.
    if (original == nullptr)
    {
        return ERROR_INVALID_ACL;
    }
    std::array<BYTE, SECURITY_MAX_SID_SIZE> ownerRights {};
    DWORD sidBytes = static_cast<DWORD>(ownerRights.size());
    if (!CreateWellKnownSid(WinCreatorOwnerRightsSid, nullptr, ownerRights.data(), &sidBytes))
    {
        return GetLastError();
    }
    // Owners otherwise retain implicit WRITE_DAC, even with a deny for their user SID.
    const bool denyOwner = !entry.namespaceDirectory && mask != 0 && owner != nullptr &&
                           EqualSid(owner, userSid_.data());
    bool existingUserAce = false;
    bool existingOwnerDeny = false;
    bool existingTraverse = false;
    std::vector<BYTE> aclBuffer(
        original->AclSize + 3 * (sizeof(ACCESS_DENIED_ACE) + SECURITY_MAX_SID_SIZE));
    auto* updated = reinterpret_cast<PACL>(aclBuffer.data());
    const DWORD revision = original->AclRevision;
    if (!InitializeAcl(updated, static_cast<DWORD>(aclBuffer.size()), revision))
    {
        return GetLastError();
    }
    // Remove only ACEs this lease added. Keep all pre-existing and unrelated ACEs verbatim.
    std::vector<void*> preserved;
    for (DWORD index = 0; index < original->AceCount; ++index)
    {
        void* raw = nullptr;
        if (!GetAce(original, index, &raw))
        {
            return GetLastError();
        }
        if ((entry.addedMask != 0 &&
                IsAccessAce(raw, userSid_.data(), entry.addedMask, entry.namespaceDirectory)) ||
            (entry.addedOwnerDeny && IsAccessAce(raw, ownerRights.data(), WRITE_DAC)) ||
            (entry.addedTraverseGrant && IsAccessAce(raw, userSid_.data(), FILE_TRAVERSE, true)))
        {
            continue;
        }
        existingUserAce =
            existingUserAce ||
            (mask != 0 && IsAccessAce(raw, userSid_.data(), mask, entry.namespaceDirectory));
        existingOwnerDeny = existingOwnerDeny || IsAccessAce(raw, ownerRights.data(), WRITE_DAC);
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        if (wantTraverse && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (ace->Header.AceFlags & INHERIT_ONLY_ACE) == 0 && (ace->Mask & FILE_TRAVERSE) != 0)
        {
            PSID sid = const_cast<DWORD*>(&ace->SidStart);
            existingTraverse = existingTraverse || EqualSid(sid, userSid_.data());
            const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(groups_.data());
            for (DWORD group = 0; group < groups->GroupCount; ++group)
            {
                const auto& value = groups->Groups[group];
                if ((value.Attributes & SE_GROUP_ENABLED) != 0 &&
                    (value.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0 &&
                    EqualSid(sid, value.Sid))
                {
                    existingTraverse = true;
                }
            }
        }
        preserved.push_back(raw);
    }
    const bool addUser = mask != 0 && !existingUserAce;
    const bool addOwner = denyOwner && !existingOwnerDeny;
    const bool addTraverse = wantTraverse && !existingTraverse;
    if (mask == 0 && entry.addedMask == 0 && !entry.addedOwnerDeny && !entry.addedTraverseGrant &&
        !addTraverse)
    {
        return ERROR_SUCCESS;
    }
    if ((addUser && !entry.namespaceDirectory &&
            !AddAccessDeniedAce(updated, revision, mask, userSid_.data())) ||
        (addOwner && !AddAccessDeniedAce(updated, revision, WRITE_DAC, ownerRights.data())))
    {
        return GetLastError();
    }
    for (const auto* raw : preserved)
    {
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (!AddAce(updated, revision, MAXDWORD, const_cast<void*>(raw), header->AceSize))
        {
            return GetLastError();
        }
    }
    // Namespace traversal grants must not override an existing explicit deny.
    if (addUser && entry.namespaceDirectory &&
        !AddAccessAllowedAce(updated, revision, mask, userSid_.data()))
    {
        return GetLastError();
    }
    if (addTraverse && !AddAccessAllowedAce(updated, revision, FILE_TRAVERSE, userSid_.data()))
    {
        return GetLastError();
    }
    SECURITY_DESCRIPTOR_CONTROL control {};
    DWORD descriptorRevision = 0;
    if (!GetSecurityDescriptorControl(descriptor.get(), &control, &descriptorRevision))
    {
        return GetLastError();
    }
    if (!entry.namespaceDirectory && !entry.writable)
    {
        // Allowed roots normally need inspection only. Acquire DACL-edit access only when
        // an ACE must change: unnecessary writer opens can conflict with Windows servicing.
        // Reopen the pinned object by handle, preserving no-follow and no-delete sharing.
        UniqueHandle writable;
        error = ReopenPinnedFile(entry.object.get(),
            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
            writable);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
        entry.object = std::move(writable);
        entry.writable = true;
    }
    error = SetObjectDacl(entry.object.get(), updated, control);
    if (error == ERROR_SUCCESS)
    {
        entry.addedMask = addUser ? mask : 0;
        entry.addedOwnerDeny = addOwner;
        entry.addedTraverseGrant = addTraverse;
    }
    return error;
}

DWORD BrokerReadScope::Restore()
{
    std::lock_guard lock(readScopeMutex);
    DWORD firstError = ERROR_SUCCESS;
    for (auto& [path, entry] : entries_)
    {
        if (entry.addedMask != 0 || entry.addedOwnerDeny || entry.addedTraverseGrant)
        {
            const DWORD error = SetAccess(entry, 0);
            if (observer_)
            {
                observer_(L"read.restore", path, error);
            }
            if (firstError == ERROR_SUCCESS)
            {
                firstError = error;
            }
        }
    }
    if (firstError == ERROR_SUCCESS)
    {
        entries_.clear();
        volumes_.clear();
        allowed_.clear();
        userSid_.clear();
        groups_.clear();
        observer_ = {};
    }
    return firstError;
}

DWORD BrokerReadScope::Visit(
    std::wstring_view path, UniqueHandle object, DWORD depth, DWORD& remaining, ULONGLONG deadline)
{
    failurePath_ = path;
    if (GetTickCount64() >= deadline)
    {
        return ERROR_TIMEOUT;
    }
    if (depth > 128 || remaining == 0)
    {
        return ERROR_NOT_ENOUGH_QUOTA;
    }
    --remaining;
    auto [position, inserted] = entries_.try_emplace(std::wstring(path));
    if (entries_.size() > 10'000)
    {
        return ERROR_NOT_ENOUGH_QUOTA;
    }
    auto& entry = position->second;
    if (inserted)
    {
        entry.object = std::move(object);
    }
    FILE_ATTRIBUTE_TAG_INFO attributes {};
    if (!GetFileInformationByHandleEx(
            entry.object.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)))
    {
        return GetLastError();
    }
    // Enumeration and opening are separate operations. A raced replacement must never
    // turn a folder-only ACL operation into a change to an individual file.
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return ERROR_DIRECTORY;
    }
    bool ancestor = false;
    bool readable = false;
    for (const auto& allowed : allowed_)
    {
        readable = readable || Within(path, allowed);
        ancestor = ancestor || Within(allowed, path);
    }
    if (readable)
    {
        DWORD error = SetAccess(entry, 0, true);
        if (observer_)
        {
            observer_(L"read.excluded_from_deny", path, error);
        }
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
        // A new working directory can contain folders denied by an earlier launch.
        // Remove those lease-owned denies too, without walking any filesystem children.
        for (auto child = entries_.lower_bound(std::wstring(path) + L"\\");
            child != entries_.end() && Within(child->first, path);)
        {
            error = SetAccess(child->second, 0, true);
            if (error != ERROR_SUCCESS)
            {
                failurePath_ = child->first;
                return error;
            }
            // These folders are now within an allowed tree. Keeping their handles would
            // needlessly prevent ordinary rename/deletion there for the rest of the scope.
            if (child->second.addedTraverseGrant)
            {
                // A formerly allowed path can still need traversal through this folder.
                ++child;
            }
            else
            {
                child = entries_.erase(child);
            }
        }
        return ERROR_SUCCESS;
    }
    if (!ancestor)
    {
        if (observer_)
        {
            observer_(L"read.deny_selected", path, ERROR_SUCCESS);
        }
        return SetAccess(entry, FILE_ALL_ACCESS);
    }
    if (observer_)
    {
        observer_(L"read.ancestor_traverse", path, ERROR_SUCCESS);
    }
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    {
        return ERROR_ACCESS_DENIED;
    }
    // Deny siblings first before making a previously blocked ancestor traversable.
    std::vector<BYTE> buffer(64 * 1024);
    bool restart = true;
    for (;;)
    {
        if (GetTickCount64() >= deadline)
        {
            return ERROR_TIMEOUT;
        }
        if (!GetFileInformationByHandleEx(entry.object.get(),
                restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo,
                buffer.data(),
                static_cast<DWORD>(buffer.size())))
        {
            const DWORD enumerationError = GetLastError();
            return enumerationError == ERROR_NO_MORE_FILES ? SetAccess(entry, AncestorDeny)
                                                           : enumerationError;
        }
        restart = false;
        const auto* child = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(buffer.data());
        for (;;)
        {
            if (GetTickCount64() >= deadline)
            {
                return ERROR_TIMEOUT;
            }
            // Even skipped files cost enumeration work. Bound every record, not just
            // recursive directory visits, while holding the broker's launch mutex.
            if (remaining == 0)
            {
                return ERROR_NOT_ENOUGH_QUOTA;
            }
            --remaining;
            const std::wstring_view name(child->FileName, child->FileNameLength / sizeof(wchar_t));
            if (name != L"." && name != L".." &&
                (child->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                const auto childPath = std::wstring(path) + L"\\" + std::wstring(name);
                UniqueHandle handle;
                DWORD error = ERROR_SUCCESS;
                if (!entries_.contains(childPath))
                {
                    failurePath_ = childPath;
                    // No data writes or deletion: other programs may hold these folders open.
                    constexpr DWORD access =
                        READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY;
                    error = OpenRelativeFile(entry.object.get(), name, access, handle);
                }
                if (error == ERROR_SUCCESS)
                {
                    error = Visit(childPath, std::move(handle), depth + 1, remaining, deadline);
                }
                if (error != ERROR_SUCCESS)
                {
                    return error;
                }
            }
            if (child->NextEntryOffset == 0)
            {
                break;
            }
            child = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(
                reinterpret_cast<const BYTE*>(child) + child->NextEntryOffset);
        }
    }
}

DWORD BrokerReadScope::EnsureRoots(HANDLE token, std::span<const std::wstring> volumes,
    std::span<const std::wstring> readable, std::wstring_view profile, std::wstring_view work,
    DWORD maximumObjects, DWORD timeoutMilliseconds)
{
    std::lock_guard lock(readScopeMutex);
    failurePath_.clear();
    std::vector<BYTE> user;
    DWORD error = QueryTokenInformation(token, TokenUser, user);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    PSID sid = reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
    if (!userSid_.empty() && !EqualSid(userSid_.data(), sid))
    {
        return ERROR_ACCESS_DENIED;
    }
    userSid_.assign(static_cast<BYTE*>(sid), static_cast<BYTE*>(sid) + GetLengthSid(sid));
    error = QueryTokenInformation(token, TokenGroups, groups_);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    auto allowed = allowed_;
    for (const auto& root : readable)
    {
        failurePath_ = root;
        std::wstring canonical;
        error = CanonicalDirectory(root, canonical);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
        allowed.push_back(std::move(canonical));
    }
    for (const auto root : {profile, work})
    {
        failurePath_ = root;
        std::wstring canonical;
        error = CanonicalDirectory(root, canonical);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
        allowed.push_back(std::move(canonical));
    }
    std::ranges::sort(allowed);
    // Keep only the broadest roots. Repeated launches beneath the profile or an existing
    // working tree do not need an ever-growing list of redundant descendants.
    std::vector<std::wstring> roots;
    for (auto& root : allowed)
    {
        if (!std::ranges::any_of(roots, [&](const auto& parent) { return Within(root, parent); }))
        {
            roots.push_back(std::move(root));
        }
    }
    allowed_ = std::move(roots);
    DWORD remaining = maximumObjects;
    const ULONGLONG deadline = GetTickCount64() + timeoutMilliseconds;
    for (const auto& volume : volumes)
    {
        failurePath_ = volume;
        const auto existing = volumes_.find(volume);
        if (existing != volumes_.end())
        {
            error = Visit(existing->second, {}, 0, remaining, deadline);
            if (error != ERROR_SUCCESS)
            {
                return error;
            }
            continue;
        }
        UniqueHandle object;
        DWORD flags = 0;
        UINT driveType = DRIVE_UNKNOWN;
        error = OpenVolumeRoot(volume, object, flags, driveType);
        if (error != ERROR_SUCCESS)
        {
            // Empty drives expose no filesystem to restrict. Inserted media is considered
            // at the next launch, like a newly mounted volume; other failures stay fatal.
            if (error == ERROR_NOT_READY &&
                (driveType == DRIVE_CDROM || driveType == DRIVE_REMOVABLE))
            {
                if (observer_)
                {
                    observer_(L"read.skip_empty_drive", volume, error);
                }
                continue;
            }
            return error;
        }
        if ((flags & FILE_PERSISTENT_ACLS) == 0)
        {
            return ERROR_NOT_SUPPORTED;
        }
        std::wstring canonical;
        error = CanonicalName(object.get(), canonical);
        if (error == ERROR_SUCCESS)
        {
            error = Visit(canonical, std::move(object), 0, remaining, deadline);
            if (error == ERROR_SUCCESS)
            {
                // An early visit failure may not have retained the root handle for reuse.
                volumes_.emplace(volume, canonical);
            }
        }
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
    }
    failurePath_.clear();
    return ERROR_SUCCESS;
}

DWORD BrokerReadScope::EnsureWindowsNamespace(HANDLE token)
{
    DWORD sessionId = 0;
    DWORD bytes = 0;
    if (!GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId), &bytes))
    {
        return GetLastError();
    }
    if (sessionId == 0)
    {
        return ERROR_SUCCESS;
    }
    // KERNELBASE opens SharedSection by this absolute native path during GUI startup.
    // With traversal bypass removed, the account needs DIRECTORY_TRAVERSE on its parents.
    const std::wstring session = L"\\Sessions\\" + std::to_wstring(sessionId);
    const std::array directories {std::wstring(L"\\Sessions"), session, session + L"\\Windows"};
    return EnsureNamespaceDirectories(directories);
}

DWORD BrokerReadScope::EnsureNamespaceDirectories(std::span<const std::wstring> directories)
{
    std::lock_guard lock(readScopeMutex);
    if (userSid_.empty())
    {
        return ERROR_INVALID_STATE;
    }
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return GetLastError();
    }
    using OpenDirectory = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    const auto openDirectory =
        reinterpret_cast<OpenDirectory>(GetProcAddress(ntdll, "NtOpenDirectoryObject"));
    if (openDirectory == nullptr)
    {
        return GetLastError();
    }
    const auto statusToError = reinterpret_cast<decltype(&RtlNtStatusToDosError)>(
        GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    if (statusToError == nullptr)
    {
        return GetLastError();
    }
    for (const auto& path : directories)
    {
        failurePath_ = path;
        auto [position, inserted] = entries_.try_emplace(path);
        if (entries_.size() > 10'000)
        {
            return ERROR_NOT_ENOUGH_QUOTA;
        }
        auto& entry = position->second;
        entry.namespaceDirectory = true;
        if (inserted || !entry.object)
        {
            UNICODE_STRING name {};
            name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
            name.MaximumLength = name.Length;
            name.Buffer = const_cast<PWSTR>(path.data());
            OBJECT_ATTRIBUTES attributes {};
            attributes.Length = sizeof(attributes);
            attributes.ObjectName = &name;
            HANDLE raw = nullptr;
            const NTSTATUS status = openDirectory(&raw, READ_CONTROL | WRITE_DAC, &attributes);
            if (status < 0)
            {
                return statusToError(status);
            }
            entry.object.reset(raw);
        }
        constexpr DWORD DirectoryTraverse = 0x0002;
        const DWORD error = SetAccess(entry, DirectoryTraverse);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
    }
    failurePath_.clear();
    return ERROR_SUCCESS;
}

DWORD BrokerReadScope::Ensure(HANDLE token, std::wstring_view profile, std::wstring_view work)
{
    std::vector<std::wstring> readable;
    std::array<wchar_t, 32'768> windows {};
    const UINT length = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    if (length == 0)
    {
        return GetLastError();
    }
    readable.emplace_back(windows.data(), length);
    for (const auto& id : {FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86})
    {
        PWSTR path = nullptr;
        const HRESULT result = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &path);
        if (FAILED(result))
        {
            return HRESULT_CODE(result);
        }
        readable.emplace_back(path);
        CoTaskMemFree(path);
    }
    // Enumerate mounted local volumes. Canonical GUID paths avoid granting a second spelling
    // of a blocked drive. Unmounted volumes and UNC/remote filesystems are out of scope.
    std::vector<std::wstring> volumes;
    std::array<wchar_t, MAX_PATH> volume {};
    const HANDLE search = FindFirstVolumeW(volume.data(), static_cast<DWORD>(volume.size()));
    if (search == INVALID_HANDLE_VALUE)
    {
        return GetLastError();
    }
    DWORD error = ERROR_SUCCESS;
    do
    {
        DWORD characters = 0;
        const BOOL pathsResult =
            GetVolumePathNamesForVolumeNameW(volume.data(), nullptr, 0, &characters);
        const DWORD pathsError = pathsResult ? ERROR_SUCCESS : GetLastError();
        if (pathsError != ERROR_MORE_DATA && pathsError != ERROR_SUCCESS)
        {
            error = pathsError;
            break;
        }
        if (characters > 1)
        {
            volumes.emplace_back(volume.data());
        }
        if (!FindNextVolumeW(search, volume.data(), static_cast<DWORD>(volume.size())))
        {
            error = GetLastError();
            break;
        }
    } while (true);
    FindVolumeClose(search);
    if (error != ERROR_NO_MORE_FILES)
    {
        return error;
    }
    error = EnsureRoots(token, volumes, readable, profile, work);
    return error == ERROR_SUCCESS ? EnsureWindowsNamespace(token) : error;
}

#ifdef LAUNCH_AS_TESTING
void SetBrokerReadScopeVolumeProbeForTesting(
    DWORD (*probe)(std::wstring_view, UINT& driveType)) noexcept
{
    volumeProbeForTesting = probe;
}
DWORD BrokerReadScope::EnsureForTesting(HANDLE token, std::span<const std::wstring> volumes,
    std::span<const std::wstring> readable, std::wstring_view profile, std::wstring_view work,
    DWORD maximumObjects, DWORD timeoutMilliseconds)
{
    return EnsureRoots(
        token, volumes, readable, profile, work, maximumObjects, timeoutMilliseconds);
}
DWORD BrokerReadScope::EnsureNamespaceForTesting(std::span<const std::wstring> directories)
{
    return EnsureNamespaceDirectories(directories);
}
#endif

} // namespace launch_as::broker
