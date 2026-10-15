// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerWriteScope.h"

#include "FileSystemAccess.h"

#include <Aclapi.h>
#include <array>
#include <filesystem>
#include <sddl.h>
#include <vector>

namespace launch_as::broker
{
namespace
{

// controlled error instead of letting the broker get exhausted
// due to unlimited recursion depth
constexpr DWORD MaximumWriteScopeDepth = 128;
constexpr DWORD MaximumWriteScopeObjects = 100'000;
constexpr DWORD WriteScopeTimeoutMilliseconds = 30'000;

struct WriteScopeBudget
{
    DWORD remainingObjects;
    ULONGLONG deadline;

    DWORD CheckTime() const { return GetTickCount64() >= deadline ? ERROR_TIMEOUT : ERROR_SUCCESS; }

    DWORD ConsumeObject()
    {
        const DWORD timeError = CheckTime();
        if (timeError != ERROR_SUCCESS)
        {
            return timeError;
        }
        if (remainingObjects == 0)
        {
            return ERROR_NOT_ENOUGH_QUOTA;
        }
        --remainingObjects;
        return ERROR_SUCCESS;
    }
};

#ifdef LAUNCH_AS_TESTING
void (*writeScopeObserver)(HANDLE, bool) = nullptr;
void (*writeScopeChildObserver)(HANDLE, std::wstring_view) = nullptr;
#endif

class AccountImpersonation final
{
  public:
    ~AccountImpersonation()
    {
        // Continuing as the account after a failed revert would corrupt the broker boundary.
        if (active_ && !RevertToSelf())
        {
            std::terminate();
        }
    }
    DWORD Begin(HANDLE token)
    {
        if (!ImpersonateLoggedOnUser(token))
        {
            return GetLastError();
        }
        active_ = true;
        return ERROR_SUCCESS;
    }

  private:
    bool active_ = false;
};

bool IsWithin(const std::filesystem::path& path, const std::filesystem::path& root)
{
    const auto value = path.native();
    const auto prefix = root.native();
    return _wcsicmp(value.c_str(), prefix.c_str()) == 0 ||
           (value.size() > prefix.size() &&
               _wcsnicmp(value.c_str(), prefix.c_str(), prefix.size()) == 0 &&
               value[prefix.size()] == L'\\');
}

DWORD ValidateScopeRoot(const std::filesystem::path& path)
{
    if (!path.is_absolute() || path == path.root_path() || path.native().starts_with(L"\\\\") ||
        path.native().find(L':', 2) != std::wstring::npos)
    {
        return ERROR_BAD_PATHNAME;
    }
    std::array<wchar_t, MAX_PATH> windows {};
    if (GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size())) == 0)
    {
        return GetLastError();
    }
    if (IsWithin(path, std::filesystem::path(windows.data())))
    {
        return ERROR_ACCESS_DENIED;
    }
    for (const auto* name : {L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramData"})
    {
        std::array<wchar_t, 32'768> value {};
        const DWORD characters =
            GetEnvironmentVariableW(name, value.data(), static_cast<DWORD>(value.size()));
        if (characters == 0 || characters >= value.size())
        {
            return ERROR_BAD_ENVIRONMENT;
        }
        if (IsWithin(path, std::filesystem::path(value.data())))
        {
            return ERROR_ACCESS_DENIED;
        }
    }
    std::array<wchar_t, 32'768> publicProfile {};
    const DWORD characters = GetEnvironmentVariableW(
        L"PUBLIC", publicProfile.data(), static_cast<DWORD>(publicProfile.size()));
    if (characters == 0 || characters >= publicProfile.size())
    {
        return ERROR_BAD_ENVIRONMENT;
    }
    // The common profile parent (normally C:\Users) must never become a Low tree.
    if (_wcsicmp(path.c_str(), std::filesystem::path(publicProfile.data()).parent_path().c_str()) ==
        0)
    {
        return ERROR_ACCESS_DENIED;
    }
    return ERROR_SUCCESS;
}

DWORD HasLowLabel(HANDLE object, bool directory, bool& low)
{
    low = false;
    PACL label = nullptr;
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    const DWORD error = GetSecurityInfo(object,
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        &label,
        descriptor.address());
    if (error != ERROR_SUCCESS || label == nullptr)
    {
        return error;
    }
    for (DWORD index = 0; index < label->AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(label, index, &rawAce))
        {
            return GetLastError();
        }
        const auto* ace = static_cast<const SYSTEM_MANDATORY_LABEL_ACE*>(rawAce);
        if (ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE &&
            IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinLowLabelSid) &&
            (ace->Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) != 0 &&
            (ace->Header.AceFlags & INHERIT_ONLY_ACE) == 0 &&
            (!directory || (ace->Header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) ==
                               (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)))
        {
            low = true;
        }
    }
    return ERROR_SUCCESS;
}

bool IsUnavailableChildError(DWORD error)
{
    return error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION ||
           error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

DWORD LabelTree(HANDLE parent, std::wstring_view name, PACL label, bool root, DWORD depth,
    WriteScopeBudget& budget)
{
    if (depth > MaximumWriteScopeDepth)
    {
        return ERROR_NOT_ENOUGH_QUOTA;
    }
    const DWORD budgetError = budget.ConsumeObject();
    if (budgetError != ERROR_SUCCESS)
    {
        return budgetError;
    }
    // Pin each object against rename/replacement, and never resolve its ancestors by path.
    UniqueHandle object;
    const DWORD openError =
        OpenRelativeFile(parent, name, READ_CONTROL | FILE_READ_ATTRIBUTES, object);
    if (openError != ERROR_SUCCESS)
    {
        // Skip unavailable children, including entries removed since enumeration.
        return !root && IsUnavailableChildError(openError) ? ERROR_SUCCESS : openError;
    }
    BY_HANDLE_FILE_INFORMATION information {};
    if (!GetFileInformationByHandle(object.get(), &information))
    {
        return GetLastError();
    }
    if ((information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
            information.nNumberOfLinks != 1))
    {
        return root ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    }
    if (root && (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return ERROR_DIRECTORY;
    }
    const bool directory = (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#ifdef LAUNCH_AS_TESTING
    if (writeScopeObserver != nullptr)
    {
        writeScopeObserver(object.get(), false);
    }
#endif
    if (root)
    {
        DWORD flags = 0;
        if (!GetVolumeInformationByHandleW(
                object.get(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0))
        {
            return GetLastError();
        }
        if ((flags & FILE_PERSISTENT_ACLS) == 0)
        {
            return ERROR_NOT_SUPPORTED;
        }
    }
    bool low = false;
    DWORD error = HasLowLabel(object.get(), directory, low);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    if (!low)
    {
        // Metadata-only access is compatible with the read scope's no-delete sharing pins.
        // The native setter labels this object without propagating through links or children.
        UniqueHandle writable;
        const DWORD writeError = OpenRelativeFile(parent, name, WRITE_OWNER, writable);
        if (writeError != ERROR_SUCCESS)
        {
            return !root && IsUnavailableChildError(writeError) ? ERROR_SUCCESS : writeError;
        }
        error = SetObjectLabel(writable.get(), label);
        if (error != ERROR_SUCCESS)
        {
            return !root && IsUnavailableChildError(error) ? ERROR_SUCCESS : error;
        }
        error = HasLowLabel(object.get(), directory, low);
        if (error != ERROR_SUCCESS || !low)
        {
            return error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error;
        }
    }
    if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return ERROR_SUCCESS;
    }
#ifdef LAUNCH_AS_TESTING
    if (writeScopeObserver != nullptr)
    {
        writeScopeObserver(object.get(), true);
    }
#endif
    // A reparse update does not redirect enumeration of an already-open directory object.
    UniqueHandle entries;
    const DWORD enumerationOpenError = OpenRelativeFile(parent, name, FILE_LIST_DIRECTORY, entries);
    if (enumerationOpenError != ERROR_SUCCESS)
    {
        return !root && IsUnavailableChildError(enumerationOpenError) ? ERROR_SUCCESS
                                                                      : enumerationOpenError;
    }
    std::vector<BYTE> buffer(64 * 1024);
    for (;;)
    {
        const DWORD timeError = budget.CheckTime();
        if (timeError != ERROR_SUCCESS)
        {
            return timeError;
        }
        if (!GetFileInformationByHandleEx(entries.get(),
                FileIdBothDirectoryInfo,
                buffer.data(),
                static_cast<DWORD>(buffer.size())))
        {
            const DWORD enumerationError = GetLastError();
            if (enumerationError == ERROR_NO_MORE_FILES ||
                (!root && IsUnavailableChildError(enumerationError)))
            {
                return budget.CheckTime();
            }
            return enumerationError;
        }
        const auto* entry = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(buffer.data());
        for (;;)
        {
            const std::wstring_view child(entry->FileName, entry->FileNameLength / sizeof(wchar_t));
            if (child != L"." && child != L"..")
            {
#ifdef LAUNCH_AS_TESTING
                if (writeScopeChildObserver != nullptr)
                {
                    writeScopeChildObserver(object.get(), child);
                }
#endif
                const DWORD childError =
                    LabelTree(object.get(), child, label, false, depth + 1, budget);
                if (childError != ERROR_SUCCESS)
                {
                    return childError;
                }
            }
            if (entry->NextEntryOffset == 0)
            {
                break;
            }
            entry = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(
                reinterpret_cast<const BYTE*>(entry) + entry->NextEntryOffset);
        }
    }
}

DWORD LabelRoot(std::wstring_view directory, PACL label, WriteScopeBudget& budget)
{
    const DWORD timeError = budget.CheckTime();
    if (timeError != ERROR_SUCCESS)
    {
        return timeError;
    }
    auto path = std::filesystem::path(directory).lexically_normal();
    if (path != path.root_path() && path.filename().empty())
    {
        path = path.parent_path();
    }
    const DWORD validationError = ValidateScopeRoot(path);
    if (validationError != ERROR_SUCCESS)
    {
        return validationError;
    }
    // Anchor at the local volume, then pin and validate ancestors one component at a time.
    std::vector<UniqueHandle> ancestors;
    UniqueHandle volume(CreateFileW(path.root_path().c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!volume)
    {
        return GetLastError();
    }
    ancestors.push_back(std::move(volume));
    for (const auto& component : path.relative_path().parent_path())
    {
        const DWORD ancestorTimeError = budget.CheckTime();
        if (ancestorTimeError != ERROR_SUCCESS)
        {
            return ancestorTimeError;
        }
        UniqueHandle handle;
        const DWORD openError = OpenRelativeFile(
            ancestors.back().get(), component.native(), FILE_READ_ATTRIBUTES, handle);
        if (openError != ERROR_SUCCESS)
        {
            return openError;
        }
        FILE_ATTRIBUTE_TAG_INFO attributes {};
        if (!GetFileInformationByHandleEx(
                handle.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)))
        {
            return GetLastError();
        }
        if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return ERROR_ACCESS_DENIED;
        }
        ancestors.push_back(std::move(handle));
    }
    return LabelTree(ancestors.back().get(), path.filename().native(), label, true, 0, budget);
}

DWORD PrepareWriteScope(HANDLE token, std::wstring_view profileDirectory,
    std::wstring_view workingDirectory, DWORD maximumObjects, DWORD timeoutMilliseconds)
{
    // Share one budget across both trees, including already-Low and unavailable objects.
    WriteScopeBudget budget {maximumObjects, GetTickCount64() + timeoutMilliseconds};
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"S:(ML;OICI;NW;;;LW)", SDDL_REVISION_1, descriptor.address(), nullptr))
    {
        return GetLastError();
    }
    PACL label = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    if (!GetSecurityDescriptorSacl(descriptor.get(), &present, &label, &defaulted))
    {
        return GetLastError();
    }
    AccountImpersonation account;
    const DWORD impersonationError = account.Begin(token);
    if (impersonationError != ERROR_SUCCESS)
    {
        return impersonationError;
    }
    const DWORD profileError = LabelRoot(profileDirectory, label, budget);
    return profileError == ERROR_SUCCESS ? LabelRoot(workingDirectory, label, budget)
                                         : profileError;
}

} // namespace

#ifdef LAUNCH_AS_TESTING
void SetBrokerWriteScopeObserverForTesting(void (*observer)(HANDLE, bool)) noexcept
{
    writeScopeObserver = observer;
}

void SetBrokerWriteScopeChildObserverForTesting(
    void (*observer)(HANDLE, std::wstring_view)) noexcept
{
    writeScopeChildObserver = observer;
}

DWORD PrepareBrokerWriteScopeWithLimitsForTesting(HANDLE token, std::wstring_view profileDirectory,
    std::wstring_view workingDirectory, DWORD maximumObjects, DWORD timeoutMilliseconds)
{
    return PrepareWriteScope(
        token, profileDirectory, workingDirectory, maximumObjects, timeoutMilliseconds);
}
#endif

DWORD PrepareBrokerWriteScope(
    HANDLE token, std::wstring_view profileDirectory, std::wstring_view workingDirectory)
{
    return PrepareWriteScope(token,
        profileDirectory,
        workingDirectory,
        MaximumWriteScopeObjects,
        WriteScopeTimeoutMilliseconds);
}

} // namespace launch_as::broker
