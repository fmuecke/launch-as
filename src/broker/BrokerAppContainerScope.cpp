// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAppContainerScope.h"

#include "AppContainerIdentity.h"
#include "FileSystemAccess.h"

#include <Aclapi.h>
#include <array>
#include <exception>
#include <filesystem>

namespace launch_as::broker
{
namespace
{
constexpr DWORD ModifyAccess =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;

class AccountImpersonation final
{
  public:
    ~AccountImpersonation()
    {
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

DWORD OpenAsAccount(
    HANDLE token, HANDLE parent, std::wstring_view name, DWORD access, UniqueHandle& object)
{
    AccountImpersonation account;
    DWORD error = account.Begin(token);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    return OpenRelativeFile(parent, name, access, object);
}

DWORD GrantPackageAccess(HANDLE token, HANDLE object, PSID sid)
{
    const DWORD mask = ModifyAccess;
    PACL oldDacl = nullptr;
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    DWORD error = GetSecurityInfo(object,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &oldDacl,
        nullptr,
        descriptor.address());
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    // Do not turn a null DACL into a restrictive DACL as a side effect of adding a grant.
    if (!oldDacl)
    {
        return ERROR_INVALID_ACL;
    }
    constexpr BYTE flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    bool granted = false;
    for (DWORD index = 0; index < oldDacl->AceCount; ++index)
    {
        void* raw = nullptr;
        if (!GetAce(oldDacl, index, &raw))
        {
            return GetLastError();
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (ace->Header.AceFlags & INHERIT_ONLY_ACE) == 0 &&
            (ace->Header.AceFlags & flags) == flags && (ace->Mask & mask) == mask &&
            EqualSid(const_cast<DWORD*>(&ace->SidStart), sid))
        {
            granted = true;
            break;
        }
    }
    LocalAllocation<PACL> dacl;
    if (!granted)
    {
        EXPLICIT_ACCESSW access {};
        access.grfAccessPermissions = mask;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = flags;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        access.Trustee.ptstrName = static_cast<LPWSTR>(sid);
        error = SetEntriesInAclW(1, &access, oldDacl, dacl.address());
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
    }
    UniqueHandle writable;
    error =
        ReopenPinnedFile(object, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | WRITE_DAC, writable);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    // Delegate metadata access only to the authorized, pinned root. Windows propagates to
    // existing descendants under the account's ordinary rights, never the broker's privileges.
    // Repeat even for an existing grant so moved-in entries receive inherited access too.
    AccountImpersonation account;
    error = account.Begin(token);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    return SetSecurityInfo(writable.get(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        granted ? oldDacl : dacl.get(),
        nullptr);
}

DWORD GrantRoot(HANDLE token, const std::filesystem::path& path, PSID sid, std::wstring& context)
{
    context = L"validate and open preparation root '" + path.native() + L"'";
    if (!path.is_absolute() || path == path.root_path() || path.native().starts_with(L"\\\\") ||
        path.native().find(L':', 2) != std::wstring::npos ||
        GetDriveTypeW(path.root_path().c_str()) == DRIVE_REMOTE)
    {
        return ERROR_BAD_PATHNAME;
    }
    const auto within = [&](const std::filesystem::path& root)
    {
        const auto prefix = root.native();
        return _wcsicmp(path.c_str(), prefix.c_str()) == 0 ||
               (path.native().size() > prefix.size() &&
                   _wcsnicmp(path.c_str(), prefix.c_str(), prefix.size()) == 0 &&
                   path.native()[prefix.size()] == L'\\');
    };
    std::array<wchar_t, MAX_PATH> windows {};
    if (!GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size())))
    {
        return GetLastError();
    }
    if (within(windows.data()))
    {
        return ERROR_ACCESS_DENIED;
    }
    for (const auto* variable : {L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramData", L"PUBLIC"})
    {
        std::vector<wchar_t> value(32'768);
        const DWORD characters =
            GetEnvironmentVariableW(variable, value.data(), static_cast<DWORD>(value.size()));
        if (!characters || characters >= value.size())
        {
            return ERROR_BAD_ENVIRONMENT;
        }
        const std::filesystem::path protectedPath(value.data());
        if (std::wstring_view(variable) == L"PUBLIC")
        {
            if (_wcsicmp(path.c_str(), protectedPath.parent_path().c_str()) == 0)
            {
                return ERROR_ACCESS_DENIED;
            }
        }
        else if (within(protectedPath))
        {
            return ERROR_ACCESS_DENIED;
        }
    }
    // Hold every ancestor against replacement and reject junctions before opening the tree.
    std::vector<UniqueHandle> ancestors;
    UniqueHandle volume;
    {
        AccountImpersonation account;
        const DWORD impersonationError = account.Begin(token);
        if (impersonationError != ERROR_SUCCESS)
        {
            return impersonationError;
        }
        volume.reset(CreateFileW(path.root_path().c_str(),
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
    }
    ancestors.push_back(std::move(volume));
    for (const auto& component : path.relative_path().parent_path())
    {
        UniqueHandle ancestor;
        DWORD error = OpenAsAccount(
            token, ancestors.back().get(), component.native(), FILE_READ_ATTRIBUTES, ancestor);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
        FILE_ATTRIBUTE_TAG_INFO info {};
        if (!GetFileInformationByHandleEx(
                ancestor.get(), FileAttributeTagInfo, &info, sizeof(info)))
        {
            return GetLastError();
        }
        if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return ERROR_ACCESS_DENIED;
        }
        ancestors.push_back(std::move(ancestor));
    }
    UniqueHandle object;
    context = L"verify managed account read/write/execute access on '" + path.native() + L"'";
    DWORD error = OpenAsAccount(token,
        ancestors.back().get(),
        path.filename().native(),
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        object);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    FILE_ATTRIBUTE_TAG_INFO info {};
    if (!GetFileInformationByHandleEx(object.get(), FileAttributeTagInfo, &info, sizeof(info)))
    {
        return GetLastError();
    }
    if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    {
        return ERROR_ACCESS_DENIED;
    }
    if ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return ERROR_DIRECTORY;
    }
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
    context = L"grant inheritable AppContainer Modify access on '" + path.native() + L"'";
    return GrantPackageAccess(token, object.get(), sid);
}

} // namespace

DWORD PrepareBrokerAppContainerScope(HANDLE token, const std::wstring& profileDirectory,
    const std::wstring& workingDirectory, const AppContainerOptions& options, std::wstring& context)
{
    AppContainerIdentity identity;
    {
        // CreateAppContainerProfile is per user, even though filesystem metadata preparation
        // below uses the broker identity after each account access check.
        AccountImpersonation account;
        DWORD error = account.Begin(token);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
        error = identity.Initialize(token, workingDirectory, options);
        if (error != ERROR_SUCCESS)
        {
            context = identity.failureContext();
            return error;
        }
    }
    PSID sid = identity.security()->AppContainerSid;
    const DWORD error = GrantRoot(token, profileDirectory, sid, context);
    return error == ERROR_SUCCESS ? GrantRoot(token, workingDirectory, sid, context) : error;
}

#ifdef LAUNCH_AS_TESTING
DWORD PrepareBrokerAppContainerRootForTesting(
    HANDLE token, const std::wstring& directory, PSID sid, std::wstring& context)
{
    return GrantRoot(token, directory, sid, context);
}

#endif

} // namespace launch_as::broker
