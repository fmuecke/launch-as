// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerLogonToken.h"
#include "BrokerReadScope.h"
#include "FileSystemAccess.h"
#include "ScopeTestSupport.h"
#include "TestSupport.h"

#include <Aclapi.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <sddl.h>
#include <winternl.h>

using namespace launch_as;
using namespace launch_as::broker;

namespace
{
std::wstring unavailableVolume;
DWORD volumeError = ERROR_SUCCESS;
UINT unavailableDriveType = DRIVE_UNKNOWN;

DWORD ProbeUnavailableVolume(std::wstring_view path, UINT& driveType)
{
    if (path == unavailableVolume)
    {
        driveType = unavailableDriveType;
        return volumeError;
    }
    return ERROR_SUCCESS;
}

bool CanOpen(const std::filesystem::path& path, DWORD access)
{
    UniqueHandle file(CreateFileW(path.c_str(),
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    return static_cast<bool>(file);
}

std::wstring DaclText(HANDLE object, SE_OBJECT_TYPE type = SE_FILE_OBJECT)
{
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    LocalAllocation<PWSTR> text;
    if (GetSecurityInfo(object,
            type,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            descriptor.address()) != ERROR_SUCCESS ||
        !ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.get(), SDDL_REVISION_1, DACL_SECURITY_INFORMATION, text.address(), nullptr))
    {
        return {};
    }
    return text.get();
}

UniqueHandle NamespaceDirectory(
    std::wstring_view path, DWORD access, PSECURITY_DESCRIPTOR descriptor = nullptr)
{
    using OpenOrCreate = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    const auto function =
        reinterpret_cast<OpenOrCreate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
            descriptor == nullptr ? "NtOpenDirectoryObject" : "NtCreateDirectoryObject"));
    if (function == nullptr)
    {
        return {};
    }
    UNICODE_STRING name {};
    name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
    name.MaximumLength = name.Length;
    name.Buffer = const_cast<PWSTR>(path.data());
    OBJECT_ATTRIBUTES attributes {};
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.SecurityDescriptor = descriptor;
    HANDLE raw = nullptr;
    return function(&raw, access, &attributes) < 0 ? UniqueHandle {} : UniqueHandle(raw);
}
bool TestEnumerationLimits(HANDLE token)
{
    test::TemporaryDirectory temporary;
    const auto volume = temporary.path() / L"volume";
    const auto profile = volume / L"profile";
    const auto work = volume / L"work";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(work);
    for (int index = 0; index < 32; ++index)
    {
        std::ofstream(volume / (L"loose-" + std::to_wstring(index) + L".txt")) << "budget";
    }
    UniqueHandle root(CreateFileW(volume.c_str(),
        READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    const auto original = DaclText(root.get());
    const std::array volumes {volume.native()};
    BrokerReadScope scope;
    const DWORD error =
        scope.EnsureForTesting(token, volumes, {}, profile.native(), work.native(), 16);
    const DWORD restoreError = scope.Restore();
    bool passed = Expect(error == ERROR_NOT_ENOUGH_QUOTA && restoreError == ERROR_SUCCESS &&
                             !original.empty() && DaclText(root.get()) == original,
        L"Loose-file enumeration exceeded its budget or failed to restore partial ACL edits.");
    passed = Expect(scope.EnsureForTesting(
                        token, volumes, {}, profile.native(), work.native(), 10'000, 0) ==
                            ERROR_TIMEOUT &&
                        scope.Restore() == ERROR_SUCCESS && DaclText(root.get()) == original,
                 L"Read-scope preparation continued after its deadline.") &&
             passed;
    return passed;
}

bool TestDirectoryPins(HANDLE token)
{
    test::TemporaryDirectory temporary;
    const auto volume = temporary.path() / L"volume";
    const auto profile = volume / L"profile";
    const auto work = volume / L"work";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(work);
    if (!Expect(CanOpen(work, DELETE), L"The pin fixture must initially permit deletion."))
    {
        return false;
    }
    BrokerReadScope scope;
    const std::array volumes {volume.native()};
    if (!Expect(scope.EnsureForTesting(token, volumes, {}, profile.native(), work.native()) ==
                    ERROR_SUCCESS,
            L"Could not prepare the directory-pin fixture."))
    {
        return false;
    }
    // The work root receives no deny. Its pin still blocks DELETE handles for every caller,
    // including an ordinary token with traversal bypass and full DACL access to this folder.
    UniqueHandle deleting(CreateFileW(work.c_str(),
        DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    const DWORD error = deleting ? ERROR_SUCCESS : GetLastError();
    const bool pinned = Expect(error == ERROR_SHARING_VIOLATION,
        L"A live scope must pin allowed roots against rename and deletion regardless of ACLs.");
    deleting.reset();
    return Expect(scope.Restore() == ERROR_SUCCESS && CanOpen(work, DELETE) &&
                      RemoveDirectoryW(work.c_str()),
               L"Final scope restoration did not release the directory pin.") &&
           pinned;
}

bool TestVolumePreparationRetry(HANDLE token)
{
    test::TemporaryDirectory temporary;
    const auto volume = temporary.path() / L"volume";
    const auto profile = volume / L"profile";
    const auto work = volume / L"work";
    const auto blocked = volume / L"private";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(work);
    std::filesystem::create_directories(blocked);
    UniqueHandle blockedHandle(CreateFileW(blocked.c_str(),
        READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    const auto original = DaclText(blockedHandle.get());
    const std::array initialVolumes {volume.native()};
    bool passed = true;
    for (const bool timeout : {false, true})
    {
        const auto discovered = temporary.path() / (timeout ? L"timeout-volume" : L"budget-volume");
        std::filesystem::create_directory(discovered);
        UniqueHandle discoveredHandle(CreateFileW(discovered.c_str(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr));
        const auto discoveredOriginal = DaclText(discoveredHandle.get());
        BrokerReadScope scope;
        if (!Expect(!original.empty() && !discoveredOriginal.empty() &&
                        scope.EnsureForTesting(
                            token, initialVolumes, {}, profile.native(), work.native()) ==
                            ERROR_SUCCESS,
                L"Could not prepare the live scope for volume retry."))
        {
            return false;
        }
        const auto prepared = DaclText(blockedHandle.get());
        const std::array volumes {discovered.native(), volume.native()};
        const DWORD error = scope.EnsureForTesting(token,
            volumes,
            {},
            profile.native(),
            work.native(),
            timeout ? 10'000 : 0,
            timeout ? 0 : 30'000);
        const DWORD expected = timeout ? ERROR_TIMEOUT : ERROR_NOT_ENOUGH_QUOTA;
        passed = Expect(error == expected && prepared != original &&
                            DaclText(blockedHandle.get()) == prepared,
                     L"A failed new-volume visit changed the existing live scope.") &&
                 passed;
        // Keep the existing scope alive: a joining launch must retry without restoration.
        passed = Expect(scope.EnsureForTesting(
                            token, volumes, {}, profile.native(), work.native()) == ERROR_SUCCESS &&
                            DaclText(discoveredHandle.get()) != discoveredOriginal,
                     L"A failed first visit poisoned subsequent volume preparation.") &&
                 passed;
        passed =
            Expect(scope.Restore() == ERROR_SUCCESS && DaclText(blockedHandle.get()) == original &&
                       DaclText(discoveredHandle.get()) == discoveredOriginal,
                L"Volume retry did not preserve final ACL restoration.") &&
            passed;
    }
    return passed;
}
} // namespace

int wmain()
{
    test::TemporaryDirectory temporary;
    if (!temporary.created() || !test::GrantScopeFixtureAccess(temporary.path()))
    {
        return 1;
    }
    const auto volume = temporary.path() / L"volume";
    const auto otherVolume = temporary.path() / L"other-volume";
    const auto readable = volume / L"Windows";
    const auto profile = volume / L"Users" / L"me";
    const auto otherProfile = volume / L"Users" / L"other";
    const auto work = volume / L"dev" / L"work";
    const auto workSibling = volume / L"dev" / L"other";
    const auto blocked = volume / L"private";
    for (const auto& directory :
        {readable, profile, otherProfile, work, workSibling, blocked, otherVolume})
    {
        std::filesystem::create_directories(directory);
        std::ofstream(directory / L"file.txt") << "read scope";
    }
    std::ofstream(volume / L"base-file.txt") << "base file";
    UniqueHandle openDirectory(CreateFileW(blocked.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    if (!Expect(static_cast<bool>(openDirectory),
            L"Could not hold a directory with read-only sharing."))
    {
        return 1;
    }
    std::ofstream(volume / L"open-log.txt") << "open log";
    UniqueHandle openLog(CreateFileW((volume / L"open-log.txt").c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr));
    if (!Expect(static_cast<bool>(openLog), L"Could not create the open-log regression fixture."))
    {
        return 1;
    }
    // A protected child explicitly grants read access; the base deny cannot inherit into it.
    LocalAllocation<PSECURITY_DESCRIPTOR> protectedDescriptor;
    PACL protectedDacl = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;WD)", SDDL_REVISION_1, protectedDescriptor.address(), nullptr) ||
        !GetSecurityDescriptorDacl(
            protectedDescriptor.get(), &present, &protectedDacl, &defaulted) ||
        SetNamedSecurityInfoW(const_cast<LPWSTR>((blocked / L"file.txt").c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            protectedDacl,
            nullptr) != ERROR_SUCCESS)
    {
        return 1;
    }
    UniqueHandle originalHandle(CreateFileW(blocked.c_str(),
        READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    const auto protectedRoot = volume / L"protected-root";
    std::filesystem::create_directory(protectedRoot);
    if (SetNamedSecurityInfoW(const_cast<LPWSTR>(protectedRoot.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            protectedDacl,
            nullptr) != ERROR_SUCCESS)
    {
        return 1;
    }
    UniqueHandle protectedRootHandle(CreateFileW(protectedRoot.c_str(),
        READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    const auto protectedOriginal = DaclText(protectedRootHandle.get());
    // Exercise legacy inherited ACLs without AUTO_INHERITED even when the host's temp
    // directory normally creates auto-inherited ACLs (unlike some Server 2022 runners).
    LocalAllocation<PSECURITY_DESCRIPTOR> legacyDescriptor;
    PACL legacyDacl = nullptr;
    if (GetSecurityInfo(originalHandle.get(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &legacyDacl,
            nullptr,
            legacyDescriptor.address()) != ERROR_SUCCESS ||
        SetObjectDacl(originalHandle.get(), legacyDacl, 0) != ERROR_SUCCESS)
    {
        return 1;
    }
    const auto originalDacl = DaclText(originalHandle.get());
    if (!Expect(originalDacl.starts_with(L"D:("),
            L"The legacy ACL fixture must lack auto-inheritance and protection flags."))
    {
        return 1;
    }
    UniqueHandle baseFileHandle(CreateFileW((volume / L"base-file.txt").c_str(),
        READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr));
    const auto baseFileDacl = DaclText(baseFileHandle.get());
    const auto openLogDacl = DaclText(openLog.get());
    UniqueHandle identityHandle(CreateFileW((blocked / L"file.txt").c_str(),
        FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr));
    BY_HANDLE_FILE_INFORMATION identity {};
    if (!identityHandle || !GetFileInformationByHandle(identityHandle.get(), &identity))
    {
        return 1;
    }
    const auto childFileDacl = DaclText(identityHandle.get());
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &rawToken))
    {
        return 1;
    }
    UniqueHandle token(rawToken);
    if (!TestEnumerationLimits(token.get()) || !TestDirectoryPins(token.get()) ||
        !TestVolumePreparationRetry(token.get()))
    {
        return 1;
    }
    UniqueHandle restricted;
    const DWORD tokenError = CreateBrokerLaunchToken(token.get(), true, false, restricted);
    if (!Expect(tokenError == ERROR_SUCCESS, L"Could not create a read-restricted launch token."))
    {
        std::wcerr << L"Token error: " << tokenError << L"\n";
        return 1;
    }
    LUID workingSet {};
    std::vector<BYTE> originalPrivileges;
    std::vector<BYTE> scopedPrivileges;
    if (!LookupPrivilegeValueW(nullptr, SE_INC_WORKING_SET_NAME, &workingSet) ||
        QueryTokenInformation(token.get(), TokenPrivileges, originalPrivileges) != ERROR_SUCCESS ||
        QueryTokenInformation(restricted.get(), TokenPrivileges, scopedPrivileges) != ERROR_SUCCESS)
    {
        return 1;
    }
    const auto isWorkingSet = [&](const LUID_AND_ATTRIBUTES& value)
    {
        return value.Luid.LowPart == workingSet.LowPart &&
               value.Luid.HighPart == workingSet.HighPart;
    };
    const auto* originalValues =
        reinterpret_cast<const TOKEN_PRIVILEGES*>(originalPrivileges.data());
    bool hadWorkingSet = false;
    for (DWORD index = 0; index < originalValues->PrivilegeCount; ++index)
    {
        hadWorkingSet = hadWorkingSet || isWorkingSet(originalValues->Privileges[index]);
    }
    const auto* scopedValues = reinterpret_cast<const TOKEN_PRIVILEGES*>(scopedPrivileges.data());
    if (!Expect(scopedValues->PrivilegeCount == (hadWorkingSet ? 1u : 0u) &&
                    (!hadWorkingSet ||
                        (isWorkingSet(scopedValues->Privileges[0]) &&
                            (scopedValues->Privileges[0].Attributes & SE_PRIVILEGE_ENABLED) == 0)),
            L"The read token must remove all privileges except an existing disabled working-set "
            L"privilege."))
    {
        return 1;
    }
    std::vector<BYTE> user;
    LocalAllocation<PWSTR> userSidText;
    if (QueryTokenInformation(token.get(), TokenUser, user) != ERROR_SUCCESS ||
        !ConvertSidToStringSidW(
            reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, userSidText.address()))
    {
        return 1;
    }
    // Allowed roots with existing traversal need no DACL edits. Model a system tree whose
    // ACL can be read but not modified, including through the owner's implicit WRITE_DAC.
    UniqueHandle readableHandle(CreateFileW(readable.c_str(),
        READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    const auto readableSddl =
        L"D:P(D;;WD;;;OW)(A;;FA;;;" + std::wstring(userSidText.get()) + L")(A;;FA;;;SY)";
    LocalAllocation<PSECURITY_DESCRIPTOR> readableDescriptor;
    PACL readableDacl = nullptr;
    if (!readableHandle ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(
            readableSddl.c_str(), SDDL_REVISION_1, readableDescriptor.address(), nullptr) ||
        !GetSecurityDescriptorDacl(readableDescriptor.get(), &present, &readableDacl, &defaulted) ||
        SetObjectDacl(readableHandle.get(), readableDacl, SE_DACL_PROTECTED) != ERROR_SUCCESS ||
        !Expect(CanOpen(readable, READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY) &&
                    !CanOpen(readable, WRITE_DAC),
            L"The allowed-root regression must permit reads but reject DACL-edit opens."))
    {
        return 1;
    }
    const auto readableOriginal = DaclText(readableHandle.get());
    // Simulate an explicitly shared working tree under a private parent lacking traversal.
    UniqueHandle parentHandle(CreateFileW(work.parent_path().c_str(),
        READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    const auto parentSddl =
        L"D:P(A;;0x00160081;;;" + std::wstring(userSidText.get()) + L")(A;;FA;;;SY)";
    LocalAllocation<PSECURITY_DESCRIPTOR> parentDescriptor;
    PACL parentDacl = nullptr;
    if (!parentHandle ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(
            parentSddl.c_str(), SDDL_REVISION_1, parentDescriptor.address(), nullptr) ||
        !GetSecurityDescriptorDacl(parentDescriptor.get(), &present, &parentDacl, &defaulted) ||
        SetObjectDacl(parentHandle.get(), parentDacl, SE_DACL_PROTECTED) != ERROR_SUCCESS)
    {
        return 1;
    }
    const auto parentOriginal = DaclText(parentHandle.get());
    std::vector<std::pair<std::wstring, std::wstring>> decisions;
    BrokerReadScope scope;
    scope.SetObserver([&](std::wstring_view action, std::wstring_view path, DWORD)
        { decisions.emplace_back(action, path); });
    const std::array volumes {volume.native(), otherVolume.native()};
    const std::array readRoots {readable.native()};
    DWORD error =
        scope.EnsureForTesting(token.get(), volumes, readRoots, profile.native(), work.native());
    if (!Expect(error == ERROR_SUCCESS, L"Could not prepare the synthetic read scope."))
    {
        std::wcerr << L"Scope error: " << error << L" at " << scope.failurePath() << L"\n";
        return 1;
    }
    bool passed = Expect(CanOpen(blocked / L"file.txt", GENERIC_READ),
        L"The protected-child probe did not exercise traversal bypass.");
    const auto observed = [&](std::wstring_view action, std::wstring_view suffix)
    {
        return std::ranges::any_of(decisions,
            [&](const auto& entry)
            { return entry.first == action && entry.second.ends_with(suffix); });
    };
    passed = Expect(observed(L"read.deny_selected", L"\\private") &&
                        observed(L"read.excluded_from_deny", L"\\Windows") &&
                        observed(L"read.ancestor_traverse", L"\\volume"),
                 L"Read-scope logging omitted deny, exclusion, or traversal decisions.") &&
             passed;
    const auto namespacePath =
        L"\\BaseNamedObjects\\launch-as-read-scope-" + temporary.path().filename().native();
    const auto namespaceSddl =
        L"D:(A;;RCWD;;;" + std::wstring(userSidText.get()) + L")(A;;GA;;;SY)";
    LocalAllocation<PSECURITY_DESCRIPTOR> namespaceDescriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            namespaceSddl.c_str(), SDDL_REVISION_1, namespaceDescriptor.address(), nullptr))
    {
        return 1;
    }
    UniqueHandle namespaceObject =
        NamespaceDirectory(namespacePath, READ_CONTROL | WRITE_DAC, namespaceDescriptor.get());
    if (!Expect(
            static_cast<bool>(namespaceObject), L"Could not create a private namespace fixture."))
    {
        return 1;
    }
    const auto namespaceOriginal = DaclText(namespaceObject.get(), SE_KERNEL_OBJECT);
    if (!ImpersonateLoggedOnUser(restricted.get()))
    {
        return 1;
    }
    passed = Expect(!NamespaceDirectory(namespacePath, 0x0002),
                 L"The namespace fixture already permitted traversal.") &&
             passed;
    if (!RevertToSelf())
    {
        std::terminate();
    }
    const std::array namespaceDirectories {namespacePath};
    passed = Expect(scope.EnsureNamespaceForTesting(namespaceDirectories) == ERROR_SUCCESS,
                 L"Could not prepare temporary namespace traversal.") &&
             passed;
    const auto namespacePrepared = DaclText(namespaceObject.get(), SE_KERNEL_OBJECT);
    passed = Expect(scope.EnsureNamespaceForTesting(namespaceDirectories) == ERROR_SUCCESS &&
                        DaclText(namespaceObject.get(), SE_KERNEL_OBJECT) == namespacePrepared,
                 L"Repeated namespace preparation accumulated traversal grants.") &&
             passed;
    if (!ImpersonateLoggedOnUser(restricted.get()))
    {
        return 1;
    }
    passed = Expect(static_cast<bool>(NamespaceDirectory(namespacePath, 0x0002)),
                 L"Namespace traversal remained blocked after preparation.") &&
             passed;
    if (!RevertToSelf())
    {
        std::terminate();
    }
    passed = Expect(DaclText(baseFileHandle.get()) == baseFileDacl &&
                        DaclText(openLog.get()) == openLogDacl &&
                        DaclText(identityHandle.get()) == childFileDacl,
                 L"Folder-only preparation changed an individual file DACL.") &&
             passed;
    const auto preparedDacl = DaclText(originalHandle.get());
    LocalAllocation<PSECURITY_DESCRIPTOR> originalDescriptor;
    PACL originalAcl = nullptr;
    SECURITY_DESCRIPTOR_CONTROL originalControl {};
    DWORD originalRevision = 0;
    // Simulate deny removal without SetSecurityInfo's auto-inheritance side effects.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            originalDacl.c_str(), SDDL_REVISION_1, originalDescriptor.address(), nullptr) ||
        !GetSecurityDescriptorDacl(originalDescriptor.get(), &present, &originalAcl, &defaulted) ||
        !GetSecurityDescriptorControl(
            originalDescriptor.get(), &originalControl, &originalRevision) ||
        SetObjectDacl(originalHandle.get(), originalAcl, originalControl) != ERROR_SUCCESS)
    {
        return 1;
    }
    // The lease must ensure the same ACLs on each launch without accumulating duplicate denies.
    error =
        scope.EnsureForTesting(token.get(), volumes, readRoots, profile.native(), work.native());
    passed = Expect(error == ERROR_SUCCESS && DaclText(originalHandle.get()) == preparedDacl,
                 L"Repeated scope preparation did not restore a removed deny exactly once.") &&
             passed;
    if (!ImpersonateLoggedOnUser(restricted.get()))
    {
        return 1;
    }
    passed = Expect(CanOpen(readable / L"file.txt", GENERIC_READ) &&
                        CanOpen(profile / L"file.txt", GENERIC_WRITE) &&
                        CanOpen(work / L"file.txt", GENERIC_WRITE),
                 L"Read restriction blocked an allowed path.") &&
             passed;
    passed = Expect(!CanOpen(blocked / L"file.txt", GENERIC_READ) &&
                        !CanOpen(otherProfile / L"file.txt", GENERIC_READ) &&
                        !CanOpen(otherVolume / L"file.txt", GENERIC_READ),
                 L"Read restriction did not block an excluded path.") &&
             passed;
    passed = Expect(CanOpen(volume / L"base-file.txt", GENERIC_READ),
                 L"Loose files in allowed-path ancestors must retain normal ACL access.") &&
             passed;
    passed = Expect(!CanOpen(blocked, WRITE_DAC), L"An owner could remove its base-folder deny.") &&
             passed;
    UniqueHandle hint(CreateFileW((work / L"file.txt").c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr));
    FILE_ID_DESCRIPTOR identifier {};
    identifier.dwSize = sizeof(identifier);
    identifier.Type = FileIdType;
    identifier.FileId.LowPart = identity.nFileIndexLow;
    identifier.FileId.HighPart = static_cast<LONG>(identity.nFileIndexHigh);
    UniqueHandle byId(OpenFileById(
        hint.get(), &identifier, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, 0));
    // This is an intentional path-only policy, not a file read allowlist. Keep the known
    // file-ID bypass observable so future claims cannot overstate the directory ACL boundary.
    std::array<char, 64> content {};
    DWORD bytes = 0;
    passed = Expect(hint && byId &&
                        ReadFile(byId.get(),
                            content.data(),
                            static_cast<DWORD>(content.size()),
                            &bytes,
                            nullptr) &&
                        std::string_view(content.data(), bytes) == "read scope",
                 L"The file-ID probe no longer matches the documented path-only policy.") &&
             passed;
    if (!RevertToSelf())
    {
        std::terminate();
    }
    // A later launch may select a parent of an earlier working directory. Its existing
    // children must become accessible too, while exclusions elsewhere retain their denies.
    error = scope.EnsureForTesting(
        token.get(), volumes, readRoots, profile.native(), work.parent_path().native());
    passed = Expect(error == ERROR_SUCCESS,
                 L"Could not extend the shared scope to a parent working directory.") &&
             passed;
    if (!ImpersonateLoggedOnUser(restricted.get()))
    {
        return 1;
    }
    passed = Expect(CanOpen(workSibling / L"file.txt", GENERIC_WRITE) &&
                        !CanOpen(blocked / L"file.txt", GENERIC_READ),
                 L"Extending a shared working directory retained obsolete sibling denies.") &&
             passed;
    passed = Expect(DeleteFileW((workSibling / L"file.txt").c_str()) &&
                        RemoveDirectoryW(workSibling.c_str()),
                 L"A formerly excluded child folder remained pinned after it became writable.") &&
             passed;
    if (!RevertToSelf())
    {
        std::terminate();
    }
    passed =
        Expect(scope.Restore() == ERROR_SUCCESS && DaclText(originalHandle.get()) == originalDacl &&
                   DaclText(namespaceObject.get(), SE_KERNEL_OBJECT) == namespaceOriginal &&
                   DaclText(parentHandle.get()) == parentOriginal &&
                   DaclText(readableHandle.get()) == readableOriginal &&
                   CanOpen(blocked / L"file.txt", GENERIC_READ) &&
                   DaclText(protectedRootHandle.get()) == protectedOriginal,
            L"Scope teardown did not restore the original ACL and access.") &&
        passed;
    // A preparation failure still leaves a restorable lease; no child is launched on failure.
    if (DaclText(originalHandle.get()) != originalDacl)
    {
        std::wcerr << L"Original DACL: " << originalDacl << L"\nRestored DACL: "
                   << DaclText(originalHandle.get()) << L"\n";
    }
    const std::array missingVolumes {volume.native(), (temporary.path() / L"missing").native()};
    error = scope.EnsureForTesting(
        token.get(), missingVolumes, readRoots, profile.native(), work.native());
    passed = Expect(error != ERROR_SUCCESS && scope.Restore() == ERROR_SUCCESS &&
                        DaclText(originalHandle.get()) == originalDacl,
                 L"Partial preparation was not restored.") &&
             passed;
    error =
        scope.EnsureForTesting(token.get(), volumes, readRoots, profile.native(), work.native());
    passed =
        Expect(error == ERROR_SUCCESS, L"Could not prepare the ACL-edit regression.") && passed;
    LocalAllocation<PSECURITY_DESCRIPTOR> currentDescriptor;
    PACL currentAcl = nullptr;
    LocalAllocation<PSID> localService;
    LocalAllocation<PACL> editedAcl;
    EXPLICIT_ACCESSW grant {};
    grant.grfAccessPermissions = READ_CONTROL;
    grant.grfAccessMode = GRANT_ACCESS;
    grant.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    if (!ConvertStringSidToSidW(L"S-1-5-19", localService.address()) ||
        GetSecurityInfo(originalHandle.get(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &currentAcl,
            nullptr,
            currentDescriptor.address()) != ERROR_SUCCESS)
    {
        return 1;
    }
    grant.Trustee.ptstrName = static_cast<LPWSTR>(localService.get());
    if (SetEntriesInAclW(1, &grant, currentAcl, editedAcl.address()) != ERROR_SUCCESS ||
        SetSecurityInfo(originalHandle.get(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            editedAcl.get(),
            nullptr) != ERROR_SUCCESS)
    {
        return 1;
    }
    passed = Expect(scope.Restore() == ERROR_SUCCESS &&
                        DaclText(originalHandle.get()).find(L";;;LS)") != std::wstring::npos,
                 L"Scope teardown discarded an unrelated ACL edit.") &&
             passed;
    // Empty media must not abort preparation of other volumes. Other failures remain fatal,
    // including a fixed drive that is not ready and loaded media without ACL support.
    unavailableVolume = (temporary.path() / L"unavailable-volume").native();
    const std::array mediaVolumes {volume.native(), unavailableVolume};
    const auto beforeMedia = DaclText(originalHandle.get());
    struct MediaCase
    {
        DWORD error;
        UINT driveType;
        DWORD expected;
    };
    for (const auto& media :
        {MediaCase {ERROR_NOT_READY, DRIVE_CDROM, ERROR_SUCCESS},
            MediaCase {ERROR_NOT_READY, DRIVE_REMOVABLE, ERROR_SUCCESS},
            MediaCase {ERROR_NOT_READY, DRIVE_FIXED, ERROR_NOT_READY},
            MediaCase {ERROR_NOT_READY, DRIVE_UNKNOWN, ERROR_NOT_READY},
            MediaCase {ERROR_ACCESS_DENIED, DRIVE_CDROM, ERROR_ACCESS_DENIED},
            MediaCase {ERROR_NOT_SUPPORTED, DRIVE_REMOVABLE, ERROR_NOT_SUPPORTED}})
    {
        volumeError = media.error;
        unavailableDriveType = media.driveType;
        decisions.clear();
        scope.SetObserver([&](std::wstring_view action, std::wstring_view path, DWORD)
            { decisions.emplace_back(action, path); });
        SetBrokerReadScopeVolumeProbeForTesting(ProbeUnavailableVolume);
        error = scope.EnsureForTesting(
            token.get(), mediaVolumes, readRoots, profile.native(), work.native());
        SetBrokerReadScopeVolumeProbeForTesting(nullptr);
        passed = Expect(observed(L"read.skip_empty_drive", L"\\unavailable-volume") ==
                            (media.expected == ERROR_SUCCESS),
                     L"Empty-drive logging did not match the media decision.") &&
                 passed;
        passed =
            Expect(error == media.expected,
                L"Volume preparation did not distinguish empty media from a required failure.") &&
            passed;
        passed =
            Expect(DaclText(originalHandle.get()) != beforeMedia &&
                       scope.Restore() == ERROR_SUCCESS &&
                       DaclText(originalHandle.get()) == beforeMedia,
                L"Unavailable media prevented preparation or restoration of another volume.") &&
            passed;
    }
    return passed ? 0 : 1;
}
