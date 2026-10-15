// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerWriteScope.h"
#include "TestSupport.h"

#include <Aclapi.h>
#include <Windows.h>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sddl.h>
#include <thread>
#include <vector>
#include <winioctl.h>

using namespace launch_as;
using namespace launch_as::broker;

namespace
{
bool CanWrite(const std::filesystem::path& path)
{
    UniqueHandle file(CreateFileW(path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    return static_cast<bool>(file);
}

bool HasMediumLabel(const std::filesystem::path& path)
{
    UniqueHandle object(CreateFileW(path.c_str(),
        READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    PACL label = nullptr;
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    if (!object ||
        GetSecurityInfo(object.get(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            nullptr,
            &label,
            descriptor.address()) != ERROR_SUCCESS ||
        label == nullptr)
    {
        return false;
    }
    for (DWORD index = 0; index < label->AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(label, index, &rawAce))
        {
            return false;
        }
        const auto* ace = static_cast<const SYSTEM_MANDATORY_LABEL_ACE*>(rawAce);
        if (ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE &&
            IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinMediumLabelSid) &&
            (ace->Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) != 0)
        {
            return true;
        }
    }
    return false;
}

DWORD SetJunction(HANDLE directory, const std::filesystem::path& target)
{
    struct MountPoint
    {
        DWORD tag;
        WORD dataLength;
        WORD reserved;
        WORD substituteOffset;
        WORD substituteLength;
        WORD printOffset;
        WORD printLength;
        wchar_t names[1];
    };
    const auto substitute = L"\\??\\" + target.native();
    const auto print = target.native();
    const size_t bytes =
        offsetof(MountPoint, names) + (substitute.size() + print.size() + 2) * sizeof(wchar_t);
    std::vector<BYTE> buffer(bytes);
    auto* point = reinterpret_cast<MountPoint*>(buffer.data());
    point->tag = IO_REPARSE_TAG_MOUNT_POINT;
    point->dataLength = static_cast<WORD>(bytes - 8);
    point->substituteLength = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
    point->printOffset = point->substituteLength + sizeof(wchar_t);
    point->printLength = static_cast<WORD>(print.size() * sizeof(wchar_t));
    memcpy(point->names, substitute.c_str(), (substitute.size() + 1) * sizeof(wchar_t));
    memcpy(reinterpret_cast<BYTE*>(point->names) + point->printOffset,
        print.c_str(),
        (print.size() + 1) * sizeof(wchar_t));
    DWORD returned = 0;
    if (!DeviceIoControl(directory,
            FSCTL_SET_REPARSE_POINT,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr,
            0,
            &returned,
            nullptr))
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

struct JunctionRace
{
    BY_HANDLE_FILE_INFORMATION identity {};
    HANDLE start = nullptr;
    HANDLE finished = nullptr;
    bool afterLabel = false;
    bool observed = false;
    bool synchronized = false;
};
JunctionRace* junctionRace = nullptr;

void MutateValidatedDirectory(HANDLE object, bool labelled)
{
    auto& race = *junctionRace;
    BY_HANDLE_FILE_INFORMATION identity {};
    if (labelled != race.afterLabel || race.observed ||
        !GetFileInformationByHandle(object, &identity) ||
        identity.dwVolumeSerialNumber != race.identity.dwVolumeSerialNumber ||
        identity.nFileIndexHigh != race.identity.nFileIndexHigh ||
        identity.nFileIndexLow != race.identity.nFileIndexLow)
    {
        return;
    }
    race.observed = true;
    race.synchronized =
        SetEvent(race.start) && WaitForSingleObject(race.finished, 10'000) == WAIT_OBJECT_0;
}

bool TestJunctionRace(
    HANDLE token, const std::filesystem::path& root, PACL mediumLabel, bool afterLabel)
{
    const auto profile = root / L"profile";
    const auto work = root / L"work";
    const auto junction = work / L"junction";
    const auto target = root / L"outside";
    const auto outside = target / L"unchanged.txt";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(junction);
    std::filesystem::create_directories(target);
    std::ofstream(outside) << "outside";
    UniqueHandle outsideHandle(CreateFileW(outside.c_str(),
        MAXIMUM_ALLOWED,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    UniqueHandle mutation(CreateFileW(junction.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    UniqueHandle start(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    UniqueHandle finished(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    JunctionRace race;
    if (!outsideHandle || !mutation || !start || !finished ||
        !GetFileInformationByHandle(mutation.get(), &race.identity) ||
        SetSecurityInfo(outsideHandle.get(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            nullptr,
            mediumLabel) != ERROR_SUCCESS)
    {
        return Expect(false, L"Could not prepare the junction race.");
    }
    outsideHandle.reset();
    race.start = start.get();
    race.finished = finished.get();
    race.afterLabel = afterLabel;
    DWORD mutationError = ERROR_TIMEOUT;
    std::thread attacker(
        [&]
        {
            if (WaitForSingleObject(start.get(), 10'000) == WAIT_OBJECT_0)
            {
                mutationError = SetJunction(mutation.get(), target);
            }
            SetEvent(finished.get());
        });
    junctionRace = &race;
    SetBrokerWriteScopeObserverForTesting(MutateValidatedDirectory);
    const DWORD error = PrepareBrokerWriteScope(token, profile.native(), work.native());
    SetBrokerWriteScopeObserverForTesting(nullptr);
    SetEvent(start.get());
    attacker.join();
    junctionRace = nullptr;
    mutation.reset();
    bool passed = Expect(race.observed && race.synchronized && mutationError == ERROR_SUCCESS,
        L"Junction mutation did not run at the synchronized validation boundary.");
    if (error != ERROR_SUCCESS)
    {
        std::wcerr << L"Junction race preparation error: " << error << L"\n";
    }
    passed = Expect(error == ERROR_SUCCESS, L"Handle-anchored scope preparation failed.") && passed;
    passed = Expect(HasMediumLabel(outside), L"Junction race changed an outside Medium label.") &&
             passed;
    passed = Expect(PrepareBrokerWriteScope(token, profile.native(), junction.native()) ==
                        ERROR_ACCESS_DENIED,
                 L"A junction was accepted as a scope root.") &&
             passed;
    UniqueHandle low;
    passed = Expect(CreateBrokerLaunchToken(token, true, true, low) == ERROR_SUCCESS,
                 L"Could not create the junction race's Low token.") &&
             passed;
    if (low && ImpersonateLoggedOnUser(low.get()))
    {
        passed =
            Expect(!CanWrite(outside), L"Junction race relabelled an outside child.") && passed;
        if (!RevertToSelf())
        {
            std::terminate();
        }
    }
    else
    {
        passed = false;
    }
    // Remove the junction itself before recursively cleaning up the disposable tree.
    passed = Expect(RemoveDirectoryW(junction.c_str()), L"Could not remove the race junction.") &&
             passed;
    return passed;
}

bool TestUnreadableChild(HANDLE token, const std::filesystem::path& root, PACL mediumLabel)
{
    const auto profile = root / L"profile";
    const auto work = root / L"work";
    const auto child = work / L"unreadable";
    const auto untouched = child / L"untouched.txt";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(child);
    std::ofstream(untouched) << "retain Medium label";
    UniqueHandle file(CreateFileW(untouched.c_str(),
        MAXIMUM_ALLOWED,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!file || SetSecurityInfo(file.get(),
                     SE_FILE_OBJECT,
                     LABEL_SECURITY_INFORMATION,
                     nullptr,
                     nullptr,
                     nullptr,
                     mediumLabel) != ERROR_SUCCESS)
    {
        return Expect(false, L"Could not set the unreadable descendant's Medium label.");
    }
    file.reset();
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(D;;0x1;;;WD)(A;;FA;;;WD)S:(ML;OICI;NW;;;LW)",
            SDDL_REVISION_1,
            descriptor.address(),
            nullptr))
    {
        return Expect(false, L"Could not prepare the unreadable child's descriptor.");
    }
    PACL dacl = nullptr;
    PACL originalDacl = nullptr;
    PACL label = nullptr;
    LocalAllocation<PSECURITY_DESCRIPTOR> originalDescriptor;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    UniqueHandle directory(CreateFileW(child.c_str(),
        MAXIMUM_ALLOWED,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    if (!directory ||
        GetSecurityInfo(directory.get(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &originalDacl,
            nullptr,
            originalDescriptor.address()) != ERROR_SUCCESS ||
        !GetSecurityDescriptorDacl(descriptor.get(), &present, &dacl, &defaulted) ||
        !GetSecurityDescriptorSacl(descriptor.get(), &present, &label, &defaulted) ||
        SetSecurityInfo(directory.get(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION |
                LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            dacl,
            label) != ERROR_SUCCESS)
    {
        return Expect(false, L"Could not deny listing the already-Low child.");
    }
    directory.reset();
    UniqueHandle metadata(CreateFileW(child.c_str(),
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    UniqueHandle listing(CreateFileW(child.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    const DWORD listingError = listing ? ERROR_SUCCESS : GetLastError();
    bool passed = Expect(metadata && !listing && listingError == ERROR_ACCESS_DENIED,
        L"The unreadable child must permit metadata reads but deny listing.");
    passed =
        Expect(PrepareBrokerWriteScope(token, profile.native(), work.native()) == ERROR_SUCCESS,
            L"An unreadable child aborted scope preparation.") &&
        passed;
    passed = Expect(PrepareBrokerWriteScope(token, profile.native(), child.native()) ==
                        ERROR_ACCESS_DENIED,
                 L"An unreadable working-directory root was accepted.") &&
             passed;
    passed =
        Expect(PrepareBrokerWriteScope(token, child.native(), work.native()) == ERROR_ACCESS_DENIED,
            L"An unreadable profile root was accepted.") &&
        passed;
    // Restore listing only, so the skipped descendant's unchanged label can be inspected.
    passed = Expect(SetNamedSecurityInfoW(const_cast<LPWSTR>(child.c_str()),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        nullptr,
                        nullptr,
                        originalDacl,
                        nullptr) == ERROR_SUCCESS,
                 L"Could not restore listing for test cleanup.") &&
             passed;
    passed = Expect(HasMediumLabel(untouched), L"An unreadable subtree was relabelled.") && passed;
    return passed;
}

struct DeletedChild
{
    std::filesystem::path path;
    bool directory = false;
    bool observed = false;
    bool deleted = false;
};
DeletedChild* deletedChild = nullptr;

void DeleteEnumeratedChild(HANDLE, std::wstring_view name)
{
    auto& child = *deletedChild;
    if (!child.observed && name == child.path.filename().native())
    {
        child.observed = true;
        child.deleted = child.directory ? RemoveDirectoryW(child.path.c_str())
                                        : DeleteFileW(child.path.c_str());
    }
}

bool TestDeletedChild(HANDLE token, const std::filesystem::path& root, bool directory)
{
    const auto profile = root / L"profile";
    const auto work = root / L"work";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(work);
    DeletedChild child {work / L"vanished", directory};
    if (directory)
    {
        std::filesystem::create_directory(child.path);
    }
    else
    {
        std::ofstream(child.path) << "delete before open";
    }
    std::ofstream(work / L"survivor.txt") << "label surviving entries";
    deletedChild = &child;
    SetBrokerWriteScopeChildObserverForTesting(DeleteEnumeratedChild);
    const DWORD error = PrepareBrokerWriteScope(token, profile.native(), work.native());
    SetBrokerWriteScopeChildObserverForTesting(nullptr);
    deletedChild = nullptr;
    bool passed = Expect(
        child.observed && child.deleted, L"The enumerated child was not deleted before its open.");
    passed =
        Expect(error == ERROR_SUCCESS, L"A vanished child aborted scope preparation.") && passed;
    passed = Expect(PrepareBrokerWriteScope(token, profile.native(), child.path.native()) ==
                        ERROR_FILE_NOT_FOUND,
                 L"A missing working-directory root was accepted.") &&
             passed;
    passed = Expect(PrepareBrokerWriteScope(token, child.path.native(), work.native()) ==
                        ERROR_FILE_NOT_FOUND,
                 L"A missing profile root was accepted.") &&
             passed;
    UniqueHandle low;
    passed = Expect(CreateBrokerLaunchToken(token, true, true, low) == ERROR_SUCCESS,
                 L"Could not create the deletion regression's Low token.") &&
             passed;
    if (low && ImpersonateLoggedOnUser(low.get()))
    {
        passed = Expect(CanWrite(work / L"survivor.txt"),
                     L"A surviving sibling was not prepared for Low-token writes.") &&
                 passed;
        if (!RevertToSelf())
        {
            std::terminate();
        }
    }
    else
    {
        passed = false;
    }
    return passed;
}

bool TestDepthLimit(HANDLE token, const std::filesystem::path& root, PACL mediumLabel)
{
    const auto profile = root / L"profile";
    const auto work = root / L"work";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(work);
    // The root stays an ordinary path; descendants use extended paths only for fixture setup.
    auto deepest = std::filesystem::path(L"\\\\?\\" + work.native());
    for (DWORD depth = 0; depth < 129; ++depth)
    {
        deepest /= L"d";
        std::filesystem::create_directory(deepest);
    }
    const auto untouched = deepest / L"untouched.txt";
    std::ofstream(untouched) << "retain Medium label";
    UniqueHandle file(CreateFileW(untouched.c_str(),
        MAXIMUM_ALLOWED,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!file || SetSecurityInfo(file.get(),
                     SE_FILE_OBJECT,
                     LABEL_SECURITY_INFORMATION,
                     nullptr,
                     nullptr,
                     nullptr,
                     mediumLabel) != ERROR_SUCCESS)
    {
        return Expect(false, L"Could not prepare the depth-limit fixture.");
    }
    file.reset();
    bool passed = Expect(
        PrepareBrokerWriteScope(token, profile.native(), work.native()) == ERROR_NOT_ENOUGH_QUOTA,
        L"An excessive directory depth did not fail with a controlled error.");
    passed = Expect(HasMediumLabel(untouched), L"Preparation continued beyond its depth limit.") &&
             passed;
    std::filesystem::remove(untouched);
    std::filesystem::remove(deepest);
    passed =
        Expect(PrepareBrokerWriteScope(token, profile.native(), work.native()) == ERROR_SUCCESS,
            L"The supported depth boundary failed after an excessive-depth rejection.") &&
        passed;
    std::filesystem::remove_all(std::filesystem::path(L"\\\\?\\" + work.native()));
    return passed;
}

bool deadlineObserverRan = false;

void ExpirePreparationDeadline(HANDLE, bool labelled)
{
    if (labelled && !deadlineObserverRan)
    {
        deadlineObserverRan = true;
        Sleep(50);
    }
}

bool TestWorkLimits(HANDLE token, const std::filesystem::path& root, PACL mediumLabel)
{
    const auto profile = root / L"profile";
    const auto work = root / L"work";
    const auto untouched = work / L"untouched.txt";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(work);
    std::ofstream(untouched) << "retain Medium label";
    UniqueHandle file(CreateFileW(untouched.c_str(),
        MAXIMUM_ALLOWED,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!file || SetSecurityInfo(file.get(),
                     SE_FILE_OBJECT,
                     LABEL_SECURITY_INFORMATION,
                     nullptr,
                     nullptr,
                     nullptr,
                     mediumLabel) != ERROR_SUCCESS)
    {
        return Expect(false, L"Could not prepare the work-limit fixture.");
    }
    file.reset();
    deadlineObserverRan = false;
    SetBrokerWriteScopeObserverForTesting(ExpirePreparationDeadline);
    const DWORD timeoutError =
        PrepareBrokerWriteScopeWithLimitsForTesting(token, profile.native(), work.native(), 3, 25);
    SetBrokerWriteScopeObserverForTesting(nullptr);
    bool passed = Expect(deadlineObserverRan && timeoutError == ERROR_TIMEOUT,
        L"Preparation did not abort when its deadline expired during traversal.");
    passed =
        Expect(HasMediumLabel(untouched), L"Preparation continued after its deadline.") && passed;
    passed =
        Expect(PrepareBrokerWriteScopeWithLimitsForTesting(
                   token, profile.native(), work.native(), 2, 30'000) == ERROR_NOT_ENOUGH_QUOTA,
            L"The object limit was not shared across the profile and work trees.") &&
        passed;
    passed = Expect(HasMediumLabel(untouched), L"Preparation continued after its object limit.") &&
             passed;
    passed = Expect(PrepareBrokerWriteScopeWithLimitsForTesting(
                        token, profile.native(), work.native(), 3, 30'000) == ERROR_SUCCESS,
                 L"Preparation failed at the exact object limit after previous rejections.") &&
             passed;
    UniqueHandle low;
    passed = Expect(CreateBrokerLaunchToken(token, false, true, low) == ERROR_SUCCESS,
                 L"Could not create the work-limit fixture's Low token.") &&
             passed;
    if (low && ImpersonateLoggedOnUser(low.get()))
    {
        passed =
            Expect(CanWrite(untouched), L"A subsequent preparation did not label the child.") &&
            passed;
        if (!RevertToSelf())
        {
            std::terminate();
        }
    }
    else
    {
        passed = false;
    }
    return passed;
}
} // namespace

int wmain()
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_PRIVILEGES,
            &rawToken))
    {
        return 1;
    }
    UniqueHandle token(rawToken);
    std::vector<BYTE> sourceIntegrity;
    if (!Expect(QueryTokenInformation(token.get(), TokenIntegrityLevel, sourceIntegrity) ==
                        ERROR_SUCCESS &&
                    IsWellKnownSid(
                        reinterpret_cast<TOKEN_MANDATORY_LABEL*>(sourceIntegrity.data())->Label.Sid,
                        WinMediumLabelSid),
            L"Run this test from a Medium-integrity executable and token."))
    {
        return 1;
    }
    for (const bool restrictAccess : {false, true})
    {
        for (const bool lowIntegrity : {false, true})
        {
            UniqueHandle launchToken;
            std::vector<BYTE> integrity;
            std::vector<BYTE> restricted;
            if (!Expect(
                    CreateBrokerLaunchToken(
                        token.get(), restrictAccess, lowIntegrity, launchToken) == ERROR_SUCCESS,
                    L"Independent launch token creation failed.") ||
                !Expect(
                    QueryTokenInformation(launchToken.get(), TokenIntegrityLevel, integrity) ==
                            ERROR_SUCCESS &&
                        IsWellKnownSid(
                            reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrity.data())->Label.Sid,
                            lowIntegrity ? WinLowLabelSid : WinMediumLabelSid),
                    L"Launch token integrity did not match the requested flag.") ||
                !Expect(QueryTokenInformation(launchToken.get(), TokenRestrictedSids, restricted) ==
                                ERROR_SUCCESS &&
                            (reinterpret_cast<TOKEN_GROUPS*>(restricted.data())->GroupCount != 0) ==
                                restrictAccess,
                    L"Launch token restricting SIDs did not match the requested flag."))
            {
                return 1;
            }
        }
    }
    if (!Expect(QueryTokenInformation(token.get(), TokenIntegrityLevel, sourceIntegrity) ==
                        ERROR_SUCCESS &&
                    IsWellKnownSid(
                        reinterpret_cast<TOKEN_MANDATORY_LABEL*>(sourceIntegrity.data())->Label.Sid,
                        WinMediumLabelSid),
            L"Creating a Low token changed the source token integrity."))
    {
        return 1;
    }
    std::wstring suffix;
    if (!CreateGuidString(suffix))
    {
        return 1;
    }
    const auto root = std::filesystem::temp_directory_path() / (L"launch-as-scope-" + suffix);
    const auto profile = root / L"profile";
    const auto work = root / L"work";
    const auto outside = root / L"outside.txt";
    if (!Expect(PrepareBrokerWriteScope(token.get(), work.root_path().native(), work.native()) ==
                    ERROR_BAD_PATHNAME,
            L"A volume root was accepted as a write scope."))
    {
        return 1;
    }
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(work / L"existing");
    std::ofstream(work / L"existing" / L"old.txt") << "before";
    const auto unicodeFile = work / L"existing" / L"\u00e4_\u65e5\u672c.txt";
    std::ofstream(unicodeFile) << "before";
    std::ofstream(outside) << "outside";
    LocalAllocation<PSECURITY_DESCRIPTOR> mediumDescriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"S:(ML;;NW;;;ME)", SDDL_REVISION_1, mediumDescriptor.address(), nullptr))
    {
        return 1;
    }
    PACL mediumLabel = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    UniqueHandle outsideHandle(CreateFileW(outside.c_str(),
        MAXIMUM_ALLOWED,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!outsideHandle ||
        !GetSecurityDescriptorSacl(mediumDescriptor.get(), &present, &mediumLabel, &defaulted) ||
        SetSecurityInfo(outsideHandle.get(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            nullptr,
            mediumLabel) != ERROR_SUCCESS)
    {
        return 1;
    }
    outsideHandle.reset();
    const auto groupReadable = root / L"group-readable.txt";
    std::ofstream(groupReadable) << "read through Users only";
    std::array<BYTE, SECURITY_MAX_SID_SIZE> users {};
    DWORD usersBytes = static_cast<DWORD>(users.size());
    if (!CreateWellKnownSid(WinBuiltinUsersSid, nullptr, users.data(), &usersBytes))
    {
        return 1;
    }
    EXPLICIT_ACCESSW readAccess {};
    readAccess.grfAccessPermissions = GENERIC_READ;
    readAccess.grfAccessMode = GRANT_ACCESS;
    readAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    readAccess.Trustee.ptstrName = reinterpret_cast<LPWSTR>(users.data());
    LocalAllocation<PACL> readDacl;
    UniqueHandle groupFile(CreateFileW(groupReadable.c_str(),
        MAXIMUM_ALLOWED,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!groupFile ||
        SetEntriesInAclW(1, &readAccess, nullptr, readDacl.address()) != ERROR_SUCCESS ||
        SetSecurityInfo(groupFile.get(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            readDacl.get(),
            nullptr) != ERROR_SUCCESS)
    {
        return 1;
    }
    groupFile.reset();
    const auto hardLink = work / L"linked-outside.txt";
    if (!Expect(CreateHardLinkW(hardLink.c_str(), outside.c_str(), nullptr),
            L"Could not prepare the hard-link regression."))
    {
        return 1;
    }
    const DWORD preparationError =
        PrepareBrokerWriteScope(token.get(), profile.native(), work.native());
    if (preparationError != ERROR_SUCCESS)
    {
        std::wcerr << L"Scope preparation error: " << preparationError << L"\n";
    }
    bool passed = Expect(preparationError == ERROR_SUCCESS, L"Scope preparation failed.");
    passed = Expect(PrepareBrokerWriteScope(token.get(),
                        (root / L"PROFILE").native(),
                        (root / L"WORK").native()) == ERROR_SUCCESS,
                 L"Ordinary case-insensitive scope paths were rejected.") &&
             passed;
    UniqueHandle low;
    passed = Expect(CreateBrokerLaunchToken(token.get(), true, true, low) == ERROR_SUCCESS,
                 L"Low write-restricted token creation failed.") &&
             passed;
    std::filesystem::create_directory(work / L"inherited");
    if (low)
    {
        std::vector<BYTE> integrity;
        passed =
            Expect(
                QueryTokenInformation(low.get(), TokenIntegrityLevel, integrity) == ERROR_SUCCESS &&
                    *GetSidSubAuthority(
                        reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrity.data())->Label.Sid, 0) ==
                        SECURITY_MANDATORY_LOW_RID,
                L"Token integrity was not Low.") &&
            passed;
        std::vector<BYTE> restricted;
        passed = Expect(QueryTokenInformation(low.get(), TokenRestrictedSids, restricted) ==
                            ERROR_SUCCESS,
                     L"Could not query restricting SIDs.") &&
                 passed;
        std::array<BYTE, SECURITY_MAX_SID_SIZE> everyone {};
        DWORD bytes = static_cast<DWORD>(everyone.size());
        CreateWellKnownSid(WinWorldSid, nullptr, everyone.data(), &bytes);
        bool foundEveryone = false;
        const auto* groups = reinterpret_cast<TOKEN_GROUPS*>(restricted.data());
        for (DWORD index = 0; index < groups->GroupCount; ++index)
        {
            foundEveryone = foundEveryone || EqualSid(groups->Groups[index].Sid, everyone.data());
        }
        passed = Expect(foundEveryone, L"Everyone is missing from restricting SIDs.") && passed;
        if (Expect(ImpersonateLoggedOnUser(low.get()), L"Could not impersonate Low token."))
        {
            passed = Expect(CanWrite(profile / L"new.txt"), L"Profile write was denied.") && passed;
            passed = Expect(CanWrite(work / L"new.txt"), L"Working-directory write was denied.") &&
                     passed;
            passed = Expect(CanWrite(work / L"existing" / L"old.txt"),
                         L"Existing descendant write was denied.") &&
                     passed;
            passed =
                Expect(CanWrite(unicodeFile), L"Unicode descendant write was denied.") && passed;
            passed = Expect(!CanWrite(outside), L"Write outside the scope succeeded.") && passed;
            passed = Expect(CanWrite(work / L"inherited" / L"new.txt"),
                         L"New directory did not inherit the Low label.") &&
                     passed;
            passed =
                Expect(!CanWrite(hardLink), L"Hard-linked outside file was relabelled.") && passed;
            UniqueHandle readable(CreateFileW(outside.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr));
            passed = Expect(static_cast<bool>(readable), L"Ordinary read was denied.") && passed;
            UniqueHandle groupRead(CreateFileW(groupReadable.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr));
            passed = Expect(static_cast<bool>(groupRead),
                         L"Restricting SIDs were incorrectly applied to reads.") &&
                     passed;
            if (!RevertToSelf())
            {
                std::terminate();
            }
        }
        else
        {
            passed = false;
        }
    }
    passed =
        TestJunctionRace(token.get(), root / L"race-before-label", mediumLabel, false) && passed;
    passed = TestJunctionRace(token.get(), root / L"race-before-enumeration", mediumLabel, true) &&
             passed;
    passed = TestUnreadableChild(token.get(), root / L"unreadable-child", mediumLabel) && passed;
    passed = TestDeletedChild(token.get(), root / L"deleted-file", false) && passed;
    passed = TestDeletedChild(token.get(), root / L"deleted-directory", true) && passed;
    passed = TestDepthLimit(token.get(), root / L"depth-limit", mediumLabel) && passed;
    passed = TestWorkLimits(token.get(), root / L"work-limits", mediumLabel) && passed;
    std::filesystem::remove_all(root);
    return passed ? 0 : 1;
}
