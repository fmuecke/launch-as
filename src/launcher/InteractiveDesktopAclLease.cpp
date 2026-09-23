// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "InteractiveDesktopAclLease.h"

#include <Aclapi.h>
#include <Sddl.h>
#include <algorithm>
#include <string>

namespace launch_as
{
namespace
{

class DesktopAclMutationLock final
{
  public:
    ~DesktopAclMutationLock()
    {
        if (pipe_ != nullptr)
        {
            CloseHandle(pipe_);
        }
    }

    [[nodiscard]] DWORD Acquire()
    {
        DWORD sessionId = MAXDWORD;
        if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId))
        {
            return GetLastError();
        }
        // The caller can create lease pipes even when its logon lacks access to
        // the session's kernel-object namespace. A first pipe instance is exclusive.
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr))
        {
            return GetLastError();
        }
        SECURITY_ATTRIBUTES attributes {};
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        const std::wstring name = L"\\\\.\\pipe\\launch-as-desktop-acl-lock-" +
                                  std::to_wstring(sessionId) +
                                  L"-4a65a62e-3770-4b3f-9d80-76e06f40bd2b";
        const ULONGLONG deadline = GetTickCount64() + 30'000;
        for (;;)
        {
            HANDLE created = CreateNamedPipeW(name.c_str(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                &attributes);
            if (created != INVALID_HANDLE_VALUE)
            {
                pipe_ = created;
                LocalFree(descriptor);
                return ERROR_SUCCESS;
            }
            const DWORD createError = GetLastError();
            if (createError != ERROR_ACCESS_DENIED || GetTickCount64() >= deadline)
            {
                LocalFree(descriptor);
                return createError;
            }
            Sleep(10);
        }
    }

  private:
    HANDLE pipe_ = nullptr;
};

[[nodiscard]] bool IsLogonSid(PSID sid) noexcept
{
    if (sid == nullptr || !IsValidSid(sid))
    {
        return false;
    }
    const auto* value = static_cast<const SID*>(sid);
    constexpr SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    return value->SubAuthorityCount == 3 &&
           std::equal(std::begin(value->IdentifierAuthority.Value),
               std::end(value->IdentifierAuthority.Value),
               std::begin(ntAuthority.Value)) &&
           *GetSidSubAuthority(sid, 0) == SECURITY_LOGON_IDS_RID;
}

[[nodiscard]] DWORD ReadSecurityDescriptor(HANDLE object, std::vector<BYTE>& descriptor)
{
    descriptor.clear();
    DWORD required = 0;
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION;
    GetUserObjectSecurity(object, &information, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        return sizeError == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR : sizeError;
    }
    descriptor.resize(required);
    if (!GetUserObjectSecurity(object, &information, descriptor.data(), required, &required))
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD GetDacl(std::vector<BYTE>& descriptor, PACL& dacl)
{
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor.data(), &present, &dacl, &defaulted))
    {
        return GetLastError();
    }
    return present && dacl != nullptr ? ERROR_SUCCESS : ERROR_INVALID_SECURITY_DESCR;
}

[[nodiscard]] DWORD WriteDacl(HANDLE object, PACL dacl)
{
    SECURITY_DESCRIPTOR descriptor {};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION))
    {
        return GetLastError();
    }
    if (!SetSecurityDescriptorDacl(&descriptor, TRUE, dacl, FALSE))
    {
        return GetLastError();
    }
    SECURITY_INFORMATION information = DACL_SECURITY_INFORMATION;
    if (!SetUserObjectSecurity(object, &information, &descriptor))
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD FingerprintDacl(PACL dacl, std::vector<std::vector<BYTE>>& fingerprints)
{
    fingerprints.clear();
    ACL_SIZE_INFORMATION size {};
    if (!GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation))
    {
        return GetLastError();
    }
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(dacl, index, &rawAce))
        {
            return GetLastError();
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        const auto* bytes = static_cast<const BYTE*>(rawAce);
        fingerprints.emplace_back(bytes, bytes + header->AceSize);
    }
    std::sort(fingerprints.begin(), fingerprints.end());
    return ERROR_SUCCESS;
}

[[nodiscard]] bool IsExactLeaseAce(const void* rawAce, PSID sid, ACCESS_MASK accessMask) noexcept
{
    const auto* header = static_cast<const ACE_HEADER*>(rawAce);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0)
    {
        return false;
    }
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(rawAce);
    auto* aceSid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
    return ace->Mask == accessMask && EqualSid(aceSid, sid) != FALSE;
}

[[nodiscard]] DWORD CountLeaseAces(PACL dacl, PSID sid, ACCESS_MASK accessMask, DWORD& count)
{
    count = 0;
    ACL_SIZE_INFORMATION size {};
    if (!GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation))
    {
        return GetLastError();
    }
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(dacl, index, &rawAce))
        {
            return GetLastError();
        }
        if (IsExactLeaseAce(rawAce, sid, accessMask))
        {
            ++count;
        }
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD BuildDaclWithoutLease(
    PACL current, PSID sid, ACCESS_MASK accessMask, std::vector<BYTE>& storage)
{
    ACL_SIZE_INFORMATION size {};
    if (!GetAclInformation(current, &size, sizeof(size), AclSizeInformation))
    {
        return GetLastError();
    }
    DWORD leaseCount = 0;
    DWORD leaseBytes = 0;
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(current, index, &rawAce))
        {
            return GetLastError();
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        if (IsExactLeaseAce(rawAce, sid, accessMask))
        {
            ++leaseCount;
            leaseBytes += header->AceSize;
        }
    }
    if (leaseCount != 1 || current->AclSize <= leaseBytes)
    {
        return ERROR_INVALID_DATA;
    }

    storage.assign(current->AclSize - leaseBytes, BYTE {});
    auto* replacement = reinterpret_cast<PACL>(storage.data());
    if (!InitializeAcl(replacement, static_cast<DWORD>(storage.size()), current->AclRevision))
    {
        return GetLastError();
    }
    for (DWORD index = 0; index < size.AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!GetAce(current, index, &rawAce))
        {
            return GetLastError();
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        if (!IsExactLeaseAce(rawAce, sid, accessMask) &&
            !AddAce(replacement, current->AclRevision, MAXDWORD, rawAce, header->AceSize))
        {
            return GetLastError();
        }
    }
    return ERROR_SUCCESS;
}

} // namespace

InteractiveDesktopAclLease::~InteractiveDesktopAclLease()
{
    static_cast<void>(Release());
    CloseHandles();
}

DWORD InteractiveDesktopAclLease::Acquire(PSID childLogonSid)
{
    if (!IsLogonSid(childLogonSid))
    {
        return ERROR_INVALID_SID;
    }
    if (windowStationLease_.leased || desktopLease_.leased)
    {
        return ERROR_BUSY;
    }

    CloseHandles();
    windowStationLease_ = {};
    desktopLease_ = {};
    const DWORD sidBytes = GetLengthSid(childLogonSid);
    childLogonSid_.resize(sidBytes);
    if (!CopySid(sidBytes, childLogonSid_.data(), childLogonSid))
    {
        return GetLastError();
    }

    windowStation_ = OpenWindowStationW(L"WinSta0", FALSE, READ_CONTROL | WRITE_DAC);
    windowStationLease_.status.openError =
        windowStation_ != nullptr ? ERROR_SUCCESS : GetLastError();
    if (windowStation_ == nullptr)
    {
        return windowStationLease_.status.openError;
    }
    desktop_ = OpenDesktopW(L"Default", 0, FALSE, READ_CONTROL | WRITE_DAC);
    desktopLease_.status.openError = desktop_ != nullptr ? ERROR_SUCCESS : GetLastError();
    if (desktop_ == nullptr)
    {
        const DWORD error = desktopLease_.status.openError;
        CloseHandles();
        return error;
    }

    windowStationLease_.object = windowStation_;
    windowStationLease_.accessMask = WINSTA_ALL_ACCESS | READ_CONTROL;
    desktopLease_.object = desktop_;
    desktopLease_.accessMask = DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW | DESKTOP_ENUMERATE |
                               DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK |
                               DESKTOP_JOURNALRECORD | DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP |
                               DESKTOP_WRITEOBJECTS | READ_CONTROL;

    const DWORD windowStationError = Apply(windowStationLease_);
    if (windowStationError != ERROR_SUCCESS)
    {
        const DWORD rollbackError = Remove(windowStationLease_);
        if (!windowStationLease_.leased)
        {
            CloseHandles();
        }
        return rollbackError == ERROR_SUCCESS ? windowStationError : rollbackError;
    }
    const DWORD desktopError = Apply(desktopLease_);
    if (desktopError != ERROR_SUCCESS)
    {
        const DWORD desktopRollbackError = Remove(desktopLease_);
        const DWORD windowStationRollbackError = Remove(windowStationLease_);
        if (!desktopLease_.leased && !windowStationLease_.leased)
        {
            CloseHandles();
        }
        if (desktopRollbackError != ERROR_SUCCESS)
        {
            return desktopRollbackError;
        }
        return windowStationRollbackError == ERROR_SUCCESS ? desktopError
                                                           : windowStationRollbackError;
    }
    return ERROR_SUCCESS;
}

DWORD InteractiveDesktopAclLease::Apply(ObjectLease& lease)
{
    DesktopAclMutationLock lock;
    const DWORD lockError = lock.Acquire();
    if (lockError != ERROR_SUCCESS)
    {
        return lockError;
    }
    std::vector<BYTE> originalDescriptor;
    lease.status.readError = ReadSecurityDescriptor(lease.object, originalDescriptor);
    PACL originalDacl = nullptr;
    if (lease.status.readError == ERROR_SUCCESS)
    {
        lease.status.readError = GetDacl(originalDescriptor, originalDacl);
    }
    DWORD existingCount = 0;
    if (lease.status.readError == ERROR_SUCCESS)
    {
        lease.status.readError =
            CountLeaseAces(originalDacl, childLogonSid_.data(), lease.accessMask, existingCount);
    }
    if (lease.status.readError != ERROR_SUCCESS)
    {
        return lease.status.readError;
    }
    if (existingCount != 0)
    {
        lease.status.addError = ERROR_ALREADY_EXISTS;
        return lease.status.addError;
    }

    EXPLICIT_ACCESSW access {};
    access.grfAccessPermissions = lease.accessMask;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(childLogonSid_.data());
    PACL updatedDacl = nullptr;
    lease.status.addError = SetEntriesInAclW(1, &access, originalDacl, &updatedDacl);
    if (lease.status.addError != ERROR_SUCCESS)
    {
        return lease.status.addError;
    }
    lease.status.addError = WriteDacl(lease.object, updatedDacl);
    LocalFree(updatedDacl);
    if (lease.status.addError != ERROR_SUCCESS)
    {
        return lease.status.addError;
    }
    lease.leased = true;

    std::vector<BYTE> leasedDescriptor;
    lease.status.verifyAddError = ReadSecurityDescriptor(lease.object, leasedDescriptor);
    PACL leasedDacl = nullptr;
    DWORD leaseCount = 0;
    if (lease.status.verifyAddError == ERROR_SUCCESS)
    {
        lease.status.verifyAddError = GetDacl(leasedDescriptor, leasedDacl);
    }
    if (lease.status.verifyAddError == ERROR_SUCCESS)
    {
        lease.status.verifyAddError =
            CountLeaseAces(leasedDacl, childLogonSid_.data(), lease.accessMask, leaseCount);
    }
    lease.status.added = lease.status.verifyAddError == ERROR_SUCCESS && leaseCount == 1;
    return lease.status.added                             ? ERROR_SUCCESS
           : lease.status.verifyAddError == ERROR_SUCCESS ? ERROR_INVALID_DATA
                                                          : lease.status.verifyAddError;
}

DWORD InteractiveDesktopAclLease::Release()
{
    DWORD result = ERROR_SUCCESS;
    const DWORD desktopError = Remove(desktopLease_);
    if (desktopError != ERROR_SUCCESS)
    {
        result = desktopError;
    }
    const DWORD windowStationError = Remove(windowStationLease_);
    if (result == ERROR_SUCCESS && windowStationError != ERROR_SUCCESS)
    {
        result = windowStationError;
    }
    if (!desktopLease_.leased && !windowStationLease_.leased)
    {
        CloseHandles();
        childLogonSid_.clear();
    }
    return result;
}

DWORD InteractiveDesktopAclLease::Remove(ObjectLease& lease)
{
    if (!lease.leased)
    {
        return ERROR_SUCCESS;
    }
    DesktopAclMutationLock lock;
    const DWORD lockError = lock.Acquire();
    if (lockError != ERROR_SUCCESS)
    {
        return lockError;
    }
    std::vector<BYTE> descriptor;
    lease.status.removeError = ReadSecurityDescriptor(lease.object, descriptor);
    PACL dacl = nullptr;
    if (lease.status.removeError == ERROR_SUCCESS)
    {
        lease.status.removeError = GetDacl(descriptor, dacl);
    }
    std::vector<BYTE> withoutLease;
    if (lease.status.removeError == ERROR_SUCCESS)
    {
        lease.status.removeError =
            BuildDaclWithoutLease(dacl, childLogonSid_.data(), lease.accessMask, withoutLease);
    }
    std::vector<AceFingerprint> expectedFingerprint;
    if (lease.status.removeError == ERROR_SUCCESS)
    {
        lease.status.removeError =
            FingerprintDacl(reinterpret_cast<PACL>(withoutLease.data()), expectedFingerprint);
    }
    if (lease.status.removeError == ERROR_SUCCESS)
    {
        lease.status.removeError =
            WriteDacl(lease.object, reinterpret_cast<PACL>(withoutLease.data()));
    }
    if (lease.status.removeError != ERROR_SUCCESS)
    {
        return lease.status.removeError;
    }
    lease.leased = false;

    std::vector<BYTE> finalDescriptor;
    lease.status.verifyRemoveError = ReadSecurityDescriptor(lease.object, finalDescriptor);
    PACL finalDacl = nullptr;
    DWORD finalLeaseCount = 0;
    std::vector<AceFingerprint> finalFingerprint;
    if (lease.status.verifyRemoveError == ERROR_SUCCESS)
    {
        lease.status.verifyRemoveError = GetDacl(finalDescriptor, finalDacl);
    }
    if (lease.status.verifyRemoveError == ERROR_SUCCESS)
    {
        lease.status.verifyRemoveError =
            CountLeaseAces(finalDacl, childLogonSid_.data(), lease.accessMask, finalLeaseCount);
    }
    if (lease.status.verifyRemoveError == ERROR_SUCCESS)
    {
        lease.status.verifyRemoveError = FingerprintDacl(finalDacl, finalFingerprint);
    }
    lease.status.removed = lease.status.verifyRemoveError == ERROR_SUCCESS && finalLeaseCount == 0;
    lease.status.restored = lease.status.removed && expectedFingerprint == finalFingerprint;
    return lease.status.restored                             ? ERROR_SUCCESS
           : lease.status.verifyRemoveError == ERROR_SUCCESS ? ERROR_INVALID_DATA
                                                             : lease.status.verifyRemoveError;
}

void InteractiveDesktopAclLease::CloseHandles() noexcept
{
    if (desktop_ != nullptr)
    {
        CloseDesktop(desktop_);
        desktop_ = nullptr;
    }
    if (windowStation_ != nullptr)
    {
        CloseWindowStation(windowStation_);
        windowStation_ = nullptr;
    }
    desktopLease_.object = nullptr;
    windowStationLease_.object = nullptr;
}

const InteractiveObjectAclLeaseStatus& InteractiveDesktopAclLease::windowStationStatus()
    const noexcept
{
    return windowStationLease_.status;
}

const InteractiveObjectAclLeaseStatus& InteractiveDesktopAclLease::desktopStatus() const noexcept
{
    return desktopLease_.status;
}

} // namespace launch_as
