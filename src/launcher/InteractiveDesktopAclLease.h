// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <vector>

namespace launch_as
{

struct InteractiveObjectAclLeaseStatus
{
    DWORD openError = ERROR_INVALID_DATA;
    DWORD readError = ERROR_INVALID_DATA;
    DWORD addError = ERROR_INVALID_DATA;
    DWORD verifyAddError = ERROR_INVALID_DATA;
    DWORD removeError = ERROR_INVALID_DATA;
    DWORD verifyRemoveError = ERROR_INVALID_DATA;
    bool added = false;
    bool removed = false;
    bool restored = false;
};

class InteractiveDesktopAclLease final
{
  public:
    InteractiveDesktopAclLease() = default;
    ~InteractiveDesktopAclLease();

    InteractiveDesktopAclLease(const InteractiveDesktopAclLease&) = delete;
    InteractiveDesktopAclLease& operator=(const InteractiveDesktopAclLease&) = delete;

    [[nodiscard]] DWORD Acquire(PSID childLogonSid);
    [[nodiscard]] DWORD Release();
    [[nodiscard]] const InteractiveObjectAclLeaseStatus& windowStationStatus() const noexcept;
    [[nodiscard]] const InteractiveObjectAclLeaseStatus& desktopStatus() const noexcept;

  private:
    using AceFingerprint = std::vector<BYTE>;

    struct ObjectLease
    {
        HANDLE object = nullptr;
        ACCESS_MASK accessMask = 0;
        bool leased = false;
        InteractiveObjectAclLeaseStatus status;
    };

    [[nodiscard]] DWORD Apply(ObjectLease& lease);
    [[nodiscard]] DWORD Remove(ObjectLease& lease);
    void CloseHandles() noexcept;

    HWINSTA windowStation_ = nullptr;
    HDESK desktop_ = nullptr;
    std::vector<BYTE> childLogonSid_;
    ObjectLease windowStationLease_;
    ObjectLease desktopLease_;
};

} // namespace launch_as
