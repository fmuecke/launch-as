// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "AppContainerOptions.h"
#include "Win32Support.h"

namespace launch_as
{

class AppContainerIdentity final
{
  public:
    AppContainerIdentity() = default;
    AppContainerIdentity(const AppContainerIdentity&) = delete;
    AppContainerIdentity& operator=(const AppContainerIdentity&) = delete;

    // The account profile must be loaded, and the calling thread must be running as that account.
    [[nodiscard]] DWORD Initialize(
        HANDLE token, const std::wstring& directory, const AppContainerOptions& options);
    [[nodiscard]] SECURITY_CAPABILITIES* security() noexcept { return &security_; }
    [[nodiscard]] const std::wstring& name() const noexcept { return name_; }
    [[nodiscard]] const std::wstring& failureContext() const noexcept { return failureContext_; }

  private:
    std::wstring name_;
    std::wstring failureContext_;
    std::vector<BYTE> sid_;
    std::vector<std::vector<BYTE>> capabilitySids_;
    std::vector<SID_AND_ATTRIBUTES> capabilities_;
    SECURITY_CAPABILITIES security_ {};
};

} // namespace launch_as
