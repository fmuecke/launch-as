// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "AppContainerIdentity.h"

#include <Windows.h>
#include <string>
#include <vector>

namespace launch_as
{

// Prepared as the managed account at Medium integrity, before starting the confined child.
// Filesystem preparation belongs to the broker. No firewall configuration is changed.
class AppContainer final
{
  public:
    AppContainer() = default;
    AppContainer(const AppContainer&) = delete;
    AppContainer& operator=(const AppContainer&) = delete;

    [[nodiscard]] DWORD Initialize(const AppContainerOptions& options);
    [[nodiscard]] SECURITY_CAPABILITIES* security() noexcept { return identity_.security(); }
    [[nodiscard]] const std::wstring& name() const noexcept { return identity_.name(); }
    [[nodiscard]] const std::wstring& failureContext() const noexcept { return failureContext_; }

  private:
    AppContainerIdentity identity_;
    std::wstring failureContext_;
};

} // namespace launch_as
