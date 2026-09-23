// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerCallerIdentity.h"
#include "BrokerProcessLauncher.h"
#include "BrokerProtocol.h"
#include "BrokerRegistration.h"
#include "InteractiveDesktopLeaseClient.h"

#include <Windows.h>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

class BrokerApplication final
{
  public:
    BrokerApplication(std::wstring_view enrollmentDirectory, std::vector<BYTE> authorizedCallerSid);

    BrokerApplication(const BrokerApplication&) = delete;
    BrokerApplication& operator=(const BrokerApplication&) = delete;

    [[nodiscard]] const std::vector<BYTE>& authorizedCallerSid() const noexcept;
    [[nodiscard]] DWORD Configure(const BrokerRequest& request, const BrokerCallerIdentity& caller,
        std::vector<std::wstring>& accounts);
    [[nodiscard]] DWORD Launch(const BrokerRequest& request, const BrokerCallerIdentity& caller,
        BrokerChildProcess& child);
    [[nodiscard]] DWORD FinishSession(const BrokerRequest& request, bool processTreeExited);

  private:
    struct AccountNameLess
    {
        [[nodiscard]] bool operator()(
            const std::wstring& left, const std::wstring& right) const noexcept;
    };

    [[nodiscard]] bool TryReserveSession(std::wstring_view accountName);
    void ReleaseSession(std::wstring_view accountName);
    [[nodiscard]] bool HasActiveSession(std::wstring_view accountName);

    std::vector<BYTE> authorizedCallerSid_;
    RegistrationService registration_;
    std::mutex launchMutex_;
    std::mutex sessionMutex_;
    std::mutex leaseMutex_;
    std::map<std::wstring, std::size_t, AccountNameLess> sessionsByAccount_;
    std::map<std::wstring, InteractiveDesktopLeaseConnection> interactiveLeasesByRequest_;
    std::size_t sessionCount_ = 0;
};

} // namespace launch_as::broker
