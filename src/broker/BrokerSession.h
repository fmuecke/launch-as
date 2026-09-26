// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "BrokerProcessLauncher.h"
#include "InteractiveDesktopLeaseClient.h"

namespace launch_as::broker
{

struct BrokerSession final
{
    BrokerSession() = default;
    ~BrokerSession()
    {
        // Even on an early return, keep the lease until the complete Job tree is gone.
        child.TerminateAndWaitForExitConfirmed();
    }

    BrokerSession(const BrokerSession&) = delete;
    BrokerSession& operator=(const BrokerSession&) = delete;

    BrokerChildProcess child;
    InteractiveDesktopLeaseConnection desktopLease;
};

} // namespace launch_as::broker
