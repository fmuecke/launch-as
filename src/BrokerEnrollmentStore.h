// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include <Windows.h>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{

struct EnrollmentRecord final
{
    std::vector<BYTE> accountSid;
    bool brokerManaged = false;
};

class EnrollmentStore final
{
  public:
    explicit EnrollmentStore(std::wstring_view directory);

    [[nodiscard]] DWORD Store(std::wstring_view accountName, const std::vector<BYTE>& accountSid,
        bool brokerManaged = false) const;
    [[nodiscard]] DWORD Load(std::wstring_view accountName, EnrollmentRecord& record) const;
    [[nodiscard]] DWORD Load(std::wstring_view accountName, std::vector<BYTE>& accountSid) const;
    [[nodiscard]] DWORD Remove(std::wstring_view accountName) const;
    [[nodiscard]] DWORD List(std::vector<std::wstring>& accountNames) const;

  private:
    [[nodiscard]] std::wstring RecordPath(std::wstring_view accountName) const;
    [[nodiscard]] std::wstring MachineKeyPath() const;

    std::wstring directory_;
};

} // namespace launch_as::broker
