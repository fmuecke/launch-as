// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#pragma once

#include "Win32Support.h"

#include <functional>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace launch_as::broker
{
#ifdef LAUNCH_AS_TESTING
void SetBrokerReadScopeVolumeProbeForTesting(
    DWORD (*probe)(std::wstring_view, UINT& driveType)) noexcept;
#endif

// One account-wide scope, serialized by BrokerApplication. Working directories accumulate
// until its last session closes. Filesystem changes touch only folder DACLs; native Windows
// namespace ancestors receive temporary traversal grants. Denies are non-inheritable;
// launch tokens must check traversal. File-ID opens and loose ancestor files are not restricted.
// Retained no-delete-sharing handles prevent replacement races. They also block rename/deletion
// of visited directories for all users until final restoration releases the pins.
class BrokerReadScope final
{
  public:
    using Observer =
        std::function<void(std::wstring_view action, std::wstring_view path, DWORD error)>;
    ~BrokerReadScope();
    void SetObserver(Observer observer);
    [[nodiscard]] DWORD Ensure(HANDLE token, std::wstring_view profile, std::wstring_view work);
    [[nodiscard]] DWORD Restore();
    [[nodiscard]] const std::wstring& failurePath() const noexcept { return failurePath_; }
#ifdef LAUNCH_AS_TESTING
    [[nodiscard]] DWORD EnsureForTesting(HANDLE token, std::span<const std::wstring> volumes,
        std::span<const std::wstring> readable, std::wstring_view profile, std::wstring_view work,
        DWORD maximumObjects = 10'000, DWORD timeoutMilliseconds = 30'000);
    [[nodiscard]] DWORD EnsureNamespaceForTesting(std::span<const std::wstring> directories);
#endif

  private:
    struct Entry
    {
        UniqueHandle object;
        DWORD addedMask = 0;
        bool addedOwnerDeny = false;
        bool namespaceDirectory = false;
        bool addedTraverseGrant = false;
        bool writable = false;
    };
    [[nodiscard]] DWORD EnsureRoots(HANDLE token, std::span<const std::wstring> volumes,
        std::span<const std::wstring> readable, std::wstring_view profile, std::wstring_view work,
        DWORD maximumObjects = 10'000, DWORD timeoutMilliseconds = 30'000);
    [[nodiscard]] DWORD Visit(std::wstring_view path, UniqueHandle object, DWORD depth,
        DWORD& remaining, ULONGLONG deadline);
    [[nodiscard]] DWORD SetAccess(Entry& entry, DWORD mask, bool readableRoot = false);
    [[nodiscard]] DWORD EnsureWindowsNamespace(HANDLE token);
    [[nodiscard]] DWORD EnsureNamespaceDirectories(std::span<const std::wstring> directories);
    std::vector<BYTE> userSid_;
    std::vector<BYTE> groups_;
    std::vector<std::wstring> allowed_;
    std::map<std::wstring, Entry> entries_;
    std::map<std::wstring, std::wstring> volumes_;
    std::wstring failurePath_;
    Observer observer_;
};

} // namespace launch_as::broker
