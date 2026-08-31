// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAudit.h"

#include <limits>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr wchar_t BrokerEventSource[] = L"launch-as-broker";
constexpr wchar_t BrokerEventSourceRegistryPath[] =
    L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\launch-as-broker";

} // namespace

DWORD RegisterBrokerEventSource()
{
    HKEY key = nullptr;
    const LSTATUS createStatus = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        BrokerEventSourceRegistryPath,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &key,
        nullptr);
    if (createStatus != ERROR_SUCCESS)
    {
        return static_cast<DWORD>(createStatus);
    }
    const DWORD supportedTypes =
        EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    const LSTATUS setStatus = RegSetValueExW(key,
        L"TypesSupported",
        0,
        REG_DWORD,
        reinterpret_cast<const BYTE*>(&supportedTypes),
        sizeof(supportedTypes));
    RegCloseKey(key);
    return static_cast<DWORD>(setStatus);
}

DWORD UnregisterBrokerEventSource()
{
    const LSTATUS deleteStatus = RegDeleteTreeW(HKEY_LOCAL_MACHINE, BrokerEventSourceRegistryPath);
    return deleteStatus == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : static_cast<DWORD>(deleteStatus);
}

DWORD WriteBrokerAuditEvent(WORD type, BrokerAuditEvent event, std::span<const std::wstring> fields)
{
    if (fields.size() > std::numeric_limits<WORD>::max())
    {
        return ERROR_INVALID_PARAMETER;
    }
    std::vector<LPCWSTR> strings;
    strings.reserve(fields.size());
    for (const std::wstring& field : fields)
    {
        if (field.find(L'\0') != std::wstring::npos)
        {
            return ERROR_INVALID_PARAMETER;
        }
        strings.push_back(field.c_str());
    }
    HANDLE source = RegisterEventSourceW(nullptr, BrokerEventSource);
    if (source == nullptr)
    {
        const DWORD sourceError = GetLastError();
        return sourceError;
    }
    const BOOL reported = ReportEventW(source,
        type,
        0,
        static_cast<DWORD>(event),
        nullptr,
        static_cast<WORD>(strings.size()),
        0,
        strings.data(),
        nullptr);
    const DWORD reportError = reported ? ERROR_SUCCESS : GetLastError();
    DeregisterEventSource(source);
    return reportError;
}

} // namespace launch_as::broker
