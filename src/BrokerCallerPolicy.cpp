// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerCallerPolicy.h"

#include "Win32Support.h"

#include <limits>
#include <string>

namespace launch_as::broker
{
namespace
{

[[nodiscard]] PSID SidPointer(const std::vector<BYTE>& sid)
{
    return const_cast<BYTE*>(sid.data());
}

[[nodiscard]] bool IsCompleteSid(const std::vector<BYTE>& sid)
{
    if (sid.empty() || !IsValidSid(SidPointer(sid)))
    {
        return false;
    }
    return GetLengthSid(SidPointer(sid)) == sid.size();
}

} // namespace

DWORD StoreAuthorizedCallerSid(std::wstring_view path, PSID callerSid)
{
    if (path.empty() || !IsValidSid(callerSid))
    {
        return ERROR_INVALID_SID;
    }
    const DWORD sidBytes = GetLengthSid(callerSid);
    std::wstring filePath(path);
    HANDLE file = CreateFileW(
        filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD createError = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (file == INVALID_HANDLE_VALUE)
    {
        return createError;
    }
    DWORD writtenBytes = 0;
    const BOOL wrote = WriteFile(file, callerSid, sidBytes, &writtenBytes, nullptr);
    const DWORD writeError = wrote ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    return wrote && writtenBytes == sidBytes ? ERROR_SUCCESS
                                             : (wrote ? ERROR_WRITE_FAULT : writeError);
}

DWORD LoadAuthorizedCallerSid(std::wstring_view path, std::vector<BYTE>& callerSid)
{
    callerSid.clear();
    if (path.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    std::wstring filePath(path);
    HANDLE file = CreateFileW(
        filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    const DWORD openError = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (file == INVALID_HANDLE_VALUE)
    {
        return openError;
    }
    LARGE_INTEGER size {};
    if (!GetFileSizeEx(file, &size))
    {
        const DWORD sizeError = GetLastError();
        CloseHandle(file);
        return sizeError;
    }
    if (size.QuadPart <= 0 || size.QuadPart > SECURITY_MAX_SID_SIZE ||
        size.QuadPart > std::numeric_limits<DWORD>::max())
    {
        CloseHandle(file);
        return ERROR_INVALID_DATA;
    }
    callerSid.resize(static_cast<std::size_t>(size.QuadPart));
    DWORD readBytes = 0;
    const BOOL read =
        ReadFile(file, callerSid.data(), static_cast<DWORD>(callerSid.size()), &readBytes, nullptr);
    const DWORD readError = read ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    if (!read || readBytes != callerSid.size() || !IsCompleteSid(callerSid))
    {
        callerSid.clear();
        return read ? ERROR_INVALID_DATA : readError;
    }
    return ERROR_SUCCESS;
}

bool IsAuthorizedCaller(
    const std::vector<BYTE>& authorizedCallerSid, const std::vector<BYTE>& callerSid)
{
    return IsCompleteSid(authorizedCallerSid) && IsCompleteSid(callerSid) &&
           EqualSid(SidPointer(authorizedCallerSid), SidPointer(callerSid)) != FALSE;
}

std::wstring GetAuthorizedCallerPolicyPath(std::wstring_view dataDirectory)
{
    return std::wstring(dataDirectory) + L"\\" + AuthorizedCallerPolicyFileName.data();
}

} // namespace launch_as::broker
