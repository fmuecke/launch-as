// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "LaunchLog.h"

#include "Win32Support.h"

#include <array>
#include <iostream>
#include <memory>
#include <shlobj.h>
#include <vector>
#include <winevt.h>

namespace launch_as
{
namespace
{
using EventHandle = std::unique_ptr<void, decltype(&EvtClose)>;

DWORD RenderValues(HANDLE context, HANDLE event, std::vector<BYTE>& buffer, DWORD& properties)
{
    DWORD bytes = 0;
    if (!EvtRender(context, event, EvtRenderEventValues, 0, nullptr, &bytes, &properties))
    {
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER)
        {
            return error;
        }
    }
    buffer.resize(bytes);
    if (!EvtRender(context, event, EvtRenderEventValues, bytes, buffer.data(), &bytes, &properties))
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

std::wstring EscapeField(std::wstring_view value)
{
    std::wstring result;
    for (const auto character : value)
    {
        if (character == L'\r' || character == L'\n' || character == L'\t')
        {
            result += character == L'\r' ? L"\\r" : character == L'\n' ? L"\\n" : L"\\t";
        }
        else
        {
            result += character;
        }
    }
    return result;
}
} // namespace

DWORD LaunchLog::Append(std::wstring_view component, std::span<const std::wstring> fields)
{
    SYSTEMTIME now {};
    GetSystemTime(&now);
    std::array<wchar_t, 32> timestamp {};
    swprintf_s(timestamp.data(),
        timestamp.size(),
        L"%04u-%02u-%02uT%02u:%02u:%02uZ",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond);
    std::wstring line = std::wstring(timestamp.data()) + L" component=" + std::wstring(component);
    for (const auto& field : fields)
    {
        line += L"\t" + EscapeField(field);
    }
    line += L"\r\n";
    const int bytes = WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS,
        line.data(),
        static_cast<int>(line.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (bytes == 0)
    {
        return GetLastError();
    }
    std::string utf8(static_cast<std::size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8,
            WC_ERR_INVALID_CHARS,
            line.data(),
            static_cast<int>(line.size()),
            utf8.data(),
            bytes,
            nullptr,
            nullptr) == 0)
    {
        return GetLastError();
    }
    UniqueHandle file(CreateFileW(path_.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!file)
    {
        return GetLastError();
    }
    DWORD written = 0;
    if (!WriteFile(file.get(), utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr))
    {
        return GetLastError();
    }
    return written == utf8.size() ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
}

DWORD LaunchLog::Start(std::wstring_view requestId)
{
    PWSTR directory = nullptr;
    const HRESULT result =
        SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &directory);
    if (FAILED(result))
    {
        return HRESULT_CODE(result);
    }
    path_ = std::filesystem::path(directory) / L"launch-as" / L"launch-as.log";
    CoTaskMemFree(directory);
    std::error_code error;
    std::filesystem::create_directories(path_.parent_path(), error);
    if (error)
    {
        return static_cast<DWORD>(error.value());
    }
    requestId_ = requestId;
    const std::array fields {L"requestId=" + requestId_, std::wstring(L"action=client.request")};
    return Append(L"launch-as", fields);
}

void LaunchLog::Record(std::wstring_view action, DWORD error) noexcept
try
{
    collectionFailed_ = collectionFailed_ || action.starts_with(L"client.log_");
    if (path_.empty())
    {
        return;
    }
    const std::array fields {
        L"requestId=" + requestId_,
        L"action=" + std::wstring(action),
        L"win32Error=" + std::to_wstring(error)
    };
    const DWORD status = Append(L"launch-as", fields);
    if (status != ERROR_SUCCESS)
    {
        std::wcerr << L"Could not append to " << path_.c_str() << L": "
                   << FormatWindowsError(status) << L"\n";
    }
}

catch (...)
{ /* Diagnostics must not interrupt session teardown. */
}

void LaunchLog::Collect() noexcept
try
{
    if (path_.empty() || collectionFailed_)
    {
        return;
    }
    const std::wstring expression =
        L"*[System[Provider[@Name='launch-as-broker'] and EventID=7 and EventRecordID>" +
        std::to_wstring(lastRecord_) + L"] and EventData[Data='requestId=" + requestId_ + L"']]";
    EventHandle query(EvtQuery(nullptr,
                          L"Application",
                          expression.c_str(),
                          EvtQueryChannelPath | EvtQueryForwardDirection),
        EvtClose);
    if (!query)
    {
        const DWORD error = GetLastError();
        Record(L"client.log_query_failed", error);
        return;
    }
    EventHandle context(EvtCreateRenderContext(0, nullptr, EvtRenderContextUser), EvtClose);
    if (!context)
    {
        const DWORD error = GetLastError();
        Record(L"client.log_context_failed", error);
        return;
    }
    EventHandle systemContext(EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem), EvtClose);
    if (!systemContext)
    {
        const DWORD error = GetLastError();
        Record(L"client.log_context_failed", error);
        return;
    }
    const ULONGLONG deadline = GetTickCount64() + 30'000;
    for (DWORD record = 0; record < 30'000 && GetTickCount64() < deadline; ++record)
    {
        EVT_HANDLE raw = nullptr;
        DWORD count = 0;
        if (!EvtNext(query.get(), 1, &raw, 1000, 0, &count))
        {
            const DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS)
            {
                Record(L"client.log_read_failed", error);
            }
            return;
        }
        EventHandle event(raw, EvtClose);
        DWORD properties = 0;
        std::vector<BYTE> systemBuffer;
        DWORD error = RenderValues(systemContext.get(), event.get(), systemBuffer, properties);
        if (error != ERROR_SUCCESS)
        {
            Record(L"client.log_render_failed", error);
            return;
        }
        const auto* systemValues = reinterpret_cast<const EVT_VARIANT*>(systemBuffer.data());
        if (properties <= EvtSystemEventRecordId ||
            systemValues[EvtSystemEventRecordId].Type != EvtVarTypeUInt64)
        {
            Record(L"client.log_invalid_event", ERROR_INVALID_DATA);
            return;
        }
        const ULONGLONG recordId = systemValues[EvtSystemEventRecordId].UInt64Val;
        std::vector<BYTE> buffer;
        error = RenderValues(context.get(), event.get(), buffer, properties);
        if (error != ERROR_SUCCESS)
        {
            Record(L"client.log_render_failed", error);
            return;
        }
        const auto* values = reinterpret_cast<const EVT_VARIANT*>(buffer.data());
        if (properties != 5)
        {
            Record(L"client.log_invalid_event", ERROR_INVALID_DATA);
            return;
        }
        std::vector<std::wstring> fields;
        for (DWORD index = 0; index < properties; ++index)
        {
            if (values[index].Type != EvtVarTypeString || values[index].StringVal == nullptr)
            {
                Record(L"client.log_invalid_event", ERROR_INVALID_DATA);
                return;
            }
            fields.emplace_back(values[index].StringVal);
        }
        error = Append(L"launch-as-broker", fields);
        if (error != ERROR_SUCCESS)
        {
            Record(L"client.log_write_failed", error);
            return;
        }
        lastRecord_ = recordId;
        completed_ = completed_ || fields[2] == L"action=session.closed" ||
                     fields[2] == L"action=launch.failed";
    }
    Record(L"client.log_limit", ERROR_NOT_ENOUGH_QUOTA);
}
catch (...)
{ /* Diagnostics must not interrupt session teardown. */
}

void LaunchLog::Finish() noexcept
{
    if (path_.empty())
    {
        return;
    }
    const ULONGLONG deadline = GetTickCount64() + 30'000;
    do
    {
        Collect();
        if (completed_ || collectionFailed_)
        {
            return;
        }
        Sleep(50);
    } while (GetTickCount64() < deadline);
    Record(L"client.log_completion_timeout", ERROR_TIMEOUT);
}
} // namespace launch_as
