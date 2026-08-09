// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <sddl.h>
#include <string>
#include <vector>

namespace
{

constexpr DWORD MaximumUserNameCharacters = 256;

struct WindowSearch
{
    HWND expected = nullptr;
    bool found = false;
};

[[nodiscard]] bool IsProcessAccessDenied(DWORD processId, DWORD desiredAccess)
{
    HANDLE process = OpenProcess(desiredAccess, FALSE, processId);
    const DWORD openError = process == nullptr ? GetLastError() : ERROR_SUCCESS;
    if (process != nullptr)
    {
        CloseHandle(process);
    }
    return openError == ERROR_ACCESS_DENIED;
}

BOOL CALLBACK FindExpectedWindow(HWND window, LPARAM value)
{
    auto* search = reinterpret_cast<WindowSearch*>(value);
    if (window == search->expected)
    {
        search->found = true;
    }
    return TRUE;
}

[[nodiscard]] bool ParseUnsigned(std::wstring_view value, unsigned long long& parsed)
{
    if (value.empty())
    {
        return false;
    }
    wchar_t* end = nullptr;
    parsed = std::wcstoull(value.data(), &end, 10);
    return end == value.data() + value.size() && *end == L'\0';
}

[[nodiscard]] DWORD GetLogonSid(std::wstring& value)
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        const DWORD tokenError = GetLastError();
        return tokenError;
    }
    DWORD bytes = 0;
    GetTokenInformation(rawToken, TokenLogonSid, nullptr, 0, &bytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
    {
        CloseHandle(rawToken);
        return sizeError;
    }
    std::vector<BYTE> buffer(bytes);
    if (!GetTokenInformation(rawToken, TokenLogonSid, buffer.data(), bytes, &bytes))
    {
        const DWORD sidError = GetLastError();
        CloseHandle(rawToken);
        return sidError;
    }
    CloseHandle(rawToken);
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
    if (groups->GroupCount != 1 || !IsValidSid(groups->Groups[0].Sid))
    {
        return ERROR_INVALID_SID;
    }
    LPWSTR rawSid = nullptr;
    if (!ConvertSidToStringSidW(groups->Groups[0].Sid, &rawSid))
    {
        const DWORD convertError = GetLastError();
        return convertError;
    }
    value = rawSid;
    LocalFree(rawSid);
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD GetAccountName(std::wstring& value)
{
    std::vector<wchar_t> buffer(MaximumUserNameCharacters);
    DWORD characters = static_cast<DWORD>(buffer.size());
    if (!GetUserNameW(buffer.data(), &characters) || characters == 0)
    {
        const DWORD nameError = GetLastError();
        return nameError;
    }
    value.assign(buffer.data(), characters - 1);
    return ERROR_SUCCESS;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 7 || std::wstring_view(arguments[1]) != L"--window" ||
        std::wstring_view(arguments[3]) != L"--process" ||
        std::wstring_view(arguments[5]) != L"--exit-code")
    {
        std::wcerr << L"Usage: BrokerChildIdentityProbe --window <hwnd> --process <pid> "
                      L"--exit-code <code>\n";
        return 1;
    }

    unsigned long long windowValue = 0;
    unsigned long long processValue = 0;
    unsigned long long exitCode = 0;
    if (!ParseUnsigned(arguments[2], windowValue) || !ParseUnsigned(arguments[4], processValue) ||
        !ParseUnsigned(arguments[6], exitCode) || windowValue == 0 || processValue == 0 ||
        processValue > MAXDWORD || exitCode > MAXDWORD)
    {
        std::wcerr << L"Invalid probe arguments.\n";
        return 1;
    }

    std::wstring logonSid;
    const DWORD logonSidError = GetLogonSid(logonSid);
    if (logonSidError != ERROR_SUCCESS)
    {
        std::wcerr << L"Could not read the child logon SID: " << logonSidError << L"\n";
        return 1;
    }
    std::wstring accountName;
    const DWORD accountNameError = GetAccountName(accountName);
    if (accountNameError != ERROR_SUCCESS)
    {
        std::wcerr << L"Could not read the child account name: " << accountNameError << L"\n";
        return 1;
    }

    WindowSearch search {.expected = reinterpret_cast<HWND>(static_cast<UINT_PTR>(windowValue))};
    SetLastError(ERROR_SUCCESS);
    const BOOL enumerated = EnumWindows(FindExpectedWindow, reinterpret_cast<LPARAM>(&search));
    const DWORD enumerationError = enumerated ? ERROR_SUCCESS : GetLastError();
    const auto printEnvironment = [](const wchar_t* name)
    {
        wchar_t* value = nullptr;
        std::size_t characters = 0;
        if (_wdupenv_s(&value, &characters, name) != 0 || value == nullptr)
        {
            std::wcout << name << L"=\n";
            return;
        }
        std::wcout << name << L"=" << value << L"\n";
        free(value);
    };
    std::wcout << L"account=" << accountName << L"\n";
    printEnvironment(L"USERNAME");
    printEnvironment(L"APPDATA");
    printEnvironment(L"LOCALAPPDATA");
    printEnvironment(L"USERPROFILE");
    std::wcout << L"logonSid=" << logonSid << L"\n";
    std::wcout << L"interactiveWindowVisible=" << (search.found ? L"true" : L"false") << L"\n";
    std::wcout << L"enumWindowsError=" << enumerationError << L"\n";
    std::wcout << L"interactiveProcessVmReadDenied="
               << (IsProcessAccessDenied(static_cast<DWORD>(processValue), PROCESS_VM_READ)
                          ? L"true"
                          : L"false")
               << L"\n";
    std::wcout << L"interactiveProcessTerminateDenied="
               << (IsProcessAccessDenied(static_cast<DWORD>(processValue), PROCESS_TERMINATE)
                          ? L"true"
                          : L"false")
               << L"\n";
    return static_cast<int>(exitCode);
}
