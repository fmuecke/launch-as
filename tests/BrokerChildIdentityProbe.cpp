// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <sddl.h>
#include <sstream>
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

[[nodiscard]] DWORD TokenContainsSid(std::wstring_view sidText, bool& contains)
{
    contains = false;
    const std::wstring sidValue(sidText);
    PSID expectedSid = nullptr;
    if (!ConvertStringSidToSidW(sidValue.c_str(), &expectedSid))
    {
        const DWORD convertError = GetLastError();
        return convertError;
    }

    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        const DWORD tokenError = GetLastError();
        LocalFree(expectedSid);
        return tokenError;
    }
    DWORD bytes = 0;
    GetTokenInformation(rawToken, TokenGroups, nullptr, 0, &bytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
    {
        CloseHandle(rawToken);
        LocalFree(expectedSid);
        return sizeError;
    }
    std::vector<BYTE> buffer(bytes);
    if (!GetTokenInformation(rawToken, TokenGroups, buffer.data(), bytes, &bytes))
    {
        const DWORD groupsError = GetLastError();
        CloseHandle(rawToken);
        LocalFree(expectedSid);
        return groupsError;
    }
    CloseHandle(rawToken);

    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
    for (DWORD index = 0; index < groups->GroupCount; ++index)
    {
        if (!IsValidSid(groups->Groups[index].Sid))
        {
            LocalFree(expectedSid);
            return ERROR_INVALID_SID;
        }
        if (EqualSid(groups->Groups[index].Sid, expectedSid))
        {
            contains = true;
            break;
        }
    }
    LocalFree(expectedSid);
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

[[nodiscard]] DWORD WriteReport(std::wstring_view path, std::wstring_view report)
{
    if (path.empty())
    {
        return ERROR_SUCCESS;
    }
    const std::wstring filePath(path);
    HANDLE file = CreateFileW(
        filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        const DWORD createError = GetLastError();
        return createError;
    }

    const int bytes = WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS,
        report.data(),
        static_cast<int>(report.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (bytes <= 0)
    {
        const DWORD conversionError = GetLastError();
        CloseHandle(file);
        return conversionError;
    }
    std::vector<char> utf8(static_cast<std::size_t>(bytes));
    if (WideCharToMultiByte(CP_UTF8,
            WC_ERR_INVALID_CHARS,
            report.data(),
            static_cast<int>(report.size()),
            utf8.data(),
            bytes,
            nullptr,
            nullptr) != bytes)
    {
        const DWORD conversionError = GetLastError();
        CloseHandle(file);
        return conversionError;
    }
    DWORD bytesWritten = 0;
    const BOOL wrote =
        WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &bytesWritten, nullptr);
    const DWORD writeError = wrote ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    return wrote && bytesWritten == utf8.size() ? ERROR_SUCCESS
                                                : (wrote ? ERROR_WRITE_FAULT : writeError);
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    const bool hasOutput = argumentCount == 11;
    if ((argumentCount != 9 && !hasOutput) || std::wstring_view(arguments[1]) != L"--window" ||
        std::wstring_view(arguments[3]) != L"--process" ||
        std::wstring_view(arguments[5]) != L"--exit-code" ||
        std::wstring_view(arguments[7]) != L"--interactive-logon-sid" ||
        std::wstring_view(arguments[8]).empty() ||
        (hasOutput && (std::wstring_view(arguments[9]) != L"--output" ||
                          std::wstring_view(arguments[10]).empty())))
    {
        std::wcerr << L"Usage: BrokerChildIdentityProbe --window <hwnd> --process <pid> "
                      L"--exit-code <code> --interactive-logon-sid <sid> [--output <path>]\n";
        return 1;
    }

    const std::wstring_view interactiveLogonSid = arguments[8];
    const std::wstring_view reportPath = hasOutput ? arguments[10] : L"";

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
    bool interactiveLogonSidPresent = false;
    const DWORD tokenGroupsError =
        TokenContainsSid(interactiveLogonSid, interactiveLogonSidPresent);
    if (tokenGroupsError != ERROR_SUCCESS)
    {
        std::wcerr << L"Could not inspect the child TokenGroups: " << tokenGroupsError << L"\n";
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
    std::wostringstream report;
    const auto printEnvironment = [&report](const wchar_t* name)
    {
        wchar_t* value = nullptr;
        std::size_t characters = 0;
        if (_wdupenv_s(&value, &characters, name) != 0 || value == nullptr)
        {
            report << name << L"=\n";
            return;
        }
        report << name << L"=" << value << L"\n";
        free(value);
    };
    report << L"account=" << accountName << L"\n";
    printEnvironment(L"USERNAME");
    printEnvironment(L"APPDATA");
    printEnvironment(L"LOCALAPPDATA");
    printEnvironment(L"USERPROFILE");
    report << L"logonSid=" << logonSid << L"\n";
    report << L"interactiveLogonSidPresentInTokenGroups="
           << (interactiveLogonSidPresent ? L"true" : L"false") << L"\n";
    report << L"interactiveWindowVisible=" << (search.found ? L"true" : L"false") << L"\n";
    report << L"enumWindowsError=" << enumerationError << L"\n";
    report << L"interactiveProcessVmReadDenied="
           << (IsProcessAccessDenied(static_cast<DWORD>(processValue), PROCESS_VM_READ) ? L"true"
                                                                                        : L"false")
           << L"\n";
    report << L"interactiveProcessTerminateDenied="
           << (IsProcessAccessDenied(static_cast<DWORD>(processValue), PROCESS_TERMINATE)
                      ? L"true"
                      : L"false")
           << L"\n";
    std::wcout << report.str();
    const DWORD reportError = WriteReport(reportPath, report.str());
    if (reportError != ERROR_SUCCESS)
    {
        std::wcerr << L"Could not write the probe report: " << reportError << L"\n";
        return 1;
    }
    return static_cast<int>(exitCode);
}
