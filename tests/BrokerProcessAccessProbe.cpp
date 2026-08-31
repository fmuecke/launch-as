// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <cwchar>
#include <iostream>
#include <string_view>

namespace
{

[[nodiscard]] bool IsDenied(DWORD processId, DWORD access, std::wstring_view accessName)
{
    HANDLE process = OpenProcess(access, FALSE, processId);
    const DWORD openError = process == nullptr ? GetLastError() : ERROR_SUCCESS;
    if (process != nullptr)
    {
        CloseHandle(process);
        std::wcerr << L"Unexpectedly opened the broker child for " << accessName << L".\n";
        return false;
    }
    if (openError != ERROR_ACCESS_DENIED)
    {
        std::wcerr << L"Opening the broker child for " << accessName << L" returned " << openError
                   << L" instead of access denied.\n";
        return false;
    }
    return true;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 2)
    {
        std::wcerr << L"Expected the broker child process ID.\n";
        return 1;
    }
    wchar_t* end = nullptr;
    const unsigned long parsed = std::wcstoul(arguments[1], &end, 10);
    if (end == arguments[1] || *end != L'\0' || parsed == 0 || parsed > MAXDWORD)
    {
        std::wcerr << L"Invalid broker child process ID.\n";
        return 1;
    }
    const DWORD processId = static_cast<DWORD>(parsed);
    return IsDenied(processId, PROCESS_VM_READ, L"VM_READ") &&
                   IsDenied(processId, PROCESS_TERMINATE, L"TERMINATE")
               ? 0
               : 1;
}
