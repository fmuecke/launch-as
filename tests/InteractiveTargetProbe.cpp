// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sddl.h>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] std::string NarrowAscii(std::wstring_view value)
{
    std::string result;
    result.reserve(value.size());
    for (const wchar_t character : value)
    {
        result.push_back(static_cast<char>(character));
    }
    return result;
}

[[nodiscard]] DWORD ReadUserObjectName(HANDLE object, std::wstring& name)
{
    name.clear();
    DWORD required = 0;
    GetUserObjectInformationW(object, UOI_NAME, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required < sizeof(wchar_t))
    {
        return sizeError;
    }
    std::vector<wchar_t> buffer(required / sizeof(wchar_t));
    if (!GetUserObjectInformationW(object, UOI_NAME, buffer.data(), required, &required))
    {
        const DWORD nameError = GetLastError();
        return nameError;
    }
    name.assign(buffer.data());
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD ReadTokenLogonSid(std::wstring& sidText)
{
    sidText.clear();
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        const DWORD tokenError = GetLastError();
        return tokenError;
    }
    DWORD required = 0;
    GetTokenInformation(token, TokenLogonSid, nullptr, 0, &required);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || required == 0)
    {
        CloseHandle(token);
        return sizeError;
    }
    std::vector<BYTE> buffer(required);
    if (!GetTokenInformation(token, TokenLogonSid, buffer.data(), required, &required))
    {
        const DWORD sidError = GetLastError();
        CloseHandle(token);
        return sidError;
    }
    CloseHandle(token);
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
    if (groups->GroupCount != 1 || !IsValidSid(groups->Groups[0].Sid))
    {
        return ERROR_INVALID_SID;
    }
    PWSTR rawSid = nullptr;
    if (!ConvertSidToStringSidW(groups->Groups[0].Sid, &rawSid))
    {
        const DWORD conversionError = GetLastError();
        return conversionError;
    }
    sidText = rawSid;
    LocalFree(rawSid);
    return ERROR_SUCCESS;
}

LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == WM_TIMER)
    {
        DestroyWindow(window);
        return 0;
    }
    if (message == WM_DESTROY)
    {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 4)
    {
        return ERROR_INVALID_PARAMETER;
    }
    wchar_t* durationEnd = nullptr;
    const unsigned long duration = wcstoul(arguments[3], &durationEnd, 10);
    if (durationEnd == arguments[3] || *durationEnd != L'\0' || duration == 0 || duration > 30'000)
    {
        return ERROR_INVALID_PARAMETER;
    }

    DWORD processSessionId = 0;
    const bool sessionRead =
        ProcessIdToSessionId(GetCurrentProcessId(), &processSessionId) != FALSE;
    const DWORD sessionError = sessionRead ? ERROR_SUCCESS : GetLastError();
    std::wstring windowStationName;
    const DWORD windowStationError =
        ReadUserObjectName(GetProcessWindowStation(), windowStationName);
    std::wstring desktopName;
    const DWORD desktopError =
        ReadUserObjectName(GetThreadDesktop(GetCurrentThreadId()), desktopName);
    std::wstring logonSid;
    const DWORD logonSidError = ReadTokenLogonSid(logonSid);

    const wchar_t className[] = L"LaunchAsInteractiveTargetProbeWindow";
    WNDCLASSW windowClass {};
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = GetModuleHandleW(nullptr);
    windowClass.lpszClassName = className;
    const ATOM classAtom = RegisterClassW(&windowClass);
    const DWORD classError = classAtom != 0 ? ERROR_SUCCESS : GetLastError();
    HWND window = nullptr;
    DWORD windowError = classError;
    if (classAtom != 0)
    {
        window = CreateWindowExW(0,
            className,
            arguments[2],
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            480,
            240,
            nullptr,
            nullptr,
            windowClass.hInstance,
            nullptr);
        windowError = window != nullptr ? ERROR_SUCCESS : GetLastError();
    }
    if (window != nullptr)
    {
        ShowWindow(window, SW_SHOW);
        UpdateWindow(window);
    }

    const bool success = sessionRead && windowStationError == ERROR_SUCCESS &&
                         desktopError == ERROR_SUCCESS && logonSidError == ERROR_SUCCESS &&
                         window != nullptr;
    std::ofstream result(std::filesystem::path(arguments[1]), std::ios::binary | std::ios::trunc);
    if (!result)
    {
        if (window != nullptr)
        {
            DestroyWindow(window);
        }
        return ERROR_OPEN_FAILED;
    }
    result << "processSessionId=" << processSessionId << '\n';
    result << "sessionError=" << sessionError << '\n';
    result << "processWindowStation=" << NarrowAscii(windowStationName) << '\n';
    result << "windowStationError=" << windowStationError << '\n';
    result << "threadDesktop=" << NarrowAscii(desktopName) << '\n';
    result << "desktopError=" << desktopError << '\n';
    result << "tokenLogonSid=" << NarrowAscii(logonSid) << '\n';
    result << "logonSidError=" << logonSidError << '\n';
    result << "windowCreated=" << (window != nullptr ? "true" : "false") << '\n';
    result << "windowError=" << windowError << '\n';
    result << "probeSucceeded=" << (success ? "true" : "false") << '\n';
    result.flush();
    if (!result.good() || !success)
    {
        if (window != nullptr)
        {
            DestroyWindow(window);
        }
        return ERROR_ACCESS_DENIED;
    }

    if (SetTimer(window, 1, duration, nullptr) == 0)
    {
        const DWORD timerError = GetLastError();
        DestroyWindow(window);
        return static_cast<int>(timerError);
    }
    MSG message {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return ERROR_SUCCESS;
}
