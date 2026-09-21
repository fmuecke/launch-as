// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

struct WindowSearch final
{
    std::wstring_view title;
    bool found = false;
};

BOOL CALLBACK FindWindowByTitle(HWND window, LPARAM parameter)
{
    auto& search = *reinterpret_cast<WindowSearch*>(parameter);
    const int length = GetWindowTextLengthW(window);
    if (length <= 0)
    {
        return TRUE;
    }
    std::vector<wchar_t> title(static_cast<std::size_t>(length) + 1);
    if (GetWindowTextW(window, title.data(), static_cast<int>(title.size())) > 0 &&
        std::wstring_view(title.data()) == search.title)
    {
        search.found = true;
    }
    return TRUE;
}

[[nodiscard]] std::wstring ReadObjectName(HANDLE object)
{
    DWORD required = 0;
    GetUserObjectInformationW(object, UOI_NAME, nullptr, 0, &required);
    if (required == 0)
    {
        return {};
    }
    std::vector<wchar_t> name((required + sizeof(wchar_t) - 1) / sizeof(wchar_t));
    if (!GetUserObjectInformationW(object, UOI_NAME, name.data(), required, &required))
    {
        return {};
    }
    return name.data();
}

[[nodiscard]] std::string NarrowAscii(std::wstring_view value)
{
    std::string result;
    result.reserve(value.size());
    for (const wchar_t character : value)
    {
        result.push_back(character >= 0 && character <= 0x7f ? static_cast<char>(character) : '?');
    }
    return result;
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 3)
    {
        std::wcerr << L"Usage: LauncherInteractiveSessionProbe.exe <window-title> <result-path>\n";
        return ERROR_INVALID_PARAMETER;
    }

    DWORD processSessionId = MAXDWORD;
    const BOOL readProcessSession = ProcessIdToSessionId(GetCurrentProcessId(), &processSessionId);
    const DWORD processSessionError = readProcessSession ? ERROR_SUCCESS : GetLastError();
    const DWORD activeConsoleSessionId = WTSGetActiveConsoleSessionId();

    HWINSTA originalWindowStation = GetProcessWindowStation();
    const DWORD originalWindowStationError =
        originalWindowStation != nullptr ? ERROR_SUCCESS : GetLastError();
    const std::wstring originalWindowStationName =
        originalWindowStation != nullptr ? ReadObjectName(originalWindowStation) : std::wstring {};

    HWINSTA interactiveWindowStation =
        OpenWindowStationW(L"WinSta0", FALSE, WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES);
    const DWORD openWindowStationError =
        interactiveWindowStation != nullptr ? ERROR_SUCCESS : GetLastError();

    DWORD setWindowStationError = ERROR_INVALID_HANDLE;
    HDESK desktop = nullptr;
    DWORD openDesktopError = ERROR_INVALID_HANDLE;
    DWORD enumerateWindowsError = ERROR_INVALID_HANDLE;
    DWORD restoreWindowStationError = ERROR_INVALID_HANDLE;
    WindowSearch search {arguments[1]};
    if (interactiveWindowStation != nullptr)
    {
        const BOOL setWindowStation = SetProcessWindowStation(interactiveWindowStation);
        setWindowStationError = setWindowStation ? ERROR_SUCCESS : GetLastError();
        if (setWindowStation)
        {
            desktop = OpenDesktopW(L"Default", 0, FALSE, DESKTOP_ENUMERATE | DESKTOP_READOBJECTS);
            openDesktopError = desktop != nullptr ? ERROR_SUCCESS : GetLastError();
            if (desktop != nullptr)
            {
                SetLastError(ERROR_SUCCESS);
                const BOOL enumerated = EnumDesktopWindows(
                    desktop, FindWindowByTitle, reinterpret_cast<LPARAM>(&search));
                enumerateWindowsError = enumerated ? ERROR_SUCCESS : GetLastError();
                CloseDesktop(desktop);
            }
            if (originalWindowStation != nullptr)
            {
                const BOOL restored = SetProcessWindowStation(originalWindowStation);
                restoreWindowStationError = restored ? ERROR_SUCCESS : GetLastError();
            }
        }
        CloseWindowStation(interactiveWindowStation);
    }

    std::ofstream output(std::filesystem::path(arguments[2]), std::ios::binary | std::ios::trunc);
    if (!output)
    {
        std::wcerr << L"Could not create the probe result: " << arguments[2] << L"\n";
        return ERROR_OPEN_FAILED;
    }
    output << "processSessionId=" << processSessionId << '\n';
    output << "processSessionError=" << processSessionError << '\n';
    output << "activeConsoleSessionId=" << activeConsoleSessionId << '\n';
    output << "processWindowStation=" << NarrowAscii(originalWindowStationName) << '\n';
    output << "originalWindowStationError=" << originalWindowStationError << '\n';
    output << "openWinSta0Error=" << openWindowStationError << '\n';
    output << "setWinSta0Error=" << setWindowStationError << '\n';
    output << "openDefaultDesktopError=" << openDesktopError << '\n';
    output << "enumerateWindowsError=" << enumerateWindowsError << '\n';
    output << "restoreWindowStationError=" << restoreWindowStationError << '\n';
    output << "canaryVisible=" << (search.found ? "true" : "false") << '\n';
    return output ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
}
