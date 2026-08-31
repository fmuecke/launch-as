// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

class TemporaryReport final
{
  public:
    explicit TemporaryReport(std::wstring path) : path_(std::move(path)) {}

    ~TemporaryReport() { DeleteFileW(path_.c_str()); }

    [[nodiscard]] const std::wstring& path() const { return path_; }

  private:
    std::wstring path_;
};

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] bool CreateTemporaryReport(TemporaryReport& report)
{
    std::array<wchar_t, MAX_PATH> temporaryDirectory {};
    if (GetTempPathW(static_cast<DWORD>(temporaryDirectory.size()), temporaryDirectory.data()) == 0)
    {
        std::wcerr << L"Could not find the temporary directory.\n";
        return false;
    }

    std::array<wchar_t, MAX_PATH> reportPath {};
    if (GetTempFileNameW(temporaryDirectory.data(), L"lap", 0, reportPath.data()) == 0)
    {
        std::wcerr << L"Could not allocate a report path.\n";
        return false;
    }
    if (!DeleteFileW(reportPath.data()))
    {
        std::wcerr << L"Could not prepare the report path.\n";
        return false;
    }

    report = TemporaryReport(reportPath.data());
    return true;
}

[[nodiscard]] bool RunProbe(const std::wstring& probePath, const TemporaryReport& report)
{
    const std::vector<std::wstring> arguments {
        L"--window",
        L"1",
        L"--process",
        std::to_wstring(GetCurrentProcessId()),
        L"--exit-code",
        L"37",
        L"--output",
        report.path(),
    };
    std::wstring commandLine = launch_as::BuildWindowsCommandLine(probePath, arguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInformation {};
    startupInformation.cb = sizeof(startupInformation);
    PROCESS_INFORMATION processInformation {};
    if (!CreateProcessW(probePath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInformation,
            &processInformation))
    {
        const DWORD processError = GetLastError();
        std::wcerr << L"Could not start the identity probe: "
                   << launch_as::FormatWindowsError(processError) << L"\n";
        return false;
    }
    launch_as::UniqueHandle process(processInformation.hProcess);
    launch_as::UniqueHandle thread(processInformation.hThread);
    if (!Expect(WaitForSingleObject(process.get(), 5'000) == WAIT_OBJECT_0,
            L"The identity probe did not exit."))
    {
        return false;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(process.get(), &exitCode))
    {
        const DWORD exitCodeError = GetLastError();
        std::wcerr << L"Could not read the identity probe exit code: "
                   << launch_as::FormatWindowsError(exitCodeError) << L"\n";
        return false;
    }
    return Expect(exitCode == 37, L"The identity probe did not preserve its requested exit code.");
}

[[nodiscard]] bool VerifyReport(const TemporaryReport& report)
{
    const HANDLE file = CreateFileW(
        report.path().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        const DWORD fileError = GetLastError();
        std::wcerr << L"Could not open the identity report: "
                   << launch_as::FormatWindowsError(fileError) << L"\n";
        return false;
    }
    launch_as::UniqueHandle reportFile(file);

    LARGE_INTEGER size {};
    if (!GetFileSizeEx(reportFile.get(), &size) || size.QuadPart <= 0 || size.QuadPart > MAXDWORD)
    {
        std::wcerr << L"The identity report has an invalid size.\n";
        return false;
    }
    std::vector<char> utf8(static_cast<std::size_t>(size.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(
            reportFile.get(), utf8.data(), static_cast<DWORD>(utf8.size()), &bytesRead, nullptr) ||
        bytesRead != utf8.size())
    {
        std::wcerr << L"Could not read the complete identity report.\n";
        return false;
    }

    const int characters = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (!Expect(characters > 0, L"The identity report is not valid UTF-8."))
    {
        return false;
    }
    std::wstring text(static_cast<std::size_t>(characters), L'\0');
    if (MultiByteToWideChar(CP_UTF8,
            MB_ERR_INVALID_CHARS,
            utf8.data(),
            static_cast<int>(utf8.size()),
            text.data(),
            characters) != characters)
    {
        std::wcerr << L"Could not decode the identity report.\n";
        return false;
    }

    return Expect(text.find(L"account=") != std::wstring::npos,
               L"The identity report did not include the account.") &&
           Expect(text.find(L"logonSid=") != std::wstring::npos,
               L"The identity report did not include the logon SID.") &&
           Expect(text.find(L"interactiveWindowVisible=") != std::wstring::npos,
               L"The identity report did not include the window result.");
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 2)
    {
        std::wcerr << L"Usage: BrokerChildIdentityProbeTests <probe-path>\n";
        return 1;
    }

    TemporaryReport report(L"");
    if (!CreateTemporaryReport(report))
    {
        return 1;
    }
    return RunProbe(arguments[1], report) && VerifyReport(report) ? 0 : 1;
}
