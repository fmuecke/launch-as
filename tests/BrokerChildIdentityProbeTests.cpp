// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "TestSupport.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <Windows.h>
#include <array>
#include <iostream>
#include <sddl.h>
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

[[nodiscard]] bool GetCurrentLogonSid(std::wstring& value)
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        const DWORD tokenError = GetLastError();
        std::wcerr << L"Could not open the test process token: "
                   << launch_as::FormatWindowsError(tokenError) << L"\n";
        return false;
    }
    launch_as::UniqueHandle token(rawToken);

    DWORD bytes = 0;
    GetTokenInformation(token.get(), TokenLogonSid, nullptr, 0, &bytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
    {
        std::wcerr << L"Could not size the test process logon SID: "
                   << launch_as::FormatWindowsError(sizeError) << L"\n";
        return false;
    }
    std::vector<BYTE> buffer(bytes);
    if (!GetTokenInformation(token.get(), TokenLogonSid, buffer.data(), bytes, &bytes))
    {
        const DWORD sidError = GetLastError();
        std::wcerr << L"Could not read the test process logon SID: "
                   << launch_as::FormatWindowsError(sidError) << L"\n";
        return false;
    }
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
    if (groups->GroupCount != 1 || !IsValidSid(groups->Groups[0].Sid))
    {
        std::wcerr << L"The test process has an invalid logon SID.\n";
        return false;
    }

    LPWSTR rawSid = nullptr;
    if (!ConvertSidToStringSidW(groups->Groups[0].Sid, &rawSid))
    {
        const DWORD convertError = GetLastError();
        std::wcerr << L"Could not format the test process logon SID: "
                   << launch_as::FormatWindowsError(convertError) << L"\n";
        return false;
    }
    value = rawSid;
    LocalFree(rawSid);
    return true;
}

[[nodiscard]] bool RunProbe(const std::wstring& probePath, const TemporaryReport& report,
    std::wstring_view interactiveLogonSid)
{
    const std::vector<std::wstring> arguments {
        L"--window",
        L"1",
        L"--process",
        std::to_wstring(GetCurrentProcessId()),
        L"--exit-code",
        L"37",
        L"--interactive-logon-sid",
        std::wstring(interactiveLogonSid),
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
           Expect(text.find(L"interactiveLogonSidPresentInTokenGroups=true") != std::wstring::npos,
               L"The identity report did not find its own logon SID in TokenGroups.") &&
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
    std::wstring interactiveLogonSid;
    if (!CreateTemporaryReport(report) || !GetCurrentLogonSid(interactiveLogonSid))
    {
        return 1;
    }
    return RunProbe(arguments[1], report, interactiveLogonSid) && VerifyReport(report) ? 0 : 1;
}
