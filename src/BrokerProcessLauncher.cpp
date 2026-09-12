// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"

#include "PseudoConsoleHostReport.h"
#include "WindowsCommandLine.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <userenv.h>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr DWORD JobTerminationTimeoutMilliseconds = 5'000;

#ifdef LAUNCH_AS_TESTING
bool failBrokerJobQueryForTesting = false;
#endif

[[nodiscard]] bool IsDirectorySeparator(wchar_t character) noexcept
{
    return character == L'\\' || character == L'/';
}

[[nodiscard]] bool HasNetworkOrDevicePrefix(std::wstring_view path) noexcept
{
    return path.size() >= 2 && IsDirectorySeparator(path[0]) && IsDirectorySeparator(path[1]);
}

class EnabledProcessPrivileges final
{
  public:
    ~EnabledProcessPrivileges()
    {
        for (DWORD index = 0; index < enabledCount_; ++index)
        {
            AdjustTokenPrivileges(token_, FALSE, &previous_[index], 0, nullptr, nullptr);
        }
        if (token_ != nullptr)
        {
            CloseHandle(token_);
        }
    }

    [[nodiscard]] DWORD EnableRequired()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_))
        {
            const DWORD tokenError = GetLastError();
            return tokenError;
        }
        const DWORD assignTokenError = Enable(SE_ASSIGNPRIMARYTOKEN_NAME);
        if (assignTokenError != ERROR_SUCCESS)
        {
            return assignTokenError;
        }
        return Enable(SE_INCREASE_QUOTA_NAME);
    }

  private:
    [[nodiscard]] DWORD Enable(const wchar_t* privilegeName)
    {
        LUID privilege {};
        if (!LookupPrivilegeValueW(nullptr, privilegeName, &privilege))
        {
            const DWORD lookupError = GetLastError();
            return lookupError;
        }
        TOKEN_PRIVILEGES requested {};
        requested.PrivilegeCount = 1;
        requested.Privileges[0].Luid = privilege;
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD returnedBytes = 0;
        if (!AdjustTokenPrivileges(token_,
                FALSE,
                &requested,
                sizeof(previous_[enabledCount_]),
                &previous_[enabledCount_],
                &returnedBytes))
        {
            const DWORD adjustError = GetLastError();
            return adjustError;
        }
        const DWORD adjustmentError = GetLastError();
        if (adjustmentError != ERROR_SUCCESS)
        {
            return adjustmentError;
        }
        ++enabledCount_;
        return ERROR_SUCCESS;
    }

    HANDLE token_ = nullptr;
    std::array<TOKEN_PRIVILEGES, 2> previous_ {};
    DWORD enabledCount_ = 0;
};

class UserEnvironmentBlock final
{
  public:
    ~UserEnvironmentBlock()
    {
        if (environment_ != nullptr)
        {
            DestroyEnvironmentBlock(environment_);
        }
    }

    [[nodiscard]] DWORD Create(HANDLE token)
    {
        if (!CreateEnvironmentBlock(&environment_, token, FALSE))
        {
            const DWORD environmentError = GetLastError();
            return environmentError;
        }
        return ERROR_SUCCESS;
    }

    [[nodiscard]] void* get() const noexcept { return environment_; }

  private:
    void* environment_ = nullptr;
};

[[nodiscard]] DWORD GetProbeExecutablePath(std::wstring& path)
{
    std::vector<wchar_t> directory(MAX_PATH);
    for (;;)
    {
        const UINT characters =
            GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
        if (characters == 0)
        {
            const DWORD directoryError = GetLastError();
            return directoryError;
        }
        if (characters < directory.size())
        {
            path.assign(directory.data(), characters);
            path += L"\\cmd.exe";
            return ERROR_SUCCESS;
        }
        if (directory.size() >= 32'768)
        {
            return ERROR_BUFFER_OVERFLOW;
        }
        directory.resize(directory.size() * 2);
    }
}

[[nodiscard]] DWORD GetBrokerConhostExecutablePath(std::wstring& path)
{
    std::vector<wchar_t> modulePath(512);
    for (;;)
    {
        const DWORD characters =
            GetModuleFileNameW(nullptr, modulePath.data(), static_cast<DWORD>(modulePath.size()));
        if (characters == 0)
        {
            const DWORD moduleError = GetLastError();
            return moduleError;
        }
        if (characters < modulePath.size())
        {
            const std::filesystem::path brokerPath(
                std::wstring(modulePath.data(), static_cast<std::size_t>(characters)));
            path = (brokerPath.parent_path() / L"launch-as-conhost.exe").native();
            std::error_code pathError;
            if (!std::filesystem::is_regular_file(path, pathError))
            {
                return pathError ? static_cast<DWORD>(pathError.value()) : ERROR_FILE_NOT_FOUND;
            }
            return ERROR_SUCCESS;
        }
        modulePath.resize(modulePath.size() * 2);
    }
}

[[nodiscard]] bool CopyValidSid(PSID source, std::vector<BYTE>& destination)
{
    destination.clear();
    if (!IsValidSid(source))
    {
        return false;
    }
    const DWORD sidBytes = GetLengthSid(source);
    destination.resize(sidBytes);
    if (!CopySid(sidBytes, destination.data(), source))
    {
        destination.clear();
        return false;
    }
    return true;
}

[[nodiscard]] bool CreateBrokerReportPipe(
    HANDLE& readEnd, HANDLE& writeEnd, DWORD bufferSize, DWORD& error)
{
    readEnd = nullptr;
    writeEnd = nullptr;
    SECURITY_ATTRIBUTES attributes {};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    if (!CreatePipe(&readEnd, &writeEnd, &attributes, bufferSize))
    {
        error = GetLastError();
        return false;
    }
    if (!SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0))
    {
        error = GetLastError();
        CloseHandle(readEnd);
        CloseHandle(writeEnd);
        readEnd = nullptr;
        writeEnd = nullptr;
        return false;
    }
    return true;
}

[[nodiscard]] HANDLE CreateInheritableNullInput(DWORD& error)
{
    SECURITY_ATTRIBUTES attributes {};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE input = CreateFileW(L"NUL",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &attributes,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (input == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        return nullptr;
    }
    return input;
}

void CloseHandleIfPresent(HANDLE& handle) noexcept
{
    if (handle != nullptr)
    {
        CloseHandle(handle);
        handle = nullptr;
    }
}

[[nodiscard]] bool QueryBrokerJobBasicAccountingInformation(
    HANDLE job, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION& accounting) noexcept
{
#ifdef LAUNCH_AS_TESTING
    if (failBrokerJobQueryForTesting)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
#endif
    return QueryInformationJobObject(job,
               JobObjectBasicAccountingInformation,
               &accounting,
               sizeof(accounting),
               nullptr) != FALSE;
}

} // namespace

#ifdef LAUNCH_AS_TESTING
void SetBrokerJobQueryFailureForTesting(bool fail) noexcept { failBrokerJobQueryForTesting = fail; }

DWORD LaunchQuickBrokerChildForTesting(BrokerChildProcess& child)
{
    const DWORD jobError = CreateBrokerJob(child);
    if (jobError != ERROR_SUCCESS)
    {
        return jobError;
    }
    std::wstring executablePath;
    const DWORD executableError = GetProbeExecutablePath(executablePath);
    if (executableError != ERROR_SUCCESS)
    {
        child.Reset();
        return executableError;
    }
    std::wstring commandLine = L"\"" + executablePath + L"\" /d /c exit 0";
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo {};
    if (!CreateProcessW(executablePath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo))
    {
        const DWORD processError = GetLastError();
        child.Reset();
        return processError;
    }
    if (!AssignProcessToJobObject(child.job_, processInfo.hProcess))
    {
        const DWORD assignmentError = GetLastError();
        static_cast<void>(TerminateProcess(processInfo.hProcess, ERROR_CANCELLED));
        static_cast<void>(WaitForSingleObject(processInfo.hProcess, INFINITE));
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        child.Reset();
        return assignmentError;
    }
    child.SetProcess(processInfo.hProcess, processInfo.hThread);
    const DWORD resumeError = child.Resume();
    if (resumeError != ERROR_SUCCESS)
    {
        static_cast<void>(child.TerminateAndWaitForExit());
    }
    return resumeError;
}
#endif

BrokerChildProcess::~BrokerChildProcess() { Reset(); }

HANDLE BrokerChildProcess::job() const noexcept { return job_; }

HANDLE BrokerChildProcess::process() const noexcept { return process_; }

DWORD BrokerChildProcess::processId() const noexcept
{
    return process_ == nullptr ? 0 : GetProcessId(process_);
}

BrokerChildProcess::operator bool() const noexcept
{
    return job_ != nullptr && process_ != nullptr && thread_ != nullptr;
}

DWORD BrokerChildProcess::Resume() noexcept
{
    if (thread_ == nullptr)
    {
        return ERROR_INVALID_HANDLE;
    }
    const DWORD suspendedCount = ResumeThread(thread_);
    if (suspendedCount == static_cast<DWORD>(-1))
    {
        const DWORD resumeError = GetLastError();
        return resumeError;
    }
    return suspendedCount == 1 ? ERROR_SUCCESS : ERROR_INVALID_STATE;
}

bool BrokerChildProcess::ReadPseudoConsoleHostResult(
    DWORD& childExitCode, std::wstring& diagnostics) noexcept
{
    childExitCode = 0;
    diagnostics.clear();
    if (exitReport_ == nullptr || diagnostics_ == nullptr)
    {
        return false;
    }

    PseudoConsoleHostExitReport report {};
    std::size_t bytesRead = 0;
    while (bytesRead < sizeof(report))
    {
        DWORD received = 0;
        if (!ReadFile(exitReport_,
                reinterpret_cast<BYTE*>(&report) + bytesRead,
                static_cast<DWORD>(sizeof(report) - bytesRead),
                &received,
                nullptr))
        {
            const DWORD reportError = GetLastError();
            if (reportError != ERROR_BROKEN_PIPE)
            {
                diagnostics = L"Could not read the console host exit report: " +
                              std::to_wstring(reportError) + L".";
            }
            break;
        }
        if (received == 0)
        {
            break;
        }
        bytesRead += received;
    }

    constexpr std::size_t MaximumDiagnosticBytes = 4 * 1024;
    std::string diagnosticBytes;
    std::array<char, 512> buffer {};
    for (;;)
    {
        DWORD received = 0;
        if (!ReadFile(
                diagnostics_, buffer.data(), static_cast<DWORD>(buffer.size()), &received, nullptr))
        {
            const DWORD diagnosticError = GetLastError();
            if (diagnosticError != ERROR_BROKEN_PIPE && diagnostics.empty())
            {
                diagnostics = L"Could not read console host diagnostics: " +
                              std::to_wstring(diagnosticError) + L".";
            }
            break;
        }
        if (received == 0)
        {
            break;
        }
        const std::size_t available = MaximumDiagnosticBytes - diagnosticBytes.size();
        const std::size_t copied = (std::min)(available, static_cast<std::size_t>(received));
        diagnosticBytes.append(buffer.data(), copied);
        if (diagnosticBytes.size() == MaximumDiagnosticBytes)
        {
            break;
        }
    }
    if (!diagnosticBytes.empty())
    {
        const int characters = MultiByteToWideChar(CP_UTF8,
            MB_ERR_INVALID_CHARS,
            diagnosticBytes.data(),
            static_cast<int>(diagnosticBytes.size()),
            nullptr,
            0);
        if (characters <= 0)
        {
            diagnostics = L"The console host emitted invalid UTF-8 diagnostics.";
        }
        else
        {
            diagnostics.resize(static_cast<std::size_t>(characters));
            if (MultiByteToWideChar(CP_UTF8,
                    MB_ERR_INVALID_CHARS,
                    diagnosticBytes.data(),
                    static_cast<int>(diagnosticBytes.size()),
                    diagnostics.data(),
                    characters) != characters)
            {
                diagnostics = L"The console host emitted invalid UTF-8 diagnostics.";
            }
        }
    }
    if (bytesRead != sizeof(report) || report.magic != PseudoConsoleHostExitReportMagic)
    {
        if (diagnostics.empty())
        {
            diagnostics = L"The console host exited without reporting the target exit code.";
        }
        return false;
    }
    childExitCode = report.childExitCode;
    return true;
}

bool BrokerChildProcess::TerminateAndWaitForExit() noexcept
{
    if (job_ == nullptr)
    {
        Reset();
        return true;
    }
    const ULONGLONG deadline = GetTickCount64() + JobTerminationTimeoutMilliseconds;
    static_cast<void>(TerminateJobObject(job_, ERROR_CANCELLED));
    if (process_ != nullptr)
    {
        const ULONGLONG now = GetTickCount64();
        const DWORD remaining = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
        if (WaitForSingleObject(process_, remaining) != WAIT_OBJECT_0)
        {
            Reset();
            return false;
        }
    }
    for (;;)
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting {};
        if (!QueryBrokerJobBasicAccountingInformation(job_, accounting))
        {
            Reset();
            return false;
        }
        if (accounting.ActiveProcesses == 0)
        {
            Reset();
            return true;
        }
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            Reset();
            return false;
        }
        const DWORD remaining = static_cast<DWORD>(deadline - now);
        Sleep(remaining < 10 ? remaining : 10);
    }
}

void BrokerChildProcess::Reset() noexcept
{
    CloseHandleIfPresent(exitReport_);
    CloseHandleIfPresent(diagnostics_);
    if (job_ != nullptr)
    {
        CloseHandle(job_);
    }
    if (profile_ != nullptr)
    {
        UnloadUserProfile(profileToken_, profile_);
    }
    if (profileToken_ != nullptr)
    {
        CloseHandle(profileToken_);
    }
    if (thread_ != nullptr)
    {
        CloseHandle(thread_);
    }
    if (process_ != nullptr)
    {
        CloseHandle(process_);
    }
    job_ = nullptr;
    process_ = nullptr;
    thread_ = nullptr;
    profileToken_ = nullptr;
    profile_ = nullptr;
}

void BrokerChildProcess::SetProcess(HANDLE process, HANDLE thread) noexcept
{
    if (thread_ != nullptr)
    {
        CloseHandle(thread_);
    }
    if (process_ != nullptr)
    {
        CloseHandle(process_);
    }
    process_ = process;
    thread_ = thread;
}

void BrokerChildProcess::SetUserProfile(HANDLE token, HANDLE profile) noexcept
{
    profileToken_ = token;
    profile_ = profile;
}

void BrokerChildProcess::SetPseudoConsoleHostReports(HANDLE exitReport, HANDLE diagnostics) noexcept
{
    CloseHandleIfPresent(exitReport_);
    CloseHandleIfPresent(diagnostics_);
    exitReport_ = exitReport;
    diagnostics_ = diagnostics;
}

DWORD CreateBrokerJob(BrokerChildProcess& child)
{
    child.Reset();
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr)
    {
        const DWORD jobError = GetLastError();
        return jobError;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
    {
        const DWORD limitError = GetLastError();
        CloseHandle(job);
        return limitError;
    }
    child.job_ = job;
    return ERROR_SUCCESS;
}

DWORD ResolveBrokerWorkingDirectory(
    std::wstring_view workingDirectory, std::wstring& resolvedDirectory)
{
    resolvedDirectory.clear();
    if (workingDirectory.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (HasNetworkOrDevicePrefix(workingDirectory))
    {
        return ERROR_BAD_PATHNAME;
    }

    const std::filesystem::path requestedDirectory(workingDirectory);
    if (!requestedDirectory.is_absolute())
    {
        return ERROR_BAD_PATHNAME;
    }

    std::error_code directoryError;
    const std::filesystem::path canonicalDirectory =
        std::filesystem::canonical(requestedDirectory, directoryError);
    if (directoryError)
    {
        return static_cast<DWORD>(directoryError.value());
    }
    if (!canonicalDirectory.is_absolute() || HasNetworkOrDevicePrefix(canonicalDirectory.native()))
    {
        return ERROR_BAD_PATHNAME;
    }
    if (!std::filesystem::is_directory(canonicalDirectory, directoryError))
    {
        return directoryError ? static_cast<DWORD>(directoryError.value()) : ERROR_DIRECTORY;
    }

    resolvedDirectory = canonicalDirectory.native();
    return ERROR_SUCCESS;
}

DWORD LaunchBrokerConsoleHost(HANDLE token, std::wstring_view accountName,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    BrokerChildProcess& child)
{
    if (token == nullptr || accountName.empty() || arguments.empty() || arguments.front().empty() ||
        workingDirectory.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    std::wstring directory;
    const DWORD workingDirectoryError = ResolveBrokerWorkingDirectory(workingDirectory, directory);
    if (workingDirectoryError != ERROR_SUCCESS)
    {
        return workingDirectoryError;
    }
    const DWORD jobError = CreateBrokerJob(child);
    if (jobError != ERROR_SUCCESS)
    {
        return jobError;
    }
    EnabledProcessPrivileges privileges;
    const DWORD privilegeError = privileges.EnableRequired();
    if (privilegeError != ERROR_SUCCESS)
    {
        child.Reset();
        return privilegeError;
    }
    std::wstring conhostPath;
    const DWORD conhostError = GetBrokerConhostExecutablePath(conhostPath);
    if (conhostError != ERROR_SUCCESS)
    {
        child.Reset();
        return conhostError;
    }
    std::wstring commandLine = BuildWindowsCommandLine(conhostPath, arguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    DWORD handleError = ERROR_SUCCESS;
    HANDLE nullInput = CreateInheritableNullInput(handleError);
    HANDLE exitReportRead = nullptr;
    HANDLE exitReportWrite = nullptr;
    HANDLE diagnosticsRead = nullptr;
    HANDLE diagnosticsWrite = nullptr;
    if (nullInput == nullptr ||
        !CreateBrokerReportPipe(
            exitReportRead, exitReportWrite, sizeof(PseudoConsoleHostExitReport), handleError) ||
        !CreateBrokerReportPipe(diagnosticsRead, diagnosticsWrite, 64 * 1024, handleError))
    {
        CloseHandleIfPresent(nullInput);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(exitReportWrite);
        CloseHandleIfPresent(diagnosticsRead);
        CloseHandleIfPresent(diagnosticsWrite);
        child.Reset();
        return handleError;
    }
    SIZE_T attributeListBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListBytes);
    const DWORD attributeListSizeError = GetLastError();
    if (attributeListBytes == 0)
    {
        CloseHandleIfPresent(nullInput);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(exitReportWrite);
        CloseHandleIfPresent(diagnosticsRead);
        CloseHandleIfPresent(diagnosticsWrite);
        child.Reset();
        return attributeListSizeError;
    }
    std::vector<BYTE> attributeListBuffer(attributeListBytes);
    auto* attributeList =
        reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeListBuffer.data());
    if (!InitializeProcThreadAttributeList(attributeList, 1, 0, &attributeListBytes))
    {
        const DWORD attributeListError = GetLastError();
        CloseHandleIfPresent(nullInput);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(exitReportWrite);
        CloseHandleIfPresent(diagnosticsRead);
        CloseHandleIfPresent(diagnosticsWrite);
        child.Reset();
        return attributeListError;
    }
    std::array<HANDLE, 3> inheritedHandles {nullInput, exitReportWrite, diagnosticsWrite};
    if (!UpdateProcThreadAttribute(attributeList,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inheritedHandles.data(),
            sizeof(inheritedHandles),
            nullptr,
            nullptr))
    {
        const DWORD attributeError = GetLastError();
        DeleteProcThreadAttributeList(attributeList);
        CloseHandleIfPresent(nullInput);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(exitReportWrite);
        CloseHandleIfPresent(diagnosticsRead);
        CloseHandleIfPresent(diagnosticsWrite);
        child.Reset();
        return attributeError;
    }
    STARTUPINFOEXW startupInfo {};
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.StartupInfo.hStdInput = nullInput;
    startupInfo.StartupInfo.hStdOutput = exitReportWrite;
    startupInfo.StartupInfo.hStdError = diagnosticsWrite;
    startupInfo.lpAttributeList = attributeList;
    PROCESS_INFORMATION processInfo {};
    std::wstring mutableAccountName(accountName);
    PROFILEINFOW profileInfo {};
    profileInfo.dwSize = sizeof(profileInfo);
    profileInfo.lpUserName = mutableAccountName.data();
    if (!LoadUserProfileW(token, &profileInfo))
    {
        const DWORD profileError = GetLastError();
        DeleteProcThreadAttributeList(attributeList);
        CloseHandleIfPresent(nullInput);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(exitReportWrite);
        CloseHandleIfPresent(diagnosticsRead);
        CloseHandleIfPresent(diagnosticsWrite);
        child.Reset();
        return profileError;
    }
    UserEnvironmentBlock environment;
    const DWORD environmentError = environment.Create(token);
    if (environmentError != ERROR_SUCCESS)
    {
        DeleteProcThreadAttributeList(attributeList);
        CloseHandleIfPresent(nullInput);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(exitReportWrite);
        CloseHandleIfPresent(diagnosticsRead);
        CloseHandleIfPresent(diagnosticsWrite);
        UnloadUserProfile(token, profileInfo.hProfile);
        child.Reset();
        return environmentError;
    }
    const BOOL created = CreateProcessAsUserW(token,
        conhostPath.c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
            EXTENDED_STARTUPINFO_PRESENT,
        environment.get(),
        directory.c_str(),
        &startupInfo.StartupInfo,
        &processInfo);
    const DWORD processError = created ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(attributeList);
    if (!created)
    {
        CloseHandleIfPresent(nullInput);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(exitReportWrite);
        CloseHandleIfPresent(diagnosticsRead);
        CloseHandleIfPresent(diagnosticsWrite);
        UnloadUserProfile(token, profileInfo.hProfile);
        child.Reset();
        return processError;
    }
    CloseHandleIfPresent(nullInput);
    CloseHandleIfPresent(exitReportWrite);
    CloseHandleIfPresent(diagnosticsWrite);
    if (!AssignProcessToJobObject(child.job_, processInfo.hProcess))
    {
        const DWORD assignmentError = GetLastError();
        if (TerminateProcess(processInfo.hProcess, ERROR_CANCELLED))
        {
            static_cast<void>(WaitForSingleObject(processInfo.hProcess, INFINITE));
        }
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(diagnosticsRead);
        UnloadUserProfile(token, profileInfo.hProfile);
        child.Reset();
        return assignmentError;
    }
    HANDLE profileToken = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(),
            token,
            GetCurrentProcess(),
            &profileToken,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS))
    {
        const DWORD duplicateError = GetLastError();
        if (TerminateProcess(processInfo.hProcess, ERROR_CANCELLED))
        {
            static_cast<void>(WaitForSingleObject(processInfo.hProcess, INFINITE));
        }
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        CloseHandleIfPresent(exitReportRead);
        CloseHandleIfPresent(diagnosticsRead);
        UnloadUserProfile(token, profileInfo.hProfile);
        child.Reset();
        return duplicateError;
    }
    child.SetProcess(processInfo.hProcess, processInfo.hThread);
    child.SetUserProfile(profileToken, profileInfo.hProfile);
    child.SetPseudoConsoleHostReports(exitReportRead, diagnosticsRead);
    return ERROR_SUCCESS;
}

DWORD LaunchFixedBrokerProbe(HANDLE token, BrokerChildProcess& child)
{
    if (token == nullptr)
    {
        return ERROR_INVALID_HANDLE;
    }
    const DWORD jobError = CreateBrokerJob(child);
    if (jobError != ERROR_SUCCESS)
    {
        return jobError;
    }
    EnabledProcessPrivileges privileges;
    const DWORD privilegeError = privileges.EnableRequired();
    if (privilegeError != ERROR_SUCCESS)
    {
        child.Reset();
        return privilegeError;
    }
    std::wstring executablePath;
    const DWORD executableError = GetProbeExecutablePath(executablePath);
    if (executableError != ERROR_SUCCESS)
    {
        child.Reset();
        return executableError;
    }
    std::wstring commandLine = L"\"" + executablePath + L"\" /d /c timeout /t 30 /nobreak >nul";
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo {};
    if (!CreateProcessAsUserW(token,
            executablePath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo))
    {
        const DWORD processError = GetLastError();
        child.Reset();
        return processError;
    }
    if (!AssignProcessToJobObject(child.job_, processInfo.hProcess))
    {
        const DWORD assignmentError = GetLastError();
        if (TerminateProcess(processInfo.hProcess, ERROR_CANCELLED))
        {
            static_cast<void>(WaitForSingleObject(processInfo.hProcess, INFINITE));
        }
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        child.Reset();
        return assignmentError;
    }
    child.SetProcess(processInfo.hProcess, processInfo.hThread);
    const DWORD resumeError = child.Resume();
    if (resumeError != ERROR_SUCCESS)
    {
        static_cast<void>(child.TerminateAndWaitForExit());
    }
    return resumeError;
}

DWORD GetTokenLogonSid(HANDLE token, std::vector<BYTE>& logonSid)
{
    logonSid.clear();
    if (token == nullptr)
    {
        return ERROR_INVALID_HANDLE;
    }
    DWORD groupBytes = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &groupBytes);
    const DWORD sizeError = GetLastError();
    if (sizeError != ERROR_INSUFFICIENT_BUFFER || groupBytes == 0)
    {
        return sizeError;
    }
    std::vector<BYTE> groups(groupBytes);
    if (!GetTokenInformation(token, TokenGroups, groups.data(), groupBytes, &groupBytes))
    {
        const DWORD groupsError = GetLastError();
        return groupsError;
    }
    const auto* tokenGroups = reinterpret_cast<const TOKEN_GROUPS*>(groups.data());
    for (DWORD index = 0; index < tokenGroups->GroupCount; ++index)
    {
        const SID_AND_ATTRIBUTES& group = tokenGroups->Groups[index];
        if ((group.Attributes & SE_GROUP_LOGON_ID) != 0)
        {
            return CopyValidSid(group.Sid, logonSid) ? ERROR_SUCCESS : ERROR_INVALID_SID;
        }
    }
    return ERROR_NOT_FOUND;
}

DWORD ValidateChildLogonSid(HANDLE process, const std::vector<BYTE>& callerLogonSid)
{
    if (process == nullptr || callerLogonSid.empty() ||
        !IsValidSid(const_cast<BYTE*>(callerLogonSid.data())))
    {
        return ERROR_INVALID_SID;
    }
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
    {
        const DWORD tokenError = GetLastError();
        return tokenError;
    }
    std::vector<BYTE> childLogonSid;
    const DWORD logonSidError = GetTokenLogonSid(token, childLogonSid);
    CloseHandle(token);
    if (logonSidError != ERROR_SUCCESS)
    {
        return logonSidError;
    }
    return EqualSid(const_cast<BYTE*>(callerLogonSid.data()), childLogonSid.data()) != FALSE
               ? ERROR_ACCESS_DENIED
               : ERROR_SUCCESS;
}

} // namespace launch_as::broker
