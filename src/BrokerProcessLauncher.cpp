// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"

#include "WindowsCommandLine.h"

#include <array>
#include <filesystem>
#include <string>
#include <userenv.h>
#include <vector>

namespace launch_as::broker
{
namespace
{

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

} // namespace

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

void BrokerChildProcess::Reset() noexcept
{
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
    if (job_ != nullptr)
    {
        CloseHandle(job_);
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

DWORD LaunchBrokerConsoleHost(HANDLE token, std::wstring_view accountName,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    BrokerChildProcess& child)
{
    if (token == nullptr || accountName.empty() || arguments.empty() || arguments.front().empty() ||
        workingDirectory.empty())
    {
        return ERROR_INVALID_PARAMETER;
    }
    std::error_code workingDirectoryError;
    if (!std::filesystem::is_directory(
            std::filesystem::path(workingDirectory), workingDirectoryError))
    {
        return workingDirectoryError ? static_cast<DWORD>(workingDirectoryError.value())
                                     : ERROR_DIRECTORY;
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
    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo {};
    const std::wstring directory(workingDirectory);
    std::wstring mutableAccountName(accountName);
    PROFILEINFOW profileInfo {};
    profileInfo.dwSize = sizeof(profileInfo);
    profileInfo.lpUserName = mutableAccountName.data();
    if (!LoadUserProfileW(token, &profileInfo))
    {
        const DWORD profileError = GetLastError();
        child.Reset();
        return profileError;
    }
    UserEnvironmentBlock environment;
    const DWORD environmentError = environment.Create(token);
    if (environmentError != ERROR_SUCCESS)
    {
        UnloadUserProfile(token, profileInfo.hProfile);
        child.Reset();
        return environmentError;
    }
    if (!CreateProcessAsUserW(token,
            conhostPath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            environment.get(),
            directory.c_str(),
            &startupInfo,
            &processInfo))
    {
        const DWORD processError = GetLastError();
        UnloadUserProfile(token, profileInfo.hProfile);
        child.Reset();
        return processError;
    }
    if (!AssignProcessToJobObject(child.job_, processInfo.hProcess))
    {
        const DWORD assignmentError = GetLastError();
        TerminateProcess(processInfo.hProcess, ERROR_CANCELLED);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
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
        TerminateProcess(processInfo.hProcess, ERROR_CANCELLED);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        UnloadUserProfile(token, profileInfo.hProfile);
        child.Reset();
        return duplicateError;
    }
    child.SetProcess(processInfo.hProcess, processInfo.hThread);
    child.SetUserProfile(profileToken, profileInfo.hProfile);
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
        TerminateProcess(processInfo.hProcess, ERROR_CANCELLED);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        child.Reset();
        return assignmentError;
    }
    child.SetProcess(processInfo.hProcess, processInfo.hThread);
    const DWORD resumeError = child.Resume();
    if (resumeError != ERROR_SUCCESS)
    {
        child.Reset();
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
