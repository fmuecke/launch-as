// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"

#include <array>
#include <string>
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

void BrokerChildProcess::Reset() noexcept
{
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
    std::wstring commandLine = L"\"" + executablePath + L"\" /d /c exit 0";
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
            CREATE_NO_WINDOW,
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
    return ERROR_SUCCESS;
}

} // namespace launch_as::broker
