// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerProcessLauncher.h"

#include "InteractiveDesktopLeaseClient.h"
#include "PseudoConsoleHostReport.h"
#include "Utf8.h"
#include "Win32Support.h"
#include "WindowsCommandLine.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <userenv.h>
#include <utility>
#include <vector>

namespace launch_as::broker
{
namespace
{

constexpr DWORD JobTerminationTimeoutMilliseconds = 5'000;

#ifdef LAUNCH_AS_TESTING
bool failBrokerJobQueryForTesting = false;
thread_local void (*sessionAssignmentObserverForTesting)() = nullptr;
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
            AdjustTokenPrivileges(token_.get(), FALSE, &previous_[index], 0, nullptr, nullptr);
        }
    }

    [[nodiscard]] DWORD EnableRequired()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            const DWORD tokenError = GetLastError();
            return tokenError;
        }
        token_.reset(token);
        // LoadUserProfileW requires backup and restore rights; CreateProcessAsUserW requires the
        // token-assignment and quota rights below. Enable them only for this launch operation.
        const DWORD backupError = Enable(SE_BACKUP_NAME);
        if (backupError != ERROR_SUCCESS)
        {
            return backupError;
        }
        const DWORD restoreError = Enable(SE_RESTORE_NAME);
        if (restoreError != ERROR_SUCCESS)
        {
            return restoreError;
        }
        const DWORD assignTokenError = Enable(SE_ASSIGNPRIMARYTOKEN_NAME);
        if (assignTokenError != ERROR_SUCCESS)
        {
            return assignTokenError;
        }
        const DWORD quotaError = Enable(SE_INCREASE_QUOTA_NAME);
        if (quotaError != ERROR_SUCCESS)
        {
            return quotaError;
        }
        return ERROR_SUCCESS;
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
        if (!AdjustTokenPrivileges(token_.get(),
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

    UniqueHandle token_;
    std::array<TOKEN_PRIVILEGES, 4> previous_ {};
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

#ifdef LAUNCH_AS_TESTING
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
#endif

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

class LoadedUserProfile final
{
  public:
    LoadedUserProfile() = default;
    ~LoadedUserProfile()
    {
        if (profile_ != nullptr)
        {
            UnloadUserProfile(token_, profile_);
        }
    }

    LoadedUserProfile(const LoadedUserProfile&) = delete;
    LoadedUserProfile& operator=(const LoadedUserProfile&) = delete;

    [[nodiscard]] DWORD Load(HANDLE token, std::wstring_view accountName)
    {
        std::wstring mutableAccountName(accountName);
        PROFILEINFOW profileInfo {};
        profileInfo.dwSize = sizeof(profileInfo);
        profileInfo.lpUserName = mutableAccountName.data();
        if (!LoadUserProfileW(token, &profileInfo))
        {
            const DWORD profileError = GetLastError();
            return profileError;
        }
        token_ = token;
        profile_ = profileInfo.hProfile;
        return ERROR_SUCCESS;
    }

    [[nodiscard]] HANDLE release() noexcept { return std::exchange(profile_, nullptr); }

  private:
    HANDLE token_ = nullptr;
    HANDLE profile_ = nullptr;
};

// Owns a process created suspended until it is handed over; otherwise terminates it.
class SuspendedProcess final
{
  public:
    SuspendedProcess() = default;
    ~SuspendedProcess() { reset(); }

    SuspendedProcess(const SuspendedProcess&) = delete;
    SuspendedProcess& operator=(const SuspendedProcess&) = delete;

    void reset() noexcept
    {
        if (information_.hProcess != nullptr)
        {
            if (TerminateProcess(information_.hProcess, ERROR_CANCELLED))
            {
                static_cast<void>(WaitForSingleObject(information_.hProcess, INFINITE));
            }
            CloseHandle(information_.hThread);
            CloseHandle(information_.hProcess);
        }
        information_ = {};
    }

    [[nodiscard]] PROCESS_INFORMATION* out() noexcept { return &information_; }
    [[nodiscard]] HANDLE process() const noexcept { return information_.hProcess; }
    [[nodiscard]] PROCESS_INFORMATION release() noexcept
    {
        return std::exchange(information_, PROCESS_INFORMATION {});
    }

  private:
    PROCESS_INFORMATION information_ {};
};

class ProcThreadAttributeList final
{
  public:
    ProcThreadAttributeList() = default;
    ~ProcThreadAttributeList()
    {
        if (initialized_)
        {
            DeleteProcThreadAttributeList(get());
        }
    }

    ProcThreadAttributeList(const ProcThreadAttributeList&) = delete;
    ProcThreadAttributeList& operator=(const ProcThreadAttributeList&) = delete;

    [[nodiscard]] DWORD Initialize(DWORD attributeCount)
    {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, attributeCount, 0, &bytes);
        const DWORD sizeError = GetLastError();
        if (bytes == 0)
        {
            return sizeError;
        }
        buffer_.resize(bytes);
        if (!InitializeProcThreadAttributeList(get(), attributeCount, 0, &bytes))
        {
            const DWORD initializeError = GetLastError();
            return initializeError;
        }
        initialized_ = true;
        return ERROR_SUCCESS;
    }

    [[nodiscard]] LPPROC_THREAD_ATTRIBUTE_LIST get() noexcept
    {
        return reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer_.data());
    }

  private:
    std::vector<BYTE> buffer_;
    bool initialized_ = false;
};

[[nodiscard]] DWORD CreateBrokerReportPipe(
    UniqueHandle& readEnd, UniqueHandle& writeEnd, DWORD bufferSize)
{
    SECURITY_ATTRIBUTES attributes {};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE rawRead = nullptr;
    HANDLE rawWrite = nullptr;
    if (!CreatePipe(&rawRead, &rawWrite, &attributes, bufferSize))
    {
        const DWORD pipeError = GetLastError();
        return pipeError;
    }
    readEnd.reset(rawRead);
    writeEnd.reset(rawWrite);
    if (!SetHandleInformation(readEnd.get(), HANDLE_FLAG_INHERIT, 0))
    {
        const DWORD inheritError = GetLastError();
        readEnd.reset();
        writeEnd.reset();
        return inheritError;
    }
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD CreateInheritableNullInput(UniqueHandle& input)
{
    SECURITY_ATTRIBUTES attributes {};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE rawInput = CreateFileW(L"NUL",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &attributes,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (rawInput == INVALID_HANDLE_VALUE)
    {
        const DWORD inputError = GetLastError();
        return inputError;
    }
    input.reset(rawInput);
    return ERROR_SUCCESS;
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

DWORD DisableBrokerProcessTcbPrivilege()
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &rawToken))
    {
        return GetLastError();
    }
    const UniqueHandle token(rawToken);
    TOKEN_PRIVILEGES requested {};
    requested.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_TCB_NAME, &requested.Privileges[0].Luid))
    {
        const DWORD lookupError = GetLastError();
        return lookupError;
    }
    // LocalSystem starts with TCB enabled. Keep it present for private thread-token copies,
    // but permanently disable it on the process token before any workers can use that token.
    if (!AdjustTokenPrivileges(token.get(), FALSE, &requested, 0, nullptr, nullptr))
    {
        const DWORD adjustmentError = GetLastError();
        return adjustmentError;
    }
    const DWORD adjustmentError = GetLastError();
    return adjustmentError;
}

DWORD SetBrokerTokenSessionId(HANDLE token, DWORD sessionId)
{
    // Session assignment runs only after caller impersonation has ended. Do not replace an
    // existing thread identity, or enable TCB on the process token shared by other workers.
    HANDLE existingToken = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &existingToken))
    {
        CloseHandle(existingToken);
        return ERROR_BAD_IMPERSONATION_LEVEL;
    }
    const DWORD threadTokenError = GetLastError();
    if (threadTokenError != ERROR_NO_TOKEN)
    {
        return threadTokenError;
    }
    if (!ImpersonateSelf(SecurityImpersonation))
    {
        return GetLastError();
    }
    struct RevertOnExit final
    {
        ~RevertOnExit()
        {
            if (!RevertToSelf())
            {
                // Never continue a service worker with the temporary privileged identity.
                RaiseFailFastException(nullptr, nullptr, 0);
            }
        }
    } revertOnExit;

    HANDLE rawThreadToken = nullptr;
    if (!OpenThreadToken(
            GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, TRUE, &rawThreadToken))
    {
        return GetLastError();
    }
    UniqueHandle threadToken(rawThreadToken);
    TOKEN_PRIVILEGES requested {};
    requested.PrivilegeCount = 1;
    requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(nullptr, SE_TCB_NAME, &requested.Privileges[0].Luid))
    {
        const DWORD lookupError = GetLastError();
        return lookupError;
    }
    const BOOL adjusted =
        AdjustTokenPrivileges(threadToken.get(), FALSE, &requested, 0, nullptr, nullptr);
    const DWORD adjustmentError = GetLastError();
    threadToken.reset();
    if (!adjusted || adjustmentError != ERROR_SUCCESS)
    {
        return adjustmentError;
    }
#ifdef LAUNCH_AS_TESTING
    if (sessionAssignmentObserverForTesting != nullptr)
    {
        sessionAssignmentObserverForTesting();
    }
#endif
    return SetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId))
               ? ERROR_SUCCESS
               : GetLastError();
}

#ifdef LAUNCH_AS_TESTING
void SetBrokerSessionAssignmentObserverForTesting(void (*observer)()) noexcept
{
    sessionAssignmentObserverForTesting = observer;
}

void SetBrokerJobQueryFailureForTesting(bool fail) noexcept { failBrokerJobQueryForTesting = fail; }

[[nodiscard]] DWORD LaunchBrokerChildForTesting(
    std::wstring_view command, BrokerChildProcess& child)
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
    std::wstring commandLine = L"\"" + executablePath + L"\" /d /c " + std::wstring(command);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    {
        SuspendedProcess process;
        if (!CreateProcessW(executablePath.c_str(),
                mutableCommandLine.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                nullptr,
                nullptr,
                &startupInfo,
                process.out()))
        {
            const DWORD processError = GetLastError();
            child.Reset();
            return processError;
        }
        if (!AssignProcessToJobObject(child.job_.get(), process.process()))
        {
            const DWORD assignmentError = GetLastError();
            process.reset();
            child.Reset();
            return assignmentError;
        }
        const PROCESS_INFORMATION processInfo = process.release();
        child.process_.reset(processInfo.hProcess);
        child.thread_.reset(processInfo.hThread);
    }
    const DWORD resumeError = child.Resume();
    if (resumeError != ERROR_SUCCESS)
    {
        child.TerminateAndWaitForExitConfirmed();
    }
    return resumeError;
}

DWORD LaunchQuickBrokerChildForTesting(BrokerChildProcess& child)
{
    return LaunchBrokerChildForTesting(L"exit 0", child);
}

DWORD LaunchDelayedBrokerChildForTesting(BrokerChildProcess& child)
{
    return LaunchBrokerChildForTesting(L"ping -n 2 127.0.0.1 >nul", child);
}
#endif

BrokerChildProcess::~BrokerChildProcess() { Reset(); }

HANDLE BrokerChildProcess::job() const noexcept { return job_.get(); }

HANDLE BrokerChildProcess::process() const noexcept { return process_.get(); }

DWORD BrokerChildProcess::processId() const noexcept
{
    return process_ ? GetProcessId(process_.get()) : 0;
}

BrokerChildProcess::operator bool() const noexcept { return job_ && process_ && thread_; }

DWORD BrokerChildProcess::Resume() noexcept
{
    if (!thread_)
    {
        return ERROR_INVALID_HANDLE;
    }
    const DWORD suspendedCount = ResumeThread(thread_.get());
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
    if (!exitReport_ || !diagnostics_)
    {
        return false;
    }

    PseudoConsoleHostExitReport report {};
    std::size_t bytesRead = 0;
    while (bytesRead < sizeof(report))
    {
        DWORD received = 0;
        if (!ReadFile(exitReport_.get(),
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
        if (!ReadFile(diagnostics_.get(),
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &received,
                nullptr))
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
        if (!Utf8ToWide(diagnosticBytes, diagnostics))
        {
            diagnostics = L"The console host emitted invalid UTF-8 diagnostics.";
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
    if (!job_)
    {
        Reset();
        return true;
    }
    const ULONGLONG deadline = GetTickCount64() + JobTerminationTimeoutMilliseconds;
    static_cast<void>(TerminateJobObject(job_.get(), ERROR_CANCELLED));
    if (process_)
    {
        const ULONGLONG now = GetTickCount64();
        const DWORD remaining = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
        if (WaitForSingleObject(process_.get(), remaining) != WAIT_OBJECT_0)
        {
            return false;
        }
    }
    const ULONGLONG now = GetTickCount64();
    const DWORD remaining = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
    const bool processTreeExited = WaitForProcessTreeExit(remaining);
    if (processTreeExited)
    {
        Reset();
    }
    return processTreeExited;
}

void BrokerChildProcess::TerminateAndWaitForExitConfirmed() noexcept
{
    while (!TerminateAndWaitForExit())
    {
        Sleep(100);
    }
}

bool BrokerChildProcess::WaitForProcessTreeExit(DWORD timeoutMilliseconds) const noexcept
{
    if (!job_)
    {
        return false;
    }
    const ULONGLONG deadline =
        timeoutMilliseconds == INFINITE ? 0 : GetTickCount64() + timeoutMilliseconds;
    for (;;)
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting {};
        if (!QueryBrokerJobBasicAccountingInformation(job_.get(), accounting))
        {
            return false;
        }
        if (accounting.ActiveProcesses == 0)
        {
            return true;
        }
        const ULONGLONG now = GetTickCount64();
        if (timeoutMilliseconds != INFINITE && now >= deadline)
        {
            return false;
        }
        const DWORD remaining =
            timeoutMilliseconds == INFINITE ? 10 : static_cast<DWORD>(deadline - now);
        Sleep(remaining < 10 ? remaining : 10);
    }
}

void BrokerChildProcess::Reset() noexcept
{
    exitReport_.reset();
    diagnostics_.reset();
    job_.reset();
    if (profile_ != nullptr)
    {
        UnloadUserProfile(profileToken_.get(), profile_);
        profile_ = nullptr;
    }
    profileToken_.reset();
    thread_.reset();
    process_.reset();
}

DWORD CreateBrokerJob(BrokerChildProcess& child)
{
    child.Reset();
    UniqueHandle job(CreateJobObjectW(nullptr, nullptr));
    if (!job)
    {
        const DWORD jobError = GetLastError();
        return jobError;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(
            job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
    {
        const DWORD limitError = GetLastError();
        return limitError;
    }
    child.job_ = std::move(job);
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

DWORD BrokerChildProcess::CreateSuspendedInJob(HANDLE token, std::wstring_view accountName,
    const std::wstring& executable, std::vector<wchar_t>& commandLine,
    const std::wstring& directory, BOOL inheritHandles, DWORD creationFlags,
    STARTUPINFOW& startupInfo)
{
    // Declaration order is cleanup order on failure: terminate the process before unloading the
    // profile it was created with.
    LoadedUserProfile profile;
    const DWORD profileError = profile.Load(token, accountName);
    if (profileError != ERROR_SUCCESS)
    {
        return profileError;
    }
    UserEnvironmentBlock environment;
    const DWORD environmentError = environment.Create(token);
    if (environmentError != ERROR_SUCCESS)
    {
        return environmentError;
    }
    SuspendedProcess process;
    if (!CreateProcessAsUserW(token,
            executable.c_str(),
            commandLine.data(),
            nullptr,
            nullptr,
            inheritHandles,
            creationFlags | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            environment.get(),
            directory.c_str(),
            &startupInfo,
            process.out()))
    {
        const DWORD processError = GetLastError();
        return processError;
    }
    if (!AssignProcessToJobObject(job_.get(), process.process()))
    {
        const DWORD assignmentError = GetLastError();
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
        return duplicateError;
    }
    const PROCESS_INFORMATION processInfo = process.release();
    process_.reset(processInfo.hProcess);
    thread_.reset(processInfo.hThread);
    profileToken_.reset(profileToken);
    profile_ = profile.release();
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
    const DWORD launchError = [&]() -> DWORD
    {
        EnabledProcessPrivileges privileges;
        const DWORD privilegeError = privileges.EnableRequired();
        if (privilegeError != ERROR_SUCCESS)
        {
            return privilegeError;
        }
        std::wstring conhostPath;
        const DWORD conhostError = GetBrokerConhostExecutablePath(conhostPath);
        if (conhostError != ERROR_SUCCESS)
        {
            return conhostError;
        }
        std::wstring commandLine = BuildWindowsCommandLine(conhostPath, arguments);
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');
        UniqueHandle nullInput;
        UniqueHandle exitReportRead;
        UniqueHandle exitReportWrite;
        UniqueHandle diagnosticsRead;
        UniqueHandle diagnosticsWrite;
        DWORD handleError = CreateInheritableNullInput(nullInput);
        if (handleError == ERROR_SUCCESS)
        {
            handleError = CreateBrokerReportPipe(
                exitReportRead, exitReportWrite, sizeof(PseudoConsoleHostExitReport));
        }
        if (handleError == ERROR_SUCCESS)
        {
            handleError = CreateBrokerReportPipe(diagnosticsRead, diagnosticsWrite, 64 * 1024);
        }
        if (handleError != ERROR_SUCCESS)
        {
            return handleError;
        }
        ProcThreadAttributeList attributeList;
        const DWORD attributeListError = attributeList.Initialize(1);
        if (attributeListError != ERROR_SUCCESS)
        {
            return attributeListError;
        }
        std::array<HANDLE, 3> inheritedHandles {
            nullInput.get(), exitReportWrite.get(), diagnosticsWrite.get()
        };
        if (!UpdateProcThreadAttribute(attributeList.get(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inheritedHandles.data(),
                sizeof(inheritedHandles),
                nullptr,
                nullptr))
        {
            const DWORD attributeError = GetLastError();
            return attributeError;
        }
        STARTUPINFOEXW startupInfo {};
        startupInfo.StartupInfo.cb = sizeof(startupInfo);
        startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startupInfo.StartupInfo.hStdInput = nullInput.get();
        startupInfo.StartupInfo.hStdOutput = exitReportWrite.get();
        startupInfo.StartupInfo.hStdError = diagnosticsWrite.get();
        startupInfo.lpAttributeList = attributeList.get();
        const DWORD processError = child.CreateSuspendedInJob(token,
            accountName,
            conhostPath,
            mutableCommandLine,
            directory,
            TRUE,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            startupInfo.StartupInfo);
        if (processError != ERROR_SUCCESS)
        {
            return processError;
        }
        child.exitReport_ = std::move(exitReportRead);
        child.diagnostics_ = std::move(diagnosticsRead);
        return ERROR_SUCCESS;
    }();
    if (launchError != ERROR_SUCCESS)
    {
        child.Reset();
    }
    return launchError;
}

DWORD LaunchBrokerInteractiveProcess(HANDLE token, std::wstring_view accountName,
    std::span<const std::wstring> arguments, std::wstring_view workingDirectory,
    DWORD targetSessionId, std::wstring_view leasePipeName, std::wstring_view leaseNonce,
    const std::vector<BYTE>& callerLogonSid, BrokerChildProcess& child,
    InteractiveDesktopLeaseConnection& lease)
{
    child.Reset();
    lease.Reset();
    if (token == nullptr || accountName.empty() || arguments.empty() || arguments.front().empty() ||
        arguments.front().find(L'"') != std::wstring::npos || workingDirectory.empty() ||
        targetSessionId == 0 || targetSessionId == MAXDWORD || leasePipeName.empty() ||
        leaseNonce.empty() || callerLogonSid.empty() ||
        !IsValidSid(const_cast<BYTE*>(callerLogonSid.data())))
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
    const DWORD sessionError = SetBrokerTokenSessionId(token, targetSessionId);
    if (sessionError != ERROR_SUCCESS)
    {
        child.Reset();
        return sessionError;
    }
    EnabledProcessPrivileges privileges;
    const DWORD privilegeError = privileges.EnableRequired();
    if (privilegeError != ERROR_SUCCESS)
    {
        child.Reset();
        return privilegeError;
    }
    std::vector<BYTE> childLogonSid;
    const DWORD logonSidError = GetTokenLogonSid(token, childLogonSid);
    if (logonSidError != ERROR_SUCCESS)
    {
        child.Reset();
        return logonSidError;
    }
    if (EqualSid(const_cast<BYTE*>(callerLogonSid.data()), childLogonSid.data()) != FALSE)
    {
        child.Reset();
        return ERROR_ACCESS_DENIED;
    }
    const DWORD acquireError =
        AcquireInteractiveDesktopLease(leasePipeName, leaseNonce, childLogonSid.data(), lease);
    if (acquireError != ERROR_SUCCESS)
    {
        child.Reset();
        return acquireError;
    }
    const auto releaseAfterFailure = [&](DWORD error)
    {
        const DWORD releaseError = ReleaseInteractiveDesktopLease(lease);
        return releaseError == ERROR_SUCCESS ? error : releaseError;
    };

    std::wstring executable(arguments.front());
    const std::span<const std::wstring> targetArguments = arguments.subspan(1);
    std::wstring commandLine = BuildWindowsCommandLine(executable, targetArguments);
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    std::wstring desktopName = L"WinSta0\\Default";
    STARTUPINFOW startupInfo {};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = desktopName.data();
    const DWORD processError = child.CreateSuspendedInJob(
        token, accountName, executable, mutableCommandLine, directory, FALSE, 0, startupInfo);
    if (processError != ERROR_SUCCESS)
    {
        child.Reset();
        return releaseAfterFailure(processError);
    }

    HANDLE rawChildToken = nullptr;
    if (!OpenProcessToken(child.process(), TOKEN_QUERY, &rawChildToken))
    {
        const DWORD childTokenError = GetLastError();
        child.TerminateAndWaitForExitConfirmed();
        return releaseAfterFailure(childTokenError);
    }
    UniqueHandle childToken(rawChildToken);
    std::vector<BYTE> launchedLogonSid;
    const DWORD launchedLogonSidError = GetTokenLogonSid(childToken.get(), launchedLogonSid);
    DWORD launchedSessionId = MAXDWORD;
    DWORD returnedBytes = 0;
    const BOOL readSession = GetTokenInformation(childToken.get(),
        TokenSessionId,
        &launchedSessionId,
        sizeof(launchedSessionId),
        &returnedBytes);
    const DWORD launchedSessionError = readSession ? ERROR_SUCCESS : GetLastError();
    childToken.reset();
    const bool identityMatches =
        launchedLogonSidError == ERROR_SUCCESS &&
        EqualSid(childLogonSid.data(), launchedLogonSid.data()) != FALSE &&
        EqualSid(const_cast<BYTE*>(callerLogonSid.data()), launchedLogonSid.data()) == FALSE;
    if (!identityMatches || launchedSessionError != ERROR_SUCCESS ||
        returnedBytes != sizeof(launchedSessionId) || launchedSessionId != targetSessionId)
    {
        child.TerminateAndWaitForExitConfirmed();
        const DWORD validationError = launchedLogonSidError != ERROR_SUCCESS ? launchedLogonSidError
                                      : launchedSessionError != ERROR_SUCCESS ? launchedSessionError
                                                                              : ERROR_ACCESS_DENIED;
        return releaseAfterFailure(validationError);
    }
    return ERROR_SUCCESS;
}

DWORD GetTokenLogonSid(HANDLE token, std::vector<BYTE>& logonSid)
{
    logonSid.clear();
    if (token == nullptr)
    {
        return ERROR_INVALID_HANDLE;
    }
    std::vector<BYTE> groups;
    const DWORD groupsError = QueryTokenInformation(token, TokenGroups, groups);
    if (groupsError != ERROR_SUCCESS)
    {
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
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &rawToken))
    {
        const DWORD tokenError = GetLastError();
        return tokenError;
    }
    const UniqueHandle token(rawToken);
    std::vector<BYTE> childLogonSid;
    const DWORD logonSidError = GetTokenLogonSid(token.get(), childLogonSid);
    if (logonSidError != ERROR_SUCCESS)
    {
        return logonSidError;
    }
    return EqualSid(const_cast<BYTE*>(callerLogonSid.data()), childLogonSid.data()) != FALSE
               ? ERROR_ACCESS_DENIED
               : ERROR_SUCCESS;
}

} // namespace launch_as::broker
