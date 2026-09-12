// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerControlPipe.h"

#include "BrokerProtocol.h"

#include <Windows.h>
#include <array>

namespace launch_as::broker
{
namespace
{

constexpr wchar_t ServiceName[] = L"launch-as-broker";
constexpr DWORD BrokerStartTimeoutMilliseconds = 5'000;

class ServiceHandle final
{
  public:
    explicit ServiceHandle(SC_HANDLE value = nullptr) noexcept : value_(value) {}
    ~ServiceHandle()
    {
        if (value_ != nullptr)
        {
            CloseServiceHandle(value_);
        }
    }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }

  private:
    SC_HANDLE value_ = nullptr;
};

[[nodiscard]] DWORD StartBrokerService()
{
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager)
    {
        const DWORD managerError = GetLastError();
        return managerError;
    }
    ServiceHandle service(OpenServiceW(manager.get(), ServiceName, SERVICE_START));
    if (!service)
    {
        const DWORD serviceError = GetLastError();
        return serviceError;
    }
    if (StartServiceW(service.get(), 0, nullptr))
    {
        return ERROR_SUCCESS;
    }
    const DWORD startError = GetLastError();
    return startError == ERROR_SERVICE_ALREADY_RUNNING ? ERROR_SUCCESS : startError;
}

} // namespace

DWORD OpenBrokerControlPipe(HANDLE& pipe)
{
    pipe = nullptr;
    bool serviceStartAttempted = false;
    const ULONGLONG deadline = GetTickCount64() + BrokerStartTimeoutMilliseconds;
    DWORD lastError = ERROR_FILE_NOT_FOUND;
    do
    {
        HANDLE rawPipe = CreateFileW(ControlPipeName.data(),
            ControlPipeClientAccess,
            0,
            nullptr,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr);
        if (rawPipe != INVALID_HANDLE_VALUE)
        {
            pipe = rawPipe;
            return ERROR_SUCCESS;
        }
        lastError = GetLastError();
        if (lastError == ERROR_PIPE_BUSY)
        {
            static_cast<void>(WaitNamedPipeW(ControlPipeName.data(), 50));
            continue;
        }
        if (lastError == ERROR_FILE_NOT_FOUND && !serviceStartAttempted)
        {
            const DWORD startError = StartBrokerService();
            if (startError != ERROR_SUCCESS)
            {
                return startError;
            }
            serviceStartAttempted = true;
        }
        else if (lastError != ERROR_FILE_NOT_FOUND)
        {
            return lastError;
        }
        Sleep(50);
    } while (GetTickCount64() < deadline);
    return lastError;
}

} // namespace launch_as::broker
