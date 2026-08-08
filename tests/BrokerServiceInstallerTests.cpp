// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerServiceInstaller.h"
#include "Win32Support.h"

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

namespace
{

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
    SC_HANDLE value_;
};

class TestService final
{
  public:
    explicit TestService(std::wstring name) : name_(std::move(name)) {}

    ~TestService()
    {
        ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        ServiceHandle service(
            manager ? OpenServiceW(manager.get(), name_.c_str(), DELETE) : nullptr);
        if (service)
        {
            DeleteService(service.get());
        }
    }

    [[nodiscard]] const std::wstring& name() const noexcept { return name_; }

  private:
    std::wstring name_;
};

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] bool HasExpectedConfiguration(
    const std::wstring& name, const std::wstring& executablePath)
{
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    ServiceHandle service(
        manager ? OpenServiceW(manager.get(), name.c_str(), SERVICE_QUERY_CONFIG) : nullptr);
    DWORD requiredBytes = 0;
    QueryServiceConfigW(service.get(), nullptr, 0, &requiredBytes);
    if (!service || GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredBytes == 0)
    {
        return false;
    }
    std::vector<BYTE> buffer(requiredBytes);
    auto* configuration = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (!QueryServiceConfigW(service.get(), configuration, requiredBytes, &requiredBytes))
    {
        return false;
    }
    return configuration->dwStartType == SERVICE_DEMAND_START &&
           std::wstring_view(configuration->lpServiceStartName) == L"LocalSystem" &&
           std::wstring_view(configuration->lpBinaryPathName) == L"\"" + executablePath + L"\"";
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 2)
    {
        std::wcerr << L"Expected the broker executable path.\n";
        return 1;
    }
    TestService service(L"launch-as-broker-test-" + std::to_wstring(GetCurrentProcessId()));
    const DWORD installError =
        launch_as::broker::InstallDemandStartBrokerService(service.name(), arguments[1]);
    if (!Expect(installError == ERROR_SUCCESS, L"Could not install the disposable service."))
    {
        std::wcerr << L"Installer status: " << installError << L"\n";
        return 1;
    }
    return Expect(HasExpectedConfiguration(service.name(), arguments[1]),
               L"Disposable service configuration does not match the broker contract.")
               ? 0
               : 1;
}
