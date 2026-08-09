// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerServiceInstaller.h"
#include "Win32Support.h"

#include <Windows.h>
#include <array>
#include <filesystem>
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

class TemporaryDirectory final
{
  public:
    explicit TemporaryDirectory(std::filesystem::path path) : path_(std::move(path)) {}

    ~TemporaryDirectory()
    {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

  private:
    std::filesystem::path path_;
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

[[nodiscard]] bool CreateEmptyFile(const std::filesystem::path& path)
{
    const HANDLE file = CreateFileW(
        path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    CloseHandle(file);
    return true;
}

[[nodiscard]] bool FileExists(const std::filesystem::path& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES;
}

[[nodiscard]] bool VerifyInstallFilesAreRemoved()
{
    std::array<wchar_t, MAX_PATH> temporaryPath {};
    if (GetTempPathW(static_cast<DWORD>(temporaryPath.size()), temporaryPath.data()) == 0)
    {
        std::wcerr << L"Could not find a temporary directory.\n";
        return false;
    }
    std::array<wchar_t, MAX_PATH> uniquePath {};
    if (GetTempFileNameW(temporaryPath.data(), L"las", 0, uniquePath.data()) == 0 ||
        !DeleteFileW(uniquePath.data()) || !CreateDirectoryW(uniquePath.data(), nullptr))
    {
        std::wcerr << L"Could not create a temporary install directory.\n";
        return false;
    }
    const TemporaryDirectory directory(uniquePath.data());
    const std::filesystem::path broker = directory.path() / L"launch-as-broker.exe";
    const std::filesystem::path conhost = directory.path() / L"launch-as-conhost.exe";
    if (!CreateEmptyFile(broker) || !CreateEmptyFile(conhost))
    {
        std::wcerr << L"Could not create temporary broker files.\n";
        return false;
    }

    const DWORD removalError =
        launch_as::broker::RemoveBrokerInstallFiles(directory.path().native());
    if (!Expect(removalError == ERROR_SUCCESS, L"Could not remove the installed broker files.") ||
        !Expect(!FileExists(broker), L"Uninstall retained launch-as-broker.exe.") ||
        !Expect(!FileExists(conhost), L"Uninstall retained launch-as-conhost.exe.") ||
        !Expect(!FileExists(directory.path()), L"Uninstall retained the empty install directory."))
    {
        return false;
    }

    if (!CreateDirectoryW(directory.path().c_str(), nullptr))
    {
        std::wcerr << L"Could not recreate the temporary install directory.\n";
        return false;
    }
    const std::filesystem::path unrelated = directory.path() / L"unrelated.txt";
    if (!CreateEmptyFile(broker) || !CreateEmptyFile(conhost) || !CreateEmptyFile(unrelated))
    {
        std::wcerr << L"Could not create the second temporary broker file set.\n";
        return false;
    }
    return Expect(launch_as::broker::RemoveBrokerInstallFiles(directory.path().native()) ==
                      ERROR_SUCCESS,
               L"Could not remove the broker files from a nonempty directory.") &&
           Expect(!FileExists(broker),
               L"Uninstall retained launch-as-broker.exe in a nonempty directory.") &&
           Expect(!FileExists(conhost),
               L"Uninstall retained launch-as-conhost.exe in a nonempty directory.") &&
           Expect(FileExists(unrelated), L"Uninstall removed an unrelated install-directory file.");
}

} // namespace

int wmain(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount == 2 && std::wstring_view(arguments[1]) == L"--files")
    {
        return VerifyInstallFilesAreRemoved() ? 0 : 1;
    }
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
