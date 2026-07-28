// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <iostream>
#include <string>
#include <string_view>

namespace
{

class Module final
{
  public:
    explicit Module(HMODULE value) noexcept : value_(value) {}

    ~Module()
    {
        if (value_ != nullptr)
        {
            static_cast<void>(FreeLibrary(value_));
        }
    }

    Module(const Module&) = delete;
    Module& operator=(const Module&) = delete;

    [[nodiscard]] HMODULE get() const noexcept { return value_; }

  private:
    HMODULE value_;
};

[[nodiscard]] bool ExpectContains(
    std::string_view manifest, std::string_view expected, std::string_view description)
{
    if (manifest.contains(expected))
    {
        return true;
    }

    std::cerr << "The launcher manifest does not contain " << description << ".\n";
    return false;
}

} // namespace

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: ManifestTests.exe <launch-as.exe>\n";
        return 1;
    }

    Module launcher(LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_AS_DATAFILE));
    if (launcher.get() == nullptr)
    {
        const DWORD loadError = GetLastError();
        std::cerr << "Could not load the launcher executable: " << loadError << "\n";
        return 1;
    }

    const HRSRC manifestResource = FindResourceW(launcher.get(), MAKEINTRESOURCEW(1), RT_MANIFEST);
    if (manifestResource == nullptr)
    {
        const DWORD resourceError = GetLastError();
        std::cerr << "Could not find the embedded launcher manifest: " << resourceError << "\n";
        return 1;
    }

    const DWORD manifestSize = SizeofResource(launcher.get(), manifestResource);
    if (manifestSize == 0)
    {
        const DWORD sizeError = GetLastError();
        std::cerr << "Could not size the embedded launcher manifest: " << sizeError << "\n";
        return 1;
    }
    const HGLOBAL manifestData = LoadResource(launcher.get(), manifestResource);
    if (manifestData == nullptr)
    {
        const DWORD loadError = GetLastError();
        std::cerr << "Could not load the embedded launcher manifest: " << loadError << "\n";
        return 1;
    }
    const auto* manifestBytes = static_cast<const char*>(LockResource(manifestData));
    if (manifestBytes == nullptr)
    {
        std::cerr << "Could not access the embedded launcher manifest.\n";
        return 1;
    }

    const std::string_view manifest(manifestBytes, manifestSize);
    return ExpectContains(manifest, "consoleAllocationPolicy", "the console allocation policy") &&
                   ExpectContains(manifest,
                       "http://schemas.microsoft.com/SMI/2024/WindowsSettings",
                       "the Windows 11 console policy namespace") &&
                   ExpectContains(manifest, ">detached<", "the detached console policy")
               ? 0
               : 1;
}
