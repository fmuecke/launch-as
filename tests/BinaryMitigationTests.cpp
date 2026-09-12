// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include <Windows.h>
#include <cstddef>
#include <iostream>

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

[[nodiscard]] bool Expect(bool condition, const wchar_t* message)
{
    if (!condition)
    {
        std::wcerr << message << L"\n";
    }
    return condition;
}

[[nodiscard]] bool IsRvaInImage(const IMAGE_NT_HEADERS64& headers, DWORD rva, std::size_t size)
{
    return rva <= headers.OptionalHeader.SizeOfImage &&
           size <= headers.OptionalHeader.SizeOfImage - rva;
}

[[nodiscard]] const IMAGE_NT_HEADERS64* GetNtHeaders(const BYTE* image)
{
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
    {
        return nullptr;
    }
    const auto* headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        image + static_cast<std::size_t>(dos->e_lfanew));
    if (headers->Signature != IMAGE_NT_SIGNATURE ||
        headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return nullptr;
    }
    return headers;
}

[[nodiscard]] bool HasCetCompatibility(const BYTE* image, const IMAGE_NT_HEADERS64& headers)
{
    const IMAGE_DATA_DIRECTORY debugDirectory =
        headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debugDirectory.VirtualAddress == 0 || debugDirectory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        !IsRvaInImage(headers, debugDirectory.VirtualAddress, debugDirectory.Size))
    {
        return false;
    }
    const auto* entries =
        reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(image + debugDirectory.VirtualAddress);
    const std::size_t entryCount = debugDirectory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (std::size_t index = 0; index < entryCount; ++index)
    {
        const IMAGE_DEBUG_DIRECTORY& entry = entries[index];
        if (entry.Type != IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS ||
            entry.SizeOfData != sizeof(DWORD) ||
            !IsRvaInImage(headers, entry.AddressOfRawData, sizeof(DWORD)))
        {
            continue;
        }
        const DWORD flags = *reinterpret_cast<const DWORD*>(image + entry.AddressOfRawData);
        return (flags & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT) != 0;
    }
    return false;
}

} // namespace

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 2)
    {
        std::wcerr << L"Usage: BinaryMitigationTests.exe <launch-as.exe>\n";
        return 1;
    }
    Module target(LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE));
    if (target.get() == nullptr)
    {
        const DWORD loadError = GetLastError();
        std::wcerr << L"Could not map the launcher image: " << loadError << L"\n";
        return 1;
    }
    const auto* image = reinterpret_cast<const BYTE*>(
        reinterpret_cast<ULONG_PTR>(target.get()) & ~static_cast<ULONG_PTR>(3));
    const IMAGE_NT_HEADERS64* headers = GetNtHeaders(image);
    if (!Expect(headers != nullptr, L"The launcher is not a valid 64-bit PE image."))
    {
        return 1;
    }
    const IMAGE_DATA_DIRECTORY loadConfigDirectory =
        headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!Expect(
            loadConfigDirectory.VirtualAddress != 0 &&
                loadConfigDirectory.Size >=
                    offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DependentLoadFlags) + sizeof(WORD) &&
                IsRvaInImage(
                    *headers, loadConfigDirectory.VirtualAddress, loadConfigDirectory.Size),
            L"The launcher does not have a usable load-configuration directory."))
    {
        return 1;
    }
    const auto* loadConfig = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY64*>(
        image + loadConfigDirectory.VirtualAddress);
    return Expect((headers->OptionalHeader.DllCharacteristics &
                      IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0,
               L"The launcher is not marked as Control Flow Guard compatible.") &&
                   Expect((loadConfig->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0,
                       L"The launcher has no Control Flow Guard instrumentation.") &&
                   Expect(loadConfig->DependentLoadFlags == LOAD_LIBRARY_SEARCH_SYSTEM32,
                       L"The launcher does not restrict dependent loads to system32.") &&
                   Expect(HasCetCompatibility(image, *headers),
                       L"The launcher is not marked CET compatible.")
               ? 0
               : 1;
}
