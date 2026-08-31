// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerPassword.h"

#include <array>
#include <bcrypt.h>
#include <cstdint>
#include <new>
#include <string_view>

namespace launch_as::broker
{
namespace
{

constexpr std::size_t PasswordLength = 32;
constexpr std::wstring_view Uppercase = L"ABCDEFGHJKLMNPQRSTUVWXYZ";
constexpr std::wstring_view Lowercase = L"abcdefghijkmnopqrstuvwxyz";
constexpr std::wstring_view Digits = L"23456789";
constexpr std::wstring_view Symbols = L"!#$%&*+-=?@";
constexpr std::wstring_view AllowedCharacters =
    L"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@";

class GeneratedPassword final
{
  public:
    ~GeneratedPassword()
    {
        SecureZeroMemory(characters_.data(), characters_.size() * sizeof(wchar_t));
    }

    [[nodiscard]] std::array<wchar_t, PasswordLength>& characters() noexcept { return characters_; }

  private:
    std::array<wchar_t, PasswordLength> characters_ {};
};

[[nodiscard]] DWORD RandomIndex(std::size_t upperBound, std::size_t& index)
{
    constexpr std::uint64_t RandomRange = static_cast<std::uint64_t>(UINT32_MAX) + 1;
    const std::uint64_t limit = RandomRange - RandomRange % upperBound;
    std::uint32_t random = 0;
    do
    {
        const NTSTATUS status = BCryptGenRandom(nullptr,
            reinterpret_cast<PUCHAR>(&random),
            static_cast<ULONG>(sizeof(random)),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0)
        {
            return ERROR_GEN_FAILURE;
        }
    } while (random >= limit);
    index = random % upperBound;
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD SelectCharacter(std::wstring_view alphabet, wchar_t& character)
{
    std::size_t index = 0;
    const DWORD randomError = RandomIndex(alphabet.size(), index);
    if (randomError != ERROR_SUCCESS)
    {
        return randomError;
    }
    character = alphabet[index];
    return ERROR_SUCCESS;
}

} // namespace

SecurePassword::~SecurePassword() { Clear(); }

void SecurePassword::Clear() noexcept
{
    if (!characters_.empty())
    {
        SecureZeroMemory(characters_.data(), characters_.size() * sizeof(wchar_t));
        characters_.clear();
    }
    length_ = 0;
}

bool SecurePassword::Assign(const BYTE* bytes, DWORD byteCount)
{
    if (bytes == nullptr || byteCount == 0 || byteCount % sizeof(wchar_t) != 0)
    {
        return false;
    }
    const auto* first = reinterpret_cast<const wchar_t*>(bytes);
    Clear();
    try
    {
        length_ = byteCount / sizeof(wchar_t);
        characters_.assign(first, first + length_);
        characters_.push_back(L'\0');
    }
    catch (...)
    {
        Clear();
        throw;
    }
    return true;
}

DWORD GenerateBrokerPassword(SecurePassword& password)
{
    GeneratedPassword generated;
    const std::array requiredClasses {Uppercase, Lowercase, Digits, Symbols};
    for (std::size_t index = 0; index < requiredClasses.size(); ++index)
    {
        const DWORD randomError =
            SelectCharacter(requiredClasses[index], generated.characters()[index]);
        if (randomError != ERROR_SUCCESS)
        {
            return randomError;
        }
    }
    for (std::size_t index = requiredClasses.size(); index < generated.characters().size(); ++index)
    {
        const DWORD randomError = SelectCharacter(AllowedCharacters, generated.characters()[index]);
        if (randomError != ERROR_SUCCESS)
        {
            return randomError;
        }
    }
    for (std::size_t index = generated.characters().size() - 1; index > 0; --index)
    {
        std::size_t swapIndex = 0;
        const DWORD randomError = RandomIndex(index + 1, swapIndex);
        if (randomError != ERROR_SUCCESS)
        {
            return randomError;
        }
        std::swap(generated.characters()[index], generated.characters()[swapIndex]);
    }

    try
    {
        if (!password.Assign(reinterpret_cast<const BYTE*>(generated.characters().data()),
                static_cast<DWORD>(generated.characters().size() * sizeof(wchar_t))))
        {
            return ERROR_INVALID_DATA;
        }
        return ERROR_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

} // namespace launch_as::broker
