// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "AppContainerIdentity.h"

#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <cstring>
#include <sddl.h>
#include <userenv.h>

namespace launch_as
{
namespace
{
DWORD CopySidBytes(PSID sid, std::vector<BYTE>& bytes)
{
    if (!IsValidSid(sid))
    {
        return ERROR_INVALID_SID;
    }
    bytes.resize(GetLengthSid(sid));
    return CopySid(static_cast<DWORD>(bytes.size()), bytes.data(), sid) ? ERROR_SUCCESS
                                                                        : GetLastError();
}

DWORD ResolveCapability(const std::wstring& name, std::vector<BYTE>& bytes)
{
    if (name.starts_with(L"S-"))
    {
        LocalAllocation<PSID> sid;
        if (!ConvertStringSidToSidW(name.c_str(), sid.address()))
        {
            return GetLastError();
        }
        const SID_IDENTIFIER_AUTHORITY authority = SECURITY_APP_PACKAGE_AUTHORITY;
        if (memcmp(GetSidIdentifierAuthority(sid.get()), &authority, sizeof(authority)) != 0 ||
            *GetSidSubAuthorityCount(sid.get()) < 2 ||
            *GetSidSubAuthority(sid.get(), 0) != SECURITY_CAPABILITY_BASE_RID)
        {
            return ERROR_INVALID_SID;
        }
        return CopySidBytes(sid.get(), bytes);
    }
    using Derive = BOOL(WINAPI*)(LPCWSTR, PSID**, DWORD*, PSID**, DWORD*);
    const auto derive = reinterpret_cast<Derive>(
        GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "DeriveCapabilitySidsFromName"));
    if (!derive)
    {
        return ERROR_NOT_SUPPORTED;
    }
    PSID* groups = nullptr;
    PSID* capabilities = nullptr;
    DWORD groupCount = 0, count = 0;
    if (!derive(name.c_str(), &groups, &groupCount, &capabilities, &count))
    {
        return GetLastError();
    }
    const DWORD error = count == 1 ? CopySidBytes(capabilities[0], bytes) : ERROR_INVALID_SID;
    for (DWORD index = 0; index < groupCount; ++index)
    {
        LocalFree(groups[index]);
    }
    for (DWORD index = 0; index < count; ++index)
    {
        LocalFree(capabilities[index]);
    }
    LocalFree(groups);
    LocalFree(capabilities);
    return error;
}

DWORD ProfileName(HANDLE token, const std::wstring& directory,
    const std::vector<std::vector<BYTE>>& capabilities, std::wstring& name)
{
    std::vector<BYTE> user;
    DWORD error = QueryTokenInformation(token, TokenUser, user);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(user.data());
    LocalAllocation<LPWSTR> sid;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, sid.address()))
    {
        return GetLastError();
    }
    // NUL separates fields unambiguously; none of these source strings can contain NUL.
    std::wstring key(sid.get());
    key.push_back(L'\0');
    key += directory;
    key.push_back(L'\0');
    std::vector<std::wstring> sortedCapabilities;
    for (const auto& capability : capabilities)
    {
        LocalAllocation<LPWSTR> text;
        if (!ConvertSidToStringSidW(const_cast<BYTE*>(capability.data()), text.address()))
        {
            return GetLastError();
        }
        sortedCapabilities.emplace_back(text.get());
    }
    std::sort(sortedCapabilities.begin(), sortedCapabilities.end());
    for (const auto& capability : sortedCapabilities)
    {
        key += capability;
        key.push_back(L'\0');
    }
    std::array<BYTE, 32> hash {};
    const NTSTATUS status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE,
        nullptr,
        0,
        reinterpret_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size() * sizeof(wchar_t)),
        hash.data(),
        static_cast<ULONG>(hash.size()));
    if (status < 0)
    {
        return ERROR_GEN_FAILURE;
    }
    name = L"launch-as-";
    constexpr wchar_t hex[] = L"0123456789abcdef";
    // 192 bits, within the Windows profile-name limit of 64 characters.
    for (std::size_t index = 0; index < 24; ++index)
    {
        name += hex[hash[index] >> 4];
        name += hex[hash[index] & 15];
    }
    return ERROR_SUCCESS;
}

} // namespace

DWORD AppContainerIdentity::Initialize(
    HANDLE token, const std::wstring& directory, const AppContainerOptions& options)
{
    failureContext_ = L"validate AppContainer options and query managed account";
    if (!options.enabled || !IsValidAppContainerOptions(options))
    {
        return ERROR_INVALID_PARAMETER;
    }
    for (const auto& capability : options.capabilities)
    {
        failureContext_ = L"resolve capability '" + capability + L"'";
        std::vector<BYTE> sid;
        const DWORD error = ResolveCapability(capability, sid);
        if (error != ERROR_SUCCESS)
        {
            return error;
        }
        if (std::find(capabilitySids_.begin(), capabilitySids_.end(), sid) == capabilitySids_.end())
        {
            capabilitySids_.push_back(std::move(sid));
        }
    }
    DWORD error = ProfileName(token, directory, capabilitySids_, name_);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    PSID sid = nullptr;
    failureContext_ = L"create AppContainer profile '" + name_ + L"'";
    HRESULT result = CreateAppContainerProfile(
        name_.c_str(), name_.c_str(), L"launch-as console sandbox", nullptr, 0, &sid);
    if (result == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
    {
        result = DeriveAppContainerSidFromAppContainerName(name_.c_str(), &sid);
    }
    if (FAILED(result))
    {
        return HRESULT_CODE(result);
    }
    error = CopySidBytes(sid, sid_);
    FreeSid(sid);
    if (error != ERROR_SUCCESS)
    {
        return error;
    }
    for (auto& capability : capabilitySids_)
    {
        capabilities_.push_back({capability.data(), SE_GROUP_ENABLED});
    }
    security_.AppContainerSid = sid_.data();
    security_.CapabilityCount = static_cast<DWORD>(capabilities_.size());
    security_.Capabilities = capabilities_.empty() ? nullptr : capabilities_.data();
    return ERROR_SUCCESS;
}

} // namespace launch_as
