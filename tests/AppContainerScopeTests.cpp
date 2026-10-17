// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

#include "BrokerAppContainerScope.h"
#include "TestSupport.h"

#include <Aclapi.h>
#include <filesystem>
#include <fstream>
#include <sddl.h>

using namespace launch_as;
using namespace launch_as::broker;

namespace
{
std::wstring Permissions(const std::filesystem::path& path, bool labelOnly = false)
{
    LocalAllocation<PSECURITY_DESCRIPTOR> descriptor;
    const DWORD information = labelOnly ? LABEL_SECURITY_INFORMATION
                                        : DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    if (GetNamedSecurityInfoW(path.c_str(),
            SE_FILE_OBJECT,
            information,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            descriptor.address()) != ERROR_SUCCESS)
    {
        return {};
    }
    LocalAllocation<LPWSTR> text;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.get(), SDDL_REVISION_1, information, text.address(), nullptr))
    {
        return {};
    }
    return text.get();
}
} // namespace

int wmain()
{
    test::TemporaryDirectory temporary;
    if (!Expect(temporary.created(), L"Could not create inheritance fixture."))
    {
        return 1;
    }
    const auto root = temporary.path();
    const auto work = root / L"work";
    const auto child = work / L"existing" / L"old.txt";
    const auto protectedChild = work / L"protected.txt";
    std::filesystem::create_directories(child.parent_path());
    std::ofstream(child) << "existing";
    std::ofstream(protectedChild) << "keep protected ACL";
    std::ofstream(root / L"late.txt") << "moved in after preparation";
    std::ofstream(root / L"shared.txt") << "owner-controlled hard link";
    if (!CreateHardLinkW((work / L"alias.txt").c_str(), (root / L"shared.txt").c_str(), nullptr))
    {
        return 1;
    }
    const auto sharedBefore = Permissions(root / L"shared.txt");

    LocalAllocation<PSID> sid;
    HANDLE rawToken = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-15-2-101-202-303-404-505-606-707", sid.address()) ||
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &rawToken))
    {
        return 1;
    }
    UniqueHandle token(rawToken);
    std::vector<BYTE> user;
    LocalAllocation<LPWSTR> userSid;
    LocalAllocation<PSECURITY_DESCRIPTOR> protectedDescriptor;
    if (QueryTokenInformation(token.get(), TokenUser, user) != ERROR_SUCCESS ||
        !ConvertSidToStringSidW(
            reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, userSid.address()))
    {
        return 1;
    }
    const std::wstring sddl = L"D:P(A;;FA;;;" + std::wstring(userSid.get()) + L")";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, protectedDescriptor.address(), nullptr) ||
        !SetFileSecurityW(protectedChild.c_str(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            protectedDescriptor.get()))
    {
        return 1;
    }
    const auto protectedBefore = Permissions(protectedChild);
    const auto rootLabel = Permissions(work, true);
    const auto childLabel = Permissions(child, true);
    std::wstring context;
    const auto prepare = [&]
    {
        return PrepareBrokerAppContainerRootForTesting(
            token.get(), work.native(), sid.get(), context);
    };
    const std::wstring package = L"S-1-15-2-101-202-303-404-505-606-707";
    const DWORD preparationError = prepare();
    if (preparationError != ERROR_SUCCESS)
    {
        std::wcerr << L"Preparation error=" << preparationError << L", " << context << L"\n";
    }
    bool passed = Expect(preparationError == ERROR_SUCCESS, L"Root inheritance setup failed.");
    passed = Expect(Permissions(child).find(package) != std::wstring::npos &&
                        Permissions(root / L"shared.txt") != sharedBefore &&
                        Permissions(root / L"shared.txt").find(package) != std::wstring::npos &&
                        Permissions(protectedChild) == protectedBefore && !protectedBefore.empty(),
                 L"Account propagation failed or changed a protected child.") &&
             passed;
    passed = Expect(Permissions(work, true) == rootLabel && Permissions(child, true) == childLabel,
                 L"AppContainer setup changed filesystem integrity labels.") &&
             passed;

    std::filesystem::create_directories(work / L"new");
    std::ofstream(work / L"new" / L"inherited.txt") << "new child";
    passed =
        Expect(Permissions(work / L"new" / L"inherited.txt").find(package) != std::wstring::npos,
            L"New children did not inherit package access.") &&
        passed;

    const auto late = work / L"late.txt";
    std::filesystem::rename(root / L"late.txt", late);
    const auto before = Permissions(late);
    passed = Expect(!before.empty() && before.find(package) == std::wstring::npos &&
                        prepare() == ERROR_SUCCESS &&
                        Permissions(late).find(package) != std::wstring::npos,
                 L"An existing root grant prevented propagation to a moved-in file.") &&
             passed;
    const auto propagated = Permissions(late);
    passed = Expect(prepare() == ERROR_SUCCESS && Permissions(late) == propagated &&
                        Permissions(protectedChild) == protectedBefore,
                 L"Repeated propagation changed an existing grant or protected ACL.") &&
             passed;

    std::filesystem::rename(work, root / L"retired");
    std::filesystem::create_directories(work / L"replacement");
    std::ofstream(work / L"replacement" / L"child.txt") << "replacement";
    passed = Expect(prepare() == ERROR_SUCCESS &&
                        Permissions(work).find(package) != std::wstring::npos &&
                        Permissions(work / L"replacement" / L"child.txt").find(package) !=
                            std::wstring::npos,
                 L"A replacement root did not propagate access to existing descendants.") &&
             passed;
    return passed ? 0 : 1;
}
