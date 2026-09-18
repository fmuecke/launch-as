# Repository Guidelines

## Structure

Organize `src/` by ownership:

- `launcher/`: client executable
- `conhost/`: pseudoconsole host
- `broker/`: service policy and runtime
- `admin/`: administration executable
- `terminal/`: shared terminal transport
- `protocol/`: wire contracts
- `common/`: low-level utilities

Keep dependencies directed toward `common`, `protocol`, and `terminal`; entry-point
modules must not depend on one another. Keep CMake-configured version templates in
`resources/`, tests in `tests/`, and generated output in uncommitted `out/build/`.

This Windows-only application launches local standard-user processes through Win32.
Credential handling, token checks, process inheritance, and terminal bridging are
security-sensitive: preserve zeroing, validation, and least privilege.

## Commands

Run from the repository root in PowerShell:

```powershell
.\build.ps1                         # format, configure x64, build Release
.\build.ps1 -Configuration Debug     # build Debug
.\build.ps1 -RunTests                # build all targets and run CTest
.\build.ps1 -RunSandboxTests         # run privileged tests in a disposable guest
ctest --test-dir out\build -C Release --output-on-failure
```

Requires Visual Studio/MSVC, a Windows SDK, CMake 3.25+, PowerShell, and
`clang-format` on `PATH`. `build.ps1` recursively formats native sources before
configuration; review formatting-only changes before committing.

Credentialed end-to-end testing is interactive and requires an existing local standard
user:

```powershell
tests\Invoke-LauncherAcceptanceTest.ps1 -TargetUser RestrictedUser
```

## Code

Follow `.clang-format`: Microsoft base, four-space indentation, 100-column limit,
Allman braces, left-aligned pointers, and sorted/regrouped includes. Use PascalCase for
types, functions, and C++ file stems (`PseudoConsoleSession`); lower-case underscores
for CMake targets (`launch_as`); and descriptive PowerShell verb-noun names
(`Invoke-LauncherBehaviorTests.ps1`). Retain SPDX headers in source and scripts.

Prefer simple, maintainable, reviewable implementations over clever or generalized
machinery. Minimize complexity especially in setup, ACL, firewall, and teardown code,
where it increases attack surface and mistakes.

## Tests

Every behavior change needs a focused test in `tests/`. Register native assertion-style
test executables in `CMakeLists.txt`; use meaningful names such as
`launcher.command_line` and labels matching their scope. Cover relevant quoting,
Unicode, missing credentials, token identity, and handle-inheritance edges. Run
`-RunTests` before opening a PR.

## Commits and PRs

Keep commits narrow and subjects short and imperative. PRs must explain user-visible and
security impact, list tests, link relevant issues, and include console output or
screenshots for CLI changes. Explicitly identify changes to credential storage,
elevation checks, or process/handle inheritance.

## Win32 Error Handling

Process `GetLastError()` immediately after the Win32 call whose error is needed: return
it directly or store it in a local `DWORD` before logging, formatting, cleanup, or any
other API call. Never pass a delayed `GetLastError()` to `FormatWindowsError` or another
helper.
