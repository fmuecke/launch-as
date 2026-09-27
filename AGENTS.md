# Agent Working Agreement

Optimize for the intended outcome, not merely the requested implementation.

- Clarify consequential assumptions early.
- Treat requirements and inherited constraints as hypotheses.
- Remove unnecessary scope before adding or optimizing anything.
- Prefer eliminating causes over compensating for symptoms.
- Complexity must justify itself.
- First make the change easy, then make the easy change.
- Tidy first when a small structural change makes the intended change simpler or safer.
- For changed functional behavior, prefer the simplest meaningful test first when practical.
- Keep structural and behavioral changes separate when practical.
- Prefer small, reversible steps and fast feedback.

Use `first-principles-analysis` for significant design, architecture, requirements, or optimization decisions.
Use `security-review` for security-sensitive work.
Use `redpen` for human-facing prose where signal/noise matters.

## Completion

Use the `definition-of-done` skill to establish required verification early and before any claim that coding work is complete, fixed, ready, or done.

---

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
modules must not depend on one another. `broker` is also a library: `admin` may link
`launch_as::broker` for account provisioning, audit, caller policy, and data-directory setup. Keep CMake-configured version templates in
`resources/`, tests in `tests/`, and generated output in uncommitted `out/build/`.

Each source folder owns its production target in `src/<module>/CMakeLists.txt`. Link
through the `launch_as::<module>` aliases and declare dependencies there. Do not add a
global `src/` include path or make every target see every module directory; the narrow
include surfaces are what make cross-module dependencies fail at compile time.
Tests that intentionally recompile production sources with test-only definitions must
declare their required folders through `configure_launch_as_test_target()`.

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
.\build.ps1 -RunAllTests             # run both sets, then offer guest acceptance
.\build.ps1 -RunAcceptanceTest        # run interactive acceptance in a fresh guest
ctest --test-dir out\build -C Release --output-on-failure
```

Requires Visual Studio/MSVC, a Windows SDK, CMake 3.25+, PowerShell, and
`clang-format` on `PATH`. `build.ps1` recursively formats native sources before
configuration; review formatting-only changes before committing.

Use the reusable [windows-sandbox-tests](.agents/skills/windows-sandbox-tests/SKILL.md)
skill to run, diagnose, or extend Sandbox tests. Read the
[launch-as workflow guide](tests/windows-sandbox-workflow.md) for this project's
commands, guest identities, result files, and coverage.

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
