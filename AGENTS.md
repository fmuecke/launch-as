# Repository Guidelines

## Project Structure & Module Organization

`src/` contains the native Windows launcher. Keep platform and process concerns in focused pairs such as `LaunchProcess.cpp/.h`, `TerminalBridge.cpp/.h`, and `WindowsCommandLine.cpp/.h`; `launch_as.cpp` is the executable entry point. `resources/` provides the CMake-configured Windows version-resource templates. `tests/` holds native test executables plus PowerShell behavior and interactive acceptance tests. Generated build products belong in `out/build/`; do not commit them.

The application is Windows-only and launches a local standard-user process using Win32 APIs. Treat credential handling, token checks, process inheritance, and terminal bridging as security-sensitive code: preserve zeroing, validation, and least-privilege behavior when making changes.

## Build, Test, and Development Commands

Run these from the repository root in PowerShell:

```powershell
.\build.ps1                         # format, configure x64, build Release
.\build.ps1 -Configuration Debug     # build Debug
.\build.ps1 -RunTests                # build all targets and run CTest
ctest --test-dir out\build -C Release --output-on-failure
```

The build requires Visual Studio/MSVC, a Windows SDK, CMake 3.25+, PowerShell, and `clang-format` on `PATH`. `build.ps1` formats C++ sources before configuring, so review formatting-only changes before committing. For a credentialed end-to-end check, use `tests\Invoke-LauncherAcceptanceTest.ps1 -TargetUser RestrictedUser`; it is interactive and expects an existing local standard user.

## Coding Style & Naming Conventions

Follow `.clang-format`: Microsoft base style, four-space indentation, 100-column limit, Allman braces, left-aligned pointers, and sorted/regrouped includes. Run `clang-format -i -- src\*.cpp src\*.h tests\*.cpp tests\*.h` when editing native code. Use PascalCase for types, functions, and C++ file stems (`PseudoConsoleSession`); use lower-case underscore names for CMake targets (`launch_as`) and descriptive PowerShell verb-noun script names (`Invoke-LauncherBehaviorTests.ps1`). Retain SPDX copyright/license headers in source and scripts.

## Testing Guidelines

Add or update a focused test in `tests/` for every behavior change. Native tests are standalone assertion-style executables registered in `CMakeLists.txt`; keep test names meaningful (for example, `launcher.command_line`) and label them by scope. Run `-RunTests` before opening a PR. Include edge cases for quoting, Unicode, credential absence, token identity, or handle inheritance where applicable.

## Commit & Pull Request Guidelines

Recent commits use short, imperative summaries, e.g. `Add secure same-pane ConPTY terminal sessions` and `refactored launcher file into four focused modules`. Keep each commit narrowly scoped. PRs should explain the user-visible and security impact, list tests run, link relevant issues, and include console output or screenshots when CLI behavior changes. Call out any changes to credential storage, elevation checks, or process/handle inheritance explicitly.

## General Implementation Guidelines

Keep implementations simple and maintainable. Aim for working, easy-to-review code that is good enough for its purpose rather than clever or highly generalized machinery. This matters especially for security-sensitive setup, ACL, firewall, and teardown code: less complexity means fewer threat vectors and fewer mistakes.
