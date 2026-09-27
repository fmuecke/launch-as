# Contributing to launch-as

Contributions should solve a concrete problem with the smallest useful change. Bug reports,
focused fixes, tests, and documentation improvements are welcome. Be respectful, explain your
reasoning, and keep feedback focused on the work.

## Start with an issue

Search existing [issues](https://github.com/fmuecke/launch-as/issues) and
[pull requests](https://github.com/fmuecke/launch-as/pulls) before opening a new one.
Open or link an issue for a bug fix or feature request. Discuss significant changes before
implementing them so contributors and maintainers can agree on the problem and scope.
Small documentation corrections can go directly through a PR.

- **Bug reports:** include the version or commit, Windows version, relevant environment,
  minimal reproduction steps, expected and actual behavior, and useful error output.
  Remove credentials and personal information from logs.
- **Feature requests:** describe the user problem, who benefits, and why existing behavior
  is insufficient. Explain the smallest useful outcome before proposing an implementation.

## Keep changes small and useful

- Address one problem per PR. Make each PR as small as possible while keeping its tests and
  necessary documentation together.
- Every addition must provide clear value. Avoid speculative features, dependencies,
  abstractions, and configuration without a demonstrated need.
- Keep unrelated cleanup, refactoring, and formatting out of a behavioral change. When a
  small preparatory refactor helps, keep it separate and preserve existing behavior.
- Prefer simple, readable code and fixes to underlying causes. Explain any unavoidable
  complexity or compatibility change.

## Set up a development environment

Fork the repository if needed, clone it, and create a topic branch from the current default
branch. Submit changes through a pull request; do not push contributions directly to the
default branch.

Development requires Windows x64, Visual Studio with MSVC C++ build tools, a Windows SDK,
CMake 3.25+, PowerShell, Ninja, and clang-format 22 or newer. Run commands from the repository
root in PowerShell:

```powershell
.\build.ps1                         # format, configure, and build Release
.\build.ps1 -Configuration Debug     # build Debug
.\build.ps1 -RunTests                # build and run host-safe CTest tests
```

The build script initializes the MSVC environment when needed. See
[Build and test](README.md#build-and-test) for further setup and test details.

## Test user-facing behavior first

For every new or changed user-facing behavior, including bug fixes:

1. Write the smallest meaningful test that demonstrates the intended behavior or reproduces
   the bug. Run it and confirm it fails for the expected reason.
2. Implement the smallest change that makes it pass.
3. Refactor if needed, keeping the tests passing.

Test observable behavior through the relevant public interface. Include applicable failure
cases, quoting, Unicode, missing credentials, token identity, and handle inheritance.
If behavior is difficult to test, discuss the test approach in the issue before implementing it.
Every behavior change needs focused coverage in `tests/`; register native test executables
in CMake with meaningful names and scope labels. Documentation-only changes need accurate
examples and working links, not new application tests.

Establish the required verification early and scale it to the change and its risks. Run
`.\build.ps1 -RunTests` before submitting code changes. For affected privileged or interactive
behavior, also run the relevant workflows:

```powershell
.\build.ps1 -RunSandboxTests         # privileged tests in a disposable Windows Sandbox
.\build.ps1 -RunAcceptanceTest       # installed, interactive acceptance in a fresh guest
```

These workflows require Windows Sandbox; interactive acceptance also requires a visible guest
desktop. Do not make tests depend on a broker service or test account installed on the host.
Use the existing guest orchestration and its reserved accounts. Passing host tests or CI does
not establish that privileged, interactive, or UAC behavior works. Report checks you could not
run and keep the PR in draft while required verification remains outstanding.

## Follow repository conventions

Follow [AGENTS.md](AGENTS.md) for code organization, naming, security, and error-handling rules.
`build.ps1` automatically formats native sources using `.clang-format`; review the resulting
diff and exclude unrelated changes.

## Submit a pull request

Keep commits focused and use short, imperative subjects. Review your own diff before requesting
review. A PR should include:

- The problem, the resulting behavior, and a link to the issue (`Fixes #123` when appropriate).
- The user-visible and security impact, explicitly identifying changes to credential storage,
  elevation checks, or process and handle inheritance.
- The tests and commands run, their results, and any remaining limitations or unverified claims.
  For behavior changes, include the failing-test evidence from before the fix.
- Console output or screenshots for CLI changes, and documentation updates when usage changes.

Use a draft PR for early feedback or incomplete work. Before requesting review, ensure relevant
checks pass and required verification is complete. Address review feedback with focused changes;
discuss new scope separately. Maintainers review and merge contributions through PRs.

Contributions use the repository's [GPL-3.0-only license](LICENSE). Preserve existing license
notices and only submit material you have the right to contribute.
