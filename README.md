<!-- Project URL: https://github.com/fmuecke/launch-as -->

# launch-as

Launch-as is currently used in [agent-win-sandbox](https://github.com/fmuecke/agent-win-sandbox) to create a least-privilege session for a coding agent like Claude Code or GitHub Copilot CLI.

The current stable version is still v0.3.2. [Browse the stable v0.3.2 version](https://github.com/fmuecke/launch-as/tree/v0.3.2). It creates the session via `CreateProcessWithLogonW` from the current user. However, this has some security implications due to derived logon session tokens:

- Session user will be able to see and interact with the regular user's desktop.
- For regular-user processes that retain the normal logon-SID default-DACL ACE, the session user
  can obtain `PROCESS_VM_READ` and `PROCESS_TERMINATE`, allowing memory reads and termination.
  Protected processes or processes with custom DACLs may not be accessible.

**1.2.0-preview · Windows x64 · console programs only**

`launch-as` starts a console program as a **launch-as-managed local standard account** through the
`launch-as-broker` Windows service. The client never accepts, reads, stores, or transmits the
account password. The broker creates an independent logon session, so the child does not inherit
the caller's logon SID or its default access to the caller's processes.

This is a general-purpose alternate-account launcher: its authorised caller can choose a configured
launch-as-managed account and any absolute executable. It is blast-radius reduction, not a sandbox: it does not
protect against a local administrator or kernel-level attacker. GUI applications are out of scope
for this version.

## Install the binary package

Extract `launch-as-v1.2.0-preview-win64.zip` and run the bundled setup script from its extracted
directory. It elevates when needed, installs or updates the demand-start service and all four
executables into `%ProgramFiles%\launch-as`, and can create a default account. Updating takes over
that account and replaces its broker-owned password. The user who runs a fresh `install` becomes the
broker's authorised caller, including after a prior uninstall; updates preserve that caller policy.
Setup rejects a candidate whose
`launch-as.exe` SemVer is lower than the installed client version; an equal version is a repair
reinstall.

```powershell
.\Setup-LaunchAs.ps1
```

The package contains `launch-as.exe`, `launch-as-admin.exe`, `launch-as-broker.exe`,
`launch-as-conhost.exe`, this README, the setup script, and the license. Keep all four executables
together while installing; setup copies them to `%ProgramFiles%\launch-as` with protected
permissions. That directory is deliberately not added to `PATH`; invoke the installed client by
its full path or add it to your own user `PATH` if desired.

For non-interactive automation, select an action explicitly and use `-Force` to accept the
documented account/password-reset or uninstall operation:

```powershell
.\Setup-LaunchAs.ps1 -Command Install -Force
.\Setup-LaunchAs.ps1 -Command Update -Force
.\Setup-LaunchAs.ps1 -Command Uninstall -Force
```

## Setup

For automation or individual elevated administration operations, use `launch-as-admin.exe`. Run
these commands from the extracted package directory (or `out\build\Release` after a source build):

```powershell
.\launch-as-admin.exe install
.\launch-as-admin.exe create LaunchAsUser
```

`install`, `create`, `forget`, `delete`, and `uninstall` require elevation. `install` stops active
broker sessions before updating the service and copies all launch-as executables. `uninstall`
removes the service and every launch-as executable from `%ProgramFiles%\launch-as`; it retains
registered Windows accounts and `%ProgramData%\launch-as` enrollment data. `create <account>` creates a dedicated account and
fails if that name already exists. Use
`create <account> --takeover` to deliberately reset an existing account's password and make it
launch-as-owned. Taking over a disabled account requires `--force` to re-enable it. A forced
takeover also creates the account when it is missing; without `--force`, a missing account fails.

The broker creates a password for each launch, uses it to reset and log on to the account, then
clears its plaintext copy. A managed account supports up to two concurrent sessions; the broker supports four sessions globally.
Further launches fail immediately. `forget` stops launch-as from managing the account without
changing the Windows account. `delete`
removes a SID-matched owned Windows account after its sessions end; neither command deletes its
profile directory.

```powershell
.\launch-as-admin.exe list
.\launch-as-admin.exe create LaunchAsUser --takeover
.\launch-as-admin.exe forget LaunchAsUser
.\launch-as-admin.exe uninstall
```

## Launch

From a normal terminal, launch a configured launch-as-managed account in the current pane:

```powershell
.\launch-as.exe `
    --user LaunchAsUser `
    --working-directory C:\dev\project `
    -- C:\Windows\System32\cmd.exe /d /k
```

`run` is an optional spelling of the same command. The client starts the demand-start broker,
creates the terminal data pipes, and returns the target program's exit code. The broker owns the
temporary launch password and kills the console job when the client control connection closes.

## Build and test

The source build requires Visual Studio/MSVC, a Windows SDK, CMake 3.25+, PowerShell, `ninja`, and
`clang-format`. Run `build.ps1` from the repository root; it initializes the MSVC environment when
needed and builds the Ninja Multi-Config Release target by default.

```powershell
.\build.ps1
.\build.ps1 -Configuration Debug
.\build.ps1 -RunTests
.\build.ps1 -RunAllTests
.\build.ps1 -PackageRelease
```

`-PackageRelease` performs a clean Release build in `out\release-build` and writes the
distributable `out\release\launch-as-v<version>-win64.zip` package.

`-RunTests` runs every non-elevated CTest test. `-RunAllTests` adds the tests labelled `elevated`:
when necessary, it asks for UAC approval and runs only that subset in an elevated child process.
That child window stays open after the elevated tests complete so their output can be inspected.
The installed-service acceptance checks remain explicit because they require an installed broker,
a configured launch-as-managed account, and the authorised non-elevated interactive session:

```powershell
.\build.ps1 -RunAcceptanceTest
.\tests\Invoke-BrokerConsoleAcceptanceTest.ps1 -Account LaunchAsUser -ExpectedExitCode 37
.\tests\Invoke-BrokerProbeAcceptanceTest.ps1 -Account LaunchAsUser
```

`-RunAcceptanceTest` uses `LaunchAsUser` by default; pass `-TargetUser <account>` to select another
managed account.

The probe confirms a distinct logon SID, no interactive windows, and denied `VM_READ` and
`TERMINATE` access to the caller's process. These are blast-radius controls, not protection from a
local administrator or kernel-level attacker.

## Design

[launch-as-broker-spec.md](launch-as-broker-spec.md) is the Phase 1 implementation specification.
The `interactive` GUI adapter is deliberately deferred to Phase 2; Phase 1 provides console
(ConPTY) launches only.

## License

`launch-as` is licensed under the [GNU General Public License version 3 only](LICENSE). Source for
this preview is available at <https://github.com/fmuecke/launch-as/tree/v1.2.0-preview>.
