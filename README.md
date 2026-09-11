<!-- Project URL: https://github.com/fmuecke/launch-as -->

# launch-as

Launch-as is currently used in [agent-win-sandbox](https://github.com/fmuecke/agent-win-sandbox) to create a least-privilege session for a coding agent like Claude Code or GitHub Copilot CLI.

The current stable version is still v3.2.0. [Browse the stable v3.2.0 version](https://github.com/fmuecke/launch-as/tree/v0.3.2). It creates the session via `CreateProcessWithLogonW` from the current user. However, this has some security implications due to derived logon session tokens:

- Session user will be able to see and interact with the regular user's desktop.
- For regular-user processes that retain the normal logon-SID default-DACL ACE, the session user
  can obtain `PROCESS_VM_READ` and `PROCESS_TERMINATE`, allowing memory reads and termination.
  Protected processes or processes with custom DACLs may not be accessible.

**1.0.0-preview · Windows x64 · console programs only**

`launch-as` starts a console program as an **enrolled local standard account** through the
`launch-as-broker` Windows service. The client never accepts, reads, stores, or transmits the
account password. The broker creates an independent logon session, so the child does not inherit
the caller's logon SID or its default access to the caller's processes.

This is a general-purpose alternate-account launcher: its authorised caller can choose an enrolled
account and any absolute executable. It is blast-radius reduction, not a sandbox: it does not
protect against a local administrator or kernel-level attacker. GUI applications are out of scope
for this preview.

## Install the binary package

Extract `launch-as-v1.0.0-preview-win64.zip` and run the bundled setup script from its extracted
directory. It elevates when needed, installs or updates the demand-start service, and can enroll a
default account. Updating re-enrolls that account and replaces its broker-owned password. The user
who runs `install` becomes the broker's authorised caller.

```powershell
.\Setup-LaunchAs.ps1
```

The package contains `launch-as.exe`, `launch-as-admin.exe`, `launch-as-broker.exe`,
`launch-as-conhost.exe`, this README, the setup script, and the license. Keep
`launch-as-admin.exe`, `launch-as-broker.exe`, and `launch-as-conhost.exe` together while
installing; setup copies the broker and console host to
`%ProgramFiles%\launch-as` with protected permissions.

## Setup

For automation or individual elevated administration operations, use `launch-as-admin.exe`. Run
these commands from the extracted package directory (or `out\build\Release` after a source build):

```powershell
.\launch-as-admin.exe install
.\launch-as-admin.exe enroll LaunchAsUser
```

`install`, `enroll`, `unenroll`, and `uninstall` require elevation. `install` stops active broker
sessions before updating the service. `enroll` creates a missing non-administrative local account,
or takes over an existing one by setting a broker-owned password. It prompts before changing an
account; `--force` is the explicit non-interactive override.

The broker creates a password for each launch, uses it only to log on, then wipes it. An enrolled
account runs one session at a time; a second launch fails immediately. `unenroll` forgets the
enrollment and disables the account, but does not delete the Windows account.

```powershell
.\launch-as-admin.exe list
.\launch-as-admin.exe unenroll LaunchAsUser
.\launch-as-admin.exe uninstall
```

## Launch

From a normal terminal, launch an enrolled account in the current pane:

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
```

`-RunTests` runs every non-elevated CTest test. The installed-service acceptance checks remain
explicit because they require elevation and an enrolled account:

```powershell
.\tests\Invoke-BrokerConsoleAcceptanceTest.ps1 -Account LaunchAsUser -ExpectedExitCode 37
.\tests\Invoke-BrokerProbeAcceptanceTest.ps1 -Account LaunchAsUser
```

The probe confirms a distinct logon SID, no interactive windows, and denied `VM_READ` and
`TERMINATE` access to the caller's process. These are blast-radius controls, not protection from a
local administrator or kernel-level attacker.

## Design

[launch-as-broker-spec.md](launch-as-broker-spec.md) is the Phase 1 implementation specification.
The `interactive` GUI adapter is deliberately deferred to Phase 2; Phase 1 provides console
(ConPTY) launches only.

## License

`launch-as` is licensed under the [GNU General Public License version 3 only](LICENSE). Source for
this preview is available at <https://github.com/fmuecke/launch-as/tree/v1.0.0-preview>.
