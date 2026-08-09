# launch-as

`launch-as` starts a console program as an **enrolled local standard account** through the
`launch-as-broker` Windows service. The client never accepts, reads, stores, or transmits the
account password. The broker creates an independent interactive logon session, which prevents the
child from inheriting the caller's logon SID and from using that SID to read or terminate the
caller's processes.

The broker is a general-purpose alternate-account launcher: an authorised caller may choose an
enrolled account and an absolute executable. Per-account executable restrictions are deliberately
not part of Phase 1.

## Setup

Run these elevated, once per computer or when changing enrolled accounts:

```powershell
.\out\build\Release\launch-as-broker.exe install
.\out\build\Release\launch-as-broker.exe enroll AgentSandbox
.\out\build\Release\launch-as-broker.exe test AgentSandbox
```

`enroll` creates a missing non-administrative local account or takes over an existing one by
setting a broker-owned password. It prompts before changing the account; `--force` is the explicit
non-interactive override. `unenroll` deletes the broker credential and disables the account, but
does not delete the Windows account.

```powershell
.\out\build\Release\launch-as-broker.exe list
.\out\build\Release\launch-as-broker.exe rotate AgentSandbox
.\out\build\Release\launch-as-broker.exe unenroll AgentSandbox
.\out\build\Release\launch-as-broker.exe uninstall
```

## Launch

From a normal terminal, launch an enrolled account in the current pane:

```powershell
.\out\build\Release\launch-as.exe `
    --user AgentSandbox `
    --working-directory C:\dev\project `
    -- C:\Windows\System32\cmd.exe /d /k
```

`run` is an optional spelling of the same command. The client starts the demand-start broker,
creates the terminal data pipes, and returns the target program's exit code. The broker owns the
credential and kills the console job when the client control connection closes.

## Build and test

Run `build.ps1` from a Visual Studio Developer PowerShell or x64 Native Tools Command Prompt. It
requires `ninja` on `PATH` and builds the Ninja Multi-Config Release target by default.

```powershell
.\build.ps1
.\build.ps1 -Configuration Debug
.\build.ps1 -RunTests
```

`-RunTests` runs every non-elevated CTest test. The installed-service acceptance checks remain
explicit because they require elevation and an enrolled account:

```powershell
.\tests\Invoke-BrokerConsoleAcceptanceTest.ps1 -Account AgentSandbox -ExpectedExitCode 37
.\tests\Invoke-BrokerProbeAcceptanceTest.ps1 -Account AgentSandbox
```

The probe confirms a distinct logon SID, no interactive windows, and denied `VM_READ` and
`TERMINATE` access to the caller's process. These are blast-radius controls, not protection from a
local administrator or kernel-level attacker.

## Design

[launch-as-broker-spec.md](launch-as-broker-spec.md) is the Phase 1 implementation specification.
The `interactive` GUI adapter is deliberately deferred to Phase 2; Phase 1 provides console
(ConPTY) launches only.

## License

`launch-as` is licensed under the GNU General Public License version 3 only.
