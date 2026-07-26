# Native launcher

`ClaudeSandboxLauncher` is a Windows C++ launcher for the existing
`ClaudeSandbox` standard-user environment. It stores the sandbox password as a
generic credential in the current Windows user's Credential Manager and runs a
caller-selected executable with `CreateProcessWithLogonW`.

The credential is scoped to the Windows user who registers it. Any process
running as that user can request the same generic credential, so this removes
the per-launch password prompt but does not create a secret boundary inside that
user account.

## Run a process

The launcher requires an absolute executable path. Everything after `--` is
passed to that executable as a separate argument:

```powershell
.\ClaudeSandboxLauncher.exe run `
    --user ClaudeSandbox `
    --working-directory C:\dev\ClaudeSandbox `
    --new-console `
    -- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe `
        -NoExit `
        -ExecutionPolicy Bypass `
        -File C:\ProgramData\claude-win-sandbox\bootstrap\Enter-ClaudeDevShell.ps1
```

`run` creates the process suspended, verifies its token SID, resumes it, waits,
and returns the child process exit code. `--new-console` is appropriate for an
interactive shell; omit it for an unattended command. The credential and local
password buffers are zeroed immediately after process creation, before the
wait begins. Registration and process creation fail closed when the target
token contains the local Administrators SID, including deny-only membership in
a UAC-filtered token.

## Build

The straightforward entrypoint configures CMake and builds x64:

```powershell
.\build.ps1
.\build.ps1 -Configuration Debug
```

Add `-RunTests` (or its short alias, `-Test`) to run the unattended CTest
behavior suite after building:

```powershell
.\build.ps1 -Configuration Release -RunTests
```

The unattended suite includes clean-machine CLI behavior, a real Windows CRT
argument round trip for empty/quoted/backslash-containing arguments, installed
account checks when `ClaudeSandbox` exists, binary version metadata, and
project-version consistency across CMake and the PowerShell entrypoints.

The executable is built with the latest C++ language mode, embedded version
information, and the dynamic MSVC runtime. A target machine therefore needs the
matching Visual C++ Redistributable.

## Acceptance test

Run the test as the regular Windows user who will later use the launcher. The
local standard user must already exist; the test intentionally does not create
or modify accounts and does not require elevation.

```powershell
.\native\tests\Invoke-LauncherAcceptanceTest.ps1
```

The test asks once for the `ClaudeSandbox` password, validates it, stores it
under a unique `test:` credential target, confirms that Credential Manager can
return it, and invokes `run` with `cmd.exe /c exit 37`. The launcher verifies the
suspended process token against the account SID, resumes it, waits for it, and
returns the sentinel exit code. The tagged credential is always removed in a
`finally` block; the normal launcher credential is never read or changed.

The build wrapper can launch the same interactive test after building:

```powershell
.\build.ps1 -Configuration Release -RunAcceptanceTest
```
