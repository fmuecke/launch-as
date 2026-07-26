# Native launcher

`ClaudeSandboxLauncher` is a Windows C++ launcher for the existing
`ClaudeSandbox` standard-user environment. It stores the sandbox password as a
generic credential in the current Windows user's Credential Manager and runs a
caller-selected executable with `CreateProcessWithLogonW`.

The credential is scoped to the Windows user who registers it. Any process
running as that user can request the same generic credential, so this removes
the per-launch password prompt but does not create a secret boundary inside that
user account.

## Register a credential

Interactive registration opens Windows Credential UI, validates the password
against the fixed local account, rejects administrative accounts, and stores the
credential:

```powershell
.\ClaudeSandboxLauncher.exe register --user ClaudeSandbox
```

For automation, `register` accepts exactly one UTF-8 password line through
redirected standard input:

```powershell
$generatedPassword |
    .\ClaudeSandboxLauncher.exe register `
        --user ClaudeSandbox `
        --password-stdin
```

The launcher refuses `--password-stdin` when standard input is still attached
to a console, so a password cannot accidentally be typed with echo enabled. The
invoking automation host still temporarily owns its plaintext copy and must
clear it when possible.

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

The default credential mode is `auto`: a stored credential is used when
available. If it is missing, Windows Credential UI opens with a Remember
checkbox. If a stored password has become stale, the launcher requests its
replacement. The replacement is stored only when requested and only after the
suspended child token has been verified.

Use `--credential-mode stored` for unattended execution; it never displays UI
and returns a distinct missing-credential exit code. Use
`--credential-mode prompt` for an ephemeral run that ignores Credential Manager,
prompts through Windows Credential UI, and never saves the password.

`run` creates the process suspended, verifies its token SID, resumes it, waits,
and returns the child process exit code. `--new-console` is appropriate for an
interactive shell; omit it for an unattended command. The credential and local
password buffers are zeroed after identity verification and optional
persistence, before the child is resumed and before the wait begins.
Registration and process creation fail closed when the target token contains
the local Administrators SID, including deny-only membership in a UAC-filtered
token.

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

The test opens Windows Credential UI once for the `ClaudeSandbox` password,
validates it, stores it under a unique `test:` credential target, confirms that
Credential Manager can return it, and invokes `run` with
`cmd.exe /c exit 37`. The launcher verifies the suspended process token against
the account SID, resumes and waits for it, and returns the sentinel exit code.
The tagged credential is always removed in a `finally` block; the normal
launcher credential is never read or changed.

To exercise password-stdin registration with the same real behavior test,
supply the password as a `SecureString`:

```powershell
$password = Read-Host 'Sandbox password' -AsSecureString
.\native\tests\Invoke-LauncherAcceptanceTest.ps1 -Password $password
```

The build wrapper can launch the same interactive test after building:

```powershell
.\build.ps1 -Configuration Release -RunAcceptanceTest
```
