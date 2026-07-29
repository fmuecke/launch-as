# launch-as

`launch-as` is a Windows C++ launcher that runs a caller-selected executable as
a different local standard user with `CreateProcessWithLogonW`. It can store
the target account's password as a generic credential in the current Windows
user’s Credential Manager.

The caller is a trusted regular Windows user who uses the launcher to run tools
such as agents in separate restricted local identities. This is a
least-privilege tool, not an elevation mechanism: it never launches programs as
Administrator and rejects administrative target accounts.

The credential is scoped to the Windows user who registers it. Any process
running as that user can request the same generic credential, so this removes
the per-launch password prompt but does not create a secret boundary inside that
user account.

## Register a credential

Interactive registration opens Windows Credential UI, validates the password
against the selected local account, rejects administrative accounts, and
stores the credential:

```powershell
.\launch-as.exe register --user RestrictedUser
```

For automation, `register` accepts exactly one UTF-8 password line through
redirected standard input:

```powershell
$generatedPassword |
    .\launch-as.exe register `
        --user RestrictedUser `
        --password-stdin
```

The launcher refuses `--password-stdin` when standard input is still attached
to a console, so a password cannot accidentally be typed with echo enabled. The
invoking automation host still temporarily owns its plaintext copy and must
clear it when possible.

## Run a process

The launcher requires an absolute executable path. `--working-directory` is
optional; when omitted, the launched process inherits the launcher's current
working directory. Everything after `--` is passed to that executable as a
separate argument:

```powershell
    .\launch-as.exe `
        --user RestrictedUser `
        --working-directory C:\dev\project `
        -- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe `
            -NoExit
```

The `run` subcommand is optional.

The default credential mode is `auto`: a stored credential is used when
available. If it is missing, Windows Credential UI opens with an unchecked
Remember checkbox. If a stored password has become stale, the launcher requests
its replacement. The replacement is stored only when requested and only after
the suspended child token has been verified.

Use `--credential-mode stored` for unattended execution; it never displays UI
and returns a distinct missing-credential exit code. Use
`--credential-mode prompt` for an ephemeral run that ignores Credential Manager,
prompts through Windows Credential UI, and never saves the password.

The launcher creates the process suspended, verifies its token SID, resumes it,
waits, and returns the child process exit code. By default,
`CreateProcessWithLogonW` gives a console application a new console window. Use
`--terminal` to host an interactive process through Windows ConPTY and relay it
through the launcher's existing terminal pane instead.

## Exit codes

A launched child's exit code is returned unchanged. Launcher-generated outcomes
use these Win32 values: `1` (`ERROR_INVALID_FUNCTION`) for a general failure,
`87` (`ERROR_INVALID_PARAMETER`) for invalid usage, `1326`
(`ERROR_LOGON_FAILURE`) when `--credential-mode stored` has no saved credential,
and `1223` (`ERROR_CANCELLED`) when an operation is cancelled. A child can also
return any of these values, so an exit code alone cannot always identify whether
the launcher or the child produced it.

When a shortcut or Explorer starts `launch-as` on Windows 11 version 24H2 or
later, the embedded manifest prevents Windows from allocating a console for the
launcher itself. Earlier Windows versions still allocate that launcher console.

The credential and local password buffers are zeroed after identity verification
and optional persistence, before the child is resumed and before the wait begins.
Registration and process creation fail closed when the target token contains
the local Administrators SID, including deny-only membership in a UAC-filtered
token.

`CreateProcessWithLogonW` does not accept the extended startup attributes
required by ConPTY. For terminal mode, the credentialed suspended process is
therefore a hidden instance of the trusted launcher running as the target
user. The parent verifies that helper's token and clears the password before
resuming it. Two one-instance, local named pipes explicitly bridge the caller's
terminal streams to the hidden helper, avoiding direct use of console handles
in the no-window process. The regular-user launcher owns both server endpoints;
the target user receives only preconnected, direction-limited client handles and
never receives a pipe name. Those client handles are non-inheritable except
during the individual process-creation call; the parent copies are closed
immediately after successful creation and inheritance is removed immediately
after a failed attempt. After the verified helper exits, the parent gives
buffered output a bounded drain period and then cancels the relay if necessary,
so a retained target-side output handle cannot keep the launcher alive
indefinitely. The helper creates the requested process with `CreateProcessW`
and the ConPTY startup attribute; that child necessarily inherits the
already-verified target identity. The initial pane dimensions are passed to
the helper; live resizing is not implemented yet.

For example, this starts a nested PowerShell session in the current
Windows Terminal or VS Code terminal pane:

```powershell
.\launch-as.exe `
    --user RestrictedUser `
    --working-directory C:\dev\project `
    --terminal `
    -- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe `
        -NoExit
```

The original shell remains the configuring user's process. The nested shell and
all processes it starts use the target identity. Exiting the nested shell
returns control to the original shell; closing its pseudoconsole terminates any
clients that remain attached after the root process exits. Closing the host
terminal also tears down the helper and its pseudoconsole session instead of
leaving the target processes running without a terminal.

Terminal mode requires Windows 10 version 1809 or newer. Its APIs are resolved
dynamically and the launcher returns a clear error on unsupported systems.
While the nested session is active, its output controls that pane and must be
treated as untrusted. It can spoof prompts and emit terminal sequences affecting
presentation, links, or terminal-supported clipboard operations. The launcher
prints the active target identity before resuming the child.

## Requirements

- Windows 10 version 1809 or newer
- Visual Studio with the MSVC C++ toolchain and a Windows SDK
- CMake 3.25 or newer
- `clang-format` on `PATH`
- PowerShell for the build and test scripts

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
argument round trip for empty/quoted/backslash-containing arguments, and a
current-user ConPTY smoke test that captures and verifies output from
`cmd.exe /c echo` through the same hidden helper and named-pipe transport used
by terminal mode. It also verifies that the handles supplied to the target
are client endpoints that cannot impersonate their peer, exercises the narrow
inheritance window, and retains a duplicate output client to verify bounded
relay shutdown. The suite covers optional installed-account checks when the
`LaunchAsTest` fixture exists and validates the embedded binary version metadata.

The executable is built with the latest C++ language mode, embedded version
information, and the static MSVC runtime. The release binary therefore does not
require a separately installed Visual C++ Redistributable.

## Acceptance test

Run the test as the regular Windows user who will later use the launcher. The
local standard user must already exist; the test intentionally does not create
or modify accounts and does not require elevation.

```powershell
.\tests\Invoke-LauncherAcceptanceTest.ps1 -TargetUser RestrictedUser
```

The test opens Windows Credential UI once for the target user's password,
validates it, stores it under a unique `test:` credential target, confirms that
Credential Manager can return it, and invokes the launcher first with
`cmd.exe /c exit 37` and then through ConPTY with a second sentinel code. For
the direct run it verifies the suspended command token; for ConPTY it verifies
the suspended target-side helper, which starts `cmd.exe` with its inherited
token. Both paths wait and return the sentinel exit code. The tagged credential
is always removed in a `finally` block; the normal launch-as credential is never
read or changed. The ConPTY path additionally requires a target-user marker to
arrive through the terminal output bridge.

To exercise password-stdin registration with the same real behavior test,
supply the password as a `SecureString`:

```powershell
$password = Read-Host 'Target account password' -AsSecureString
.\tests\Invoke-LauncherAcceptanceTest.ps1 `
    -TargetUser RestrictedUser `
    -Password $password
```

The build wrapper can launch the same interactive test after building:

```powershell
.\build.ps1 `
    -Configuration Release `
    -RunAcceptanceTest `
    -TargetUser RestrictedUser
```

## License

`launch-as` is licensed under the GNU General Public License version 3 only.
A short copyright and no-warranty notice accompanies the usage text when the
launcher is called without parameters or with invalid parameters.
See [LICENSE](LICENSE).
