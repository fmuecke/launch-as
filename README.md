# launch-as

A small Windows launcher that runs any executable as a **different local
standard user**, without retyping a password every time.

`launch-as` signs in with `CreateProcessWithLogonW`, optionally caches the
target account's password in the current user's Windows Credential Manager, and
can host the launched program right inside your existing terminal pane through
ConPTY — so a nested shell under another identity feels like a normal tab.

**Scope:** `launch-as` is for a trusted regular Windows user who wants to run
tools such as coding agents in separate restricted local identities. It is not
an elevation tool: it never launches a program as Administrator and rejects
administrative target accounts.

```powershell
# Store the target account's password once
.\launch-as.exe register --user RestrictedUser

# Run something as that user, reusing the stored credential
.\launch-as.exe --user RestrictedUser -- C:\Windows\System32\cmd.exe

# Or open a nested shell in the current Windows Terminal / VS Code pane
.\launch-as.exe --user RestrictedUser --terminal `
    -- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoExit
```

## Why

Running a build, tool, or shell under a restricted local account is a simple way
to contain what it can touch. Doing that repeatedly usually means a password
prompt every time or a plaintext secret in a script. `launch-as` keeps the
convenience of a one-time setup while keeping the password out of your scripts.

This matters most for processes that act on their own. AI coding agents such as
**Claude Code** or **GitHub Copilot** run commands, edit files, and invoke tools
with whatever rights their host shell holds. Launching them under a dedicated
restricted user separates the agent's identity from your own: it acts as its own
account, reaches only the resources you grant that account, and its actions stay
attributable to it rather than blending into your session — all without giving up
the convenience of your normal terminal.

## Features

- **Run as another local user** from an absolute executable path, with an
  optional working directory and full argument pass-through after `--`.
- **Credential Manager integration** — register a password once; later launches
  reuse it with no prompt. Stale passwords are detected and can be refreshed.
- **Flexible credential modes** — `auto` (prompt if missing), `stored`
  (unattended, never shows UI), and `prompt` (ephemeral, never saved).
- **Terminal mode (`--terminal`)** hosts an interactive process through ConPTY in
  your current terminal pane instead of spawning a separate console window.
- **Safe by construction** — refuses administrative target accounts, verifies the
  child's token SID before resuming it, and zeroes password buffers after use.

## Requirements

- Windows 10 version 1809 or newer (terminal mode requires the same minimum)
- Visual Studio with the MSVC C++ toolchain and a Windows SDK
- CMake 3.25 or newer, `clang-format` on `PATH`, and PowerShell

## Build

```powershell
.\build.ps1                              # configure + build x64 Release
.\build.ps1 -Configuration Debug
.\build.ps1 -Configuration Release -Test  # build and run the CTest suite
```

The release binary links the static MSVC runtime, so it needs no separately
installed Visual C++ Redistributable.

## Documentation

See **[DESIGN-DECISIONS.md](DESIGN-DECISIONS.md)** for the complete reference: every CLI option, the
credential and security model, the ConPTY / named-pipe terminal bridge, and the
build and acceptance test details. See [CHANGELOG.md](CHANGELOG.md) for release
notes.

## License

`launch-as` is licensed under the GNU General Public License version 3 only.
See [LICENSE](LICENSE).
