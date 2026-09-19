# Changelog

## [1.2.0-preview] - 2026-09-15

- Changed: Setup installs, updates, and uninstalls `launch-as.exe` and `launch-as-admin.exe`
  alongside the broker and console host in `%ProgramFiles%\launch-as`.
- Added: `Setup-LaunchAs.ps1 -Command Install|Update|Uninstall` supports explicit automation;
  `-Force` accepts the corresponding confirmation.
- Security: Setup compares the source and installed `launch-as.exe` product versions as SemVer and
  refuses a downgrade.
- Fixed: A service update preserves an existing authorised caller policy instead of silently
  transferring launch authority to the account that ran the update.

## [1.1.0] - 2026-09-14

- Added: `launch-as-admin create`, explicit `create <account> --takeover`, `list`, `forget`, and
  `delete` for launch-as-managed accounts. Ownership is SID-pinned; forced takeover creates a
  missing account, while unforced takeover rejects it. `delete` affects only accounts owned by
  launch-as, while `forget` leaves the Windows account unchanged.
- Changed: Managed accounts support up to two concurrent sessions each and the broker supports
  four globally. Further launches fail with `session_limit_reached` / `ERROR_BUSY`.
- Changed: The broker rotates each managed-account password per launch, uses it to reset and log
  on to the account, then clears its plaintext copy from memory.
- Changed: `Setup-LaunchAs.ps1` creates or explicitly takes over its default managed account only
  after a successful install or update; takeover replaces the broker-owned password.
- Security: Hardened broker startup and storage against control-pipe squatting, untrusted
  `%ProgramData%` ownership, reparse points, environment-derived data paths, and tampered account
  configuration records.
- Security: Rejects managed accounts with administrative or non-standard privileges, uses a
  privilege-restricted Medium-integrity logon token, validates local working directories before
  launch, and clears generated password buffers.
- Security: Setup self-elevation validates the default account name, preserves paths with spaces,
  and launches PowerShell from `PSHOME` rather than a user-controlled `PATH` lookup.
- Security: Hardened terminal and service boundaries with programmatic pipe ACLs, bounded control
  connections and resize handling, audit-field validation, a dedicated service SID, the service
  privileges required for profile loading, and native binary mitigations.
- Fixed: Setup repairs the enrollment directory before broker startup.
- Fixed: Preserved target exit codes in broker mode; redirected stdin EOF no longer cancels the
  target; terminal shutdown no longer waits indefinitely for console input.
- Fixed: Drains job trees before profile cleanup, bounds failed-session teardown, and always
  releases session and worker capacity.
- Fixed: Correct Windows command-line quoting, immediate Win32 error capture, fail-fast handling
  of failed impersonation reverts, and strict null-terminated Win32 path boundaries.
- Changed: Removed obsolete Credential Manager implementation code. `build.ps1 -RunAllTests` now
  runs non-elevated CTest coverage, elevated integration coverage in Windows Sandbox, and the
  installed-service acceptance suite; the broker-command test no longer needs an installed service.

## [1.0.0-preview] - 2026-08-09

- Added: Passwordless, same-pane console launches as an enrolled local standard account.
- Added: Separate logon sessions and a noninteractive desktop for launched console tools; they
  cannot read or terminate the caller's processes or inspect the caller's windows.
- Added: `launch-as-admin` to enroll, list, and unenroll multiple local accounts.
- Changed: An enrolled account runs one session at a time. Its password is generated for each
  launch, used only to log on, then discarded; a second launch fails immediately.
- Added: `Setup-LaunchAs.ps1` for interactive install, update, uninstall, and optional default
  account enrollment.
- Changed: Existing Credential Manager registrations and credential-mode options no longer work;
  enroll accounts through `launch-as-admin` instead.

## [0.3.2] - 2026-07-30

- Changed: Clarified that the returned error code messages are only corresponding win32 codes
- Changed: Using standard Win32 codes to reduce collisions with pass-through child exit codes.
- Fixed: Resizing in `--terminal` sessions
- Fixed: UTF-8 output configuration now runs before internal pseudoconsole-host dispatch.

## [0.3.1] - 2026-07-29

- Changed: Nonzero child exit codes now include the corresponding Windows message.
- Changed: `--terminal` is the sole current-pane option.
- Changed: Saving a prompted credential is opt-in.
- Fixed: Closing the host terminal now ends the related `--terminal` session.
- Fixed: Error codes of launch-as are now propagated properly

## [0.3.0] - 2026-07-28

- Added: First standalone release for launching a program as another local standard user.
- Added: Credential Manager support for remembered, prompted, and unattended starts.
- Added: `--terminal` for Windows Terminal and VS Code panes.
- Changed: Direct invocation is supported alongside the explicit `run` subcommand.

[1.2.0-preview]: https://github.com/fmuecke/launch-as/releases/tag/v1.2.0-preview
[1.1.0]: https://github.com/fmuecke/launch-as/releases/tag/v1.1.0
[1.1.0-preview]: https://github.com/fmuecke/launch-as/releases/tag/v1.1.0-preview
[1.0.0-preview]: https://github.com/fmuecke/launch-as/releases/tag/v1.0.0-preview
[0.3.2]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.2
[0.3.1]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.1
[0.3.0]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.0
