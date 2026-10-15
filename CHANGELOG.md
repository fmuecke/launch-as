# Changelog

## [Unreleased]

- Fixed: Shared-scope diagnostics follow active logged requests, so a failed or closing launch cannot take final restoration out of another session's text log.
- Clarified: Directory pins prevent rename/deletion by every user until scope restoration; added focused coverage for pin lifetime.
- Added: `--log` appends launch steps and read-scope deny/exclusion decisions to the caller's `%LOCALAPPDATA%\launch-as\launch-as.log`. Broker diagnostics also use the Application event log (`launch-as-broker`, event ID 7).
- Added: `--restrict-access` for console and interactive launches. It adds a write-restricted token, ensures temporary account-SID denies on each launch, and removes them after the account's last session tree exits. Concurrent restricted sessions share their working directories. `--low-integrity` remains independently available. Read restriction skips empty optical/removable drives reporting "not ready"; other volume and ACL failures still reject launch. Inserted media is considered at the next launch.
- Security: Read restriction changes only folder DACLs. Tokens lose traversal bypass so base-folder denies also block protected children through ordinary paths. File-ID opens bypass these denies; loose ancestor files and allowed system trees retain normal ACLs. New base folders and mounts need another launch. Remote shares, unmounted volumes, existing handles, and hard-link aliases in allowed trees remain outside this path restriction. Abrupt broker termination can leave temporary denies behind.
- Security: `--low-integrity` labels the profile and working tree using the account's permissions. Labels persist and may be partially applied on failure. This is not a directory allowlist: other writable Low objects remain accessible; remote shares, network access, and services acting on the workload's behalf are outside this control. Access restriction still permits writes granted to its restricting SIDs within accessible paths.
- Fixed: Read-scope enumeration counts loose files against its work budget and checks its deadline during enumeration, bounding preparation work between filesystem calls even in large ancestor folders.
- Tests: Added option/protocol and read/write-scope tests, plus installed-broker Windows Sandbox acceptance for both launch modes, runtime compatibility, descendants, shared-scope lifetime, and failed-launch restoration.

## [1.3.0] - 2026-09-21

- Fixed: Resizing the terminal no longer duplicates or overwrites earlier output (visible with
  full-width content such as Claude Code diffs). `launch-as-conhost.exe` now hosts the target with
  Microsoft's ConPTY 1.24 (`conpty.dll` and `OpenConsole.exe`), which setup installs beside it,
  instead of the inbox Windows ConPTY, which repaints its whole viewport on every resize.
- Security: The installed trust boundary now includes the bundled `conpty.dll` and
  `OpenConsole.exe`; updates to them ship with launch-as, not Windows Update.
- Added: Public `--mode interactive` launches GUI targets on the authenticated caller's shared
  `WinSta0\Default` desktop while retaining an independent managed-account logon SID.
- Security: The launcher holds an exact child-logon-SID desktop ACL lease until the broker reports
  the complete interactive process tree exited; the installed service now retains and enables
  `SeTcbPrivilege` only for cross-session token assignment.
- Tests: Added one fresh Windows Sandbox installed-service acceptance path through the public CLI,
  including caller-session placement, a visible GUI window, independent logon SID, and lease
  release. Crash recovery, RDP, Fast User Switching, launcher disappearance, and broker restart
  remain additional acceptance cases.
- Changed: (internal) Modfying integration tests are now encapsulated by using the Windows Sandbox as
  as test environment.
- Changed: (internal) Restructured source according to the different aspects (admin, broker, common,
  conhost, launcher, protocol, and terminal) to improve maintainability.
- Added: full automated github release workflow

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
- Changed: Removed obsolete Credential Manager implementation code. Local CTest no longer registers
  privileged tests, `build.ps1 -RunAllTests` runs their automated coverage in Windows Sandbox and
  offers automated interactive acceptance from a fresh standard guest caller, and no test requires
  a host-installed broker or managed account.

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

[1.3.0]: https://github.com/fmuecke/launch-as/releases/tag/v1.3.0-preview
[1.2.0-preview]: https://github.com/fmuecke/launch-as/releases/tag/v1.2.0-preview
[1.1.0]: https://github.com/fmuecke/launch-as/releases/tag/v1.1.0
[1.1.0-preview]: https://github.com/fmuecke/launch-as/releases/tag/v1.1.0-preview
[1.0.0-preview]: https://github.com/fmuecke/launch-as/releases/tag/v1.0.0-preview
[0.3.2]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.2
[0.3.1]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.1
[0.3.0]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.0
