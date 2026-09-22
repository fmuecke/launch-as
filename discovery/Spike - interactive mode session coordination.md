# Interactive mode session coordination

Decision date: 2026-09-21

## Goal

Support GUI programs on the authenticated caller's `WinSta0\Default` while preserving an
independent target logon session. Shared-desktop GUI mode deliberately accepts the UI attack
surface (screen, window, clipboard, and input interaction), but should not give the target the
caller's logon SID or the resulting access to caller process objects.

These are separate properties:

| Launch path | Desktop session | Target logon SID | Shared UI surface | Caller-process surface |
| --- | --- | --- | --- | --- |
| Historical `CreateProcessWithLogonW` client | Caller | Includes caller logon SID | Open | Open |
| Broker console mode | Session 0, noninteractive | Independent | Closed | Closed |
| Intended broker interactive mode | Caller | Independent | Open | Closed |

## Verified learning

An interactive Windows Sandbox probe compared the same controlled window from two contexts:

- The connected caller ran in session 1 on `WinSta0` and saw the window.
- A scheduled `LocalSystem` process ran in session 0 on `Service-0x0-3e7$`.
- The Session-0 process successfully opened a `WinSta0\Default`, but it opened the identically
  named objects in session 0 and could not see the session-1 window.
- `WTSGetActiveConsoleSessionId` returned `0xFFFFFFFF` in the connected Sandbox session. It is not
  a valid selector for an authenticated caller and must remain diagnostic only.

Therefore the Session-0 broker cannot directly lease access on another session's interactive
window station through `OpenWindowStation`. Some code already running in the authenticated caller's
session must perform the DACL change.

The historical `CreateProcessWithLogonW` path remains a valid low-complexity compatibility option.
It is not equivalent to the intended broker boundary: the client handles a clear-text password,
receives powerful child handles, and the target carries the caller logon SID. Both attack surfaces
are accepted in that design.

## Decision

Use a caller-side ACL lease for the first broker-owned interactive-mode slice. Keep a
session-local SYSTEM coordinator as a fallback, not as the starting design.

The selected flow is:

1. The broker authenticates the pipe caller and cross-checks its session identity.
2. The broker performs `LogonUserW`, retains the primary token, and extracts the unique child logon
   SID.
3. The broker sends only a nonce, the fixed desktop name, and the child logon SID to a coordinator
   already running as the caller in that session.
4. The coordinator adds minimum, explicit ACEs for that logon SID to its own `WinSta0` and
   `Default` desktop, then acknowledges the nonce.
5. The broker sets `TokenSessionId`, creates and validates the child, and retains the Job, profile,
   credential, token, and lifecycle authority.
6. When the complete process tree exits, the coordinator removes only the ACEs added for that
   lease. It never restores a whole saved DACL.

The coordinator may initially be the launcher plus a small background lease lifetime. It must
never receive the managed-account password, a reusable target primary token, or a privileged target
process handle.

If later environments show that the caller-side coordinator cannot obtain
`READ_CONTROL | WRITE_DAC` on its own interactive objects, the fallbacks are:

1. A narrowly scoped, protected SYSTEM coordinator in the caller session, with the same no-secret
   and no-target-token contract.
2. An explicit `CreateProcessWithLogonW` compatibility mode that documents both open surfaces and
   restores client-side credential ownership.
3. A separate RDP, Windows Sandbox, or VM session for GUI workloads that are not trusted with the
   caller's shared desktop.

A persistent account-SID ACE is not selected. It would grant ambient desktop access to every logon
of the managed account instead of scoping access to one unique child logon SID.

## Probe result and evidence boundary

The caller-side ACL gate passed in a fresh interactive Windows Sandbox guest. The original
test-local implementation was then replaced by the production launcher component
`InteractiveDesktopAclLease`; its retained passing run is
`out/windows-sandbox-interactive-session-probe/2aa3fd01e896474cb037f29b26db8aee`.

The probe used `Start-Process -Credential` to run the fresh local standard account
`LaunchAsDevCaller` on the connected session's desktop. The process reported:

- session 1 on `WinSta0`;
- token user SID `S-1-5-21-2047949552-857980807-821054962-1000`;
- administrator membership `false` and elevation `false`; and
- native process exit code 0.

For both `WinSta0` and `Default`, it:

1. Opened that session's `WinSta0` and `Default` with the minimum rights needed to read and modify
   their DACLs.
2. Added one exact ACE for a synthetic logon-SID-shaped SID.
3. Verified the ACE was present with the intended mask.
4. Removed only that exact ACE.
5. Verified that the remaining DACL was semantically identical to the original.
6. Reported the token user, elevation, administrator membership, session id, object names, exact
   Win32 errors, cleanup result, and native exit code through the shared result file.

Every read, add, verify, remove, and final-verify Win32 result was 0. The exact lease ACE was present
after each add, absent after each remove, and the sorted final ACE fingerprints were identical to
the originals. An independent before/after SDDL comparison outside the production component also
matched for both objects. The probe never restored a saved whole DACL.

The production component rejects SIDs that are not shaped as a Windows logon SID. It grants only
object-specific GUI rights: `WINSTA_ALL_ACCESS` for the window station and the complete set of
desktop-specific rights for the desktop. It does not grant `WRITE_DAC`, `WRITE_OWNER`, or another
standard ownership right to the target logon SID. The coordinator itself opens the objects with
`READ_CONTROL | WRITE_DAC`, retains those handles for the lease, and retries exact removal during
destruction if an explicit release failed.

This completes the caller-session ACL lease-owner primitive. It does not yet prove that a
broker-created target can use the granted masks or cover broker-to-coordinator authentication,
detached coordinator lifetime, RDP, Fast User Switching, coordinator crashes, launcher
disappearance, and broker restart. Those remain end-to-end acceptance gates. The next vertical
slice should add the authenticated broker/coordinator handshake and exercise a broker-created
target token against the lease, with removal after normal Job completion.
