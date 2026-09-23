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
`out/windows-sandbox-interactive-session-probe/fd17d091683e47b5a46e7b459c1e708e`.

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

The production component rejects SIDs that are not shaped as a Windows logon SID. It grants
`READ_CONTROL` plus the object-specific GUI rights: `WINSTA_ALL_ACCESS` for the window station and
the complete set of desktop-specific rights for the desktop. It does not grant `WRITE_DAC`,
`WRITE_OWNER`, `DELETE`, or another standard mutation right to the target logon SID. The
coordinator itself opens the objects with `READ_CONTROL | WRITE_DAC`, retains those handles for the
lease, and retries exact removal during destruction if an explicit release failed.

## Authenticated handshake slice

The next production slice adds the broker/client and caller-session coordinator halves of a
one-connection lease protocol. The caller creates a random, first-instance, local-only message pipe
whose DACL grants access only to LocalSystem. Before reading a request, the coordinator requires:

- a LocalSystem named-pipe impersonation token in session 0;
- a nonzero kernel-reported client process id; and
- a kernel-reported named-pipe client session id of 0.

The standard-user coordinator cannot open an arbitrary LocalSystem process token for a redundant
user-SID cross-check; the live probe returned `ERROR_ACCESS_DENIED` for that attempt. Authentication
therefore uses the pipe DACL, the impersonated client token, and named-pipe process/session metadata.
This does not trust a client-supplied identity field.

After peer authentication, the coordinator accepts only the versioned acquire and release messages
defined in `BrokerProtocol`. Acquire contains exactly the nonce, fixed `WinSta0\Default` desktop,
and child logon SID. Release contains only the same nonce. Unexpected fields, account-SID-shaped
values, nonce mismatches, duplicate fields, and malformed operations are rejected. The broker-side
connection remains open for the lease lifetime; closing it early destroys the coordinator's RAII
lease and removes the exact ACEs.

A fresh Windows Sandbox run exercised the production components across the real identity and
session boundary:

- the coordinator ran as the non-administrator, non-elevated session-1 caller;
- the client ran as LocalSystem in session 0 and used its token's real logon SID;
- acquire and release both returned zero;
- the connection remained held after acquire; and
- independent before/after DACL snapshots matched for both `WinSta0` and `Default`.

The retained passing run is
`out/windows-sandbox-interactive-session-probe/fd17d091683e47b5a46e7b459c1e708e`.

This completes the authenticated lease-channel primitive.

## Broker-created target slice

The next internal slice now connects the production token and process-launch pieces to that lease
channel. It deliberately does not expose public interactive mode yet. In a fresh Windows Sandbox
guest, a Session-0 LocalSystem probe used the production account provisioner and logon path to:

1. Create a temporary standard managed account and its restricted primary token.
2. Assign that token to the authenticated caller coordinator's session 1.
3. Acquire the `WinSta0\Default` lease for the target token's own logon SID.
4. Load the target profile and environment, create a native GUI target suspended, assign it to the
   broker Job, validate the child session and logon SID, and resume it.
5. Wait for the complete Job tree to reach zero before releasing the lease and deleting the
   temporary account.

The first live attempt exposed an important mask requirement: object-specific GUI rights alone let
`CreateProcessAsUserW` return successfully, but the child exited `0xC0000142` before its entry point.
A target-side diagnostic narrowed that to `user32.dll` returning `ERROR_DLL_INIT_FAILED` (1114).
Adding `READ_CONTROL` to both temporary ACEs fixed initialization; no `WRITE_DAC`, `WRITE_OWNER`,
or `DELETE` grant was needed.

The final probe used the normal statically linked GUI executable. The target itself reported
session 1, `WinSta0`, `Default`, and the exact logon SID used for the lease. The caller-session
coordinator independently observed its visible window. The Job was empty before release, release
returned zero, and the independent before/after DACL comparison matched. The retained passing run
is `out/windows-sandbox-interactive-session-probe/b5c19f51a91442908abcdbd6f94bf186`.

This proves normal-completion behavior for the internal broker launch primitive in one connected
Windows Sandbox session. At this point it did not wire interactive mode into the installed broker
request or public CLI, and it did not prove detached coordinator lifetime, RDP, Fast User
Switching, coordinator crashes, launcher disappearance, or broker restart.

## Private broker-request slice

The fourth internal slice wires the lease and launch primitives through a still-private production
broker request. An interactive request must contain exactly a lease-pipe name and nonce in its
`interactive` object. Session id, caller SID, and caller logon SID are not request fields; unknown
fields are rejected. `BrokerPipeServer` obtains the session id and logon SID from the impersonated,
authenticated pipe caller, and `BrokerApplication` uses only that captured identity when assigning
the target token to a session and acquiring the lease.

Interactive requests have detached control-connection lifetime: closing the initiating control
pipe does not terminate the target. The broker worker retains the kill-on-close Job and waits for
the complete process tree. On normal completion, service stop, or another worker teardown path it
terminates or confirms the Job tree before `BrokerApplication::FinishSession` releases the desktop
lease and session admission slot. The lease remains broker-owned and keyed by request id; the
caller-side coordinator never receives the managed-account password, target token, or target
process handle.

Evidence is deliberately split at the boundary it exercises:

- Focused protocol and broker-pipe tests prove the exact private request shape, rejection of
  client-supplied identity, dispatch with the authenticated pipe caller's session/logon SID, and
  survival of control-pipe disconnect until a delayed Job tree exits.
- A fresh interactive Windows Sandbox run exercises `BrokerApplication`, the production account
  provisioning/logon path, the real caller-session ACL coordinator, the production GUI launch,
  Job-before-release ordering, and final DACL restoration. The retained passing run is
  `out/windows-sandbox-interactive-session-probe/51810e492bb9409d9470c501f8dd953c`.

These results do not yet form one installed-service end-to-end test: the Sandbox probe enters at
the application seam while the pipe path is proven in focused tests. The public CLI also does not
yet create or retain the coordinator and emits only console requests. That public coordinator/CLI
path plus installed interactive acceptance is the next feature slice. Crash recovery, RDP, Fast
User Switching, launcher disappearance, and broker restart remain additional acceptance work.

## Public coordinator and installed-service slice

The public client now accepts `--mode console|interactive`, with console remaining the default.
For interactive mode it creates a unique first-instance, SYSTEM-only lease pipe and nonce, sends
their names in the otherwise identity-free broker request, and coordinates the lease from the
caller's session. The launcher stays alive until the broker releases the lease after the complete
GUI process tree exits. It never receives the managed-account password, target token, or target
process handle.

The installed service requires `SeTcbPrivilege` in its SCM required-privileges list so the broker
can enable that privilege only while assigning the restricted target token to the authenticated
caller's session. The first installed run exposed the omitted service configuration through
`ERROR_NOT_ALL_ASSIGNED`; adding the privilege completed the intended least-duration enablement.

A fresh Windows Sandbox run then exercised the public CLI, production-named installed service,
authenticated caller identity, coordinator handshake, target creation, and release in one path.
The target reported the caller's session, `WinSta0`, `Default`, and a logon SID different from the
caller's; the caller observed the target's visible window; and the launcher returned success only
after the target tree exited and the ACL lease was released. The retained passing run is
`out/windows-sandbox-acceptance/1f50a9f293c64685a207f512d887f542`.

This is one normal-completion acceptance case. Crash recovery, RDP, Fast User Switching, launcher
disappearance, and broker restart remain additional acceptance work.
