# launch-as-broker — Implementation Specification

Status: Phase 1 console implementation · Language: C++ (native Windows service) · Supersedes the earlier `spec.md` and the retired pre-broker design notes

---

## 1. Phases and delivery order

**Phase 1 — ship a working console-agent path now:** move restricted-account credentials **and**
privileged process creation out of the interactive `launch-as` client into a dedicated Windows service
(`launch-as-broker`). Ship the **`console` (ConPTY) mode** as a usable daily-driver path for console
agents, with a clean, independent logon session instead of one derived from the interactive user's
logon. Console mode requires **no interactive-desktop support**: it does not enter the caller's
session or request access to `WinSta0` or `Default`.

**Phase n — GUI applications, when selected later:** support applications such as VS Code or Claude
Desktop. GUI support is not a prerequisite for shipping Phase 1 and retains its distinct shared-desktop
security residual until separately designed and accepted.

The service provides one narrow operation:

> An authorised interactive user asks the broker to start a program of their choice as a configured launch-as-managed Windows account, in a chosen session mode.

The caller never receives, reads, or decrypts the restricted account password, and the resulting child process never carries the interactive user's logon SID.

---

## 2. Why this exists (the problem being fixed)

The current client launches with `CreateProcessWithLogonW(user, ".", pw, LOGON_WITH_PROFILE, …)`. That call routes through the secondary-logon service and, by design, **grafts the interactive user's logon SID onto the new token** so the child can reach `WinSta0\Default`. The child's `TokenUser` is genuinely `LaunchAsUser` (file ACLs isolate correctly), but the grafted logon SID has a second, unwanted effect:

- Every process carries a default DACL ACE granting its **logon SID** the mask `0x121411` (`TERMINATE | VM_READ | QUERY_INFORMATION | QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE`).
- Because the agent token now contains the interactive user's logon SID as a group, the agent can `OpenProcess` the interactive user's processes and **read their memory or terminate them** — no `SeDebugPrivilege` required.

This is **Surface 2** (process/kernel-object reach). It exists purely because the token shares the interactive logon session. A genuine, independent `LogonUser(LaunchAsUser)` mints a **new** logon session with its **own** logon SID, which no longer matches the interactive user's process DACLs → Surface 2 closes.

There is also **Surface 1** (UI/desktop reach): any process on `WinSta0\Default` can enumerate windows, screen-capture the framebuffer (not integrity- or UIPI-gated), and inject input laterally. Surface 1 is a property of *being on the shared desktop*, independent of the token's SIDs.

**Primary goal of this service:** close Surface 2 for all launches, by never deriving the child token from the interactive logon.
**Secondary goal:** keep the account password out of the client and out of IPC (broker-owned credential).
**Later GUI phase:** Surface 1 for GUI mode remains a documented residual — see §7.

---

## 3. Security goals and non-goals

Protect against:

- an agent process (running as `LaunchAsUser`) reading/terminating the interactive user's processes (**Surface 2**);
- an agent process or an ordinary interactive-user process reading the stored account password;
- password exposure via files, command lines, environment, logs, dumps, or IPC;
- unauthorised local users invoking the broker.

First version does **not** protect against:

- a compromised local administrator or kernel-level malware;
- a compromised service binary or installer;
- LSASS credential theft by an administrator;
- **GUI applications** — support for VS Code, Claude Desktop, and other interactive applications is a later phase. A GUI child shares the caller's desktop by necessity; this documented residual requires separate acceptance.

---

## 4. Naming and fixed identifiers

| Thing | Value |
|---|---|
| Service name | `launch-as-broker` |
| Restricted account (local) | `LaunchAsUser` (referenced as `.\LaunchAsUser`) |
| Default profile id | `LaunchAsUser` |
| Control pipe | `\\.\pipe\launch-as-broker.v1` |
| Config + internal enrollment-data root | `%ProgramData%\launch-as\` |
| Internal enrollment store | `%ProgramData%\launch-as\enrollments\` |
| Service binary | `%ProgramFiles%\launch-as\launch-as-broker.exe` |
| Console host helper | `%ProgramFiles%\launch-as\launch-as-conhost.exe` (console mode only) |

All configuration, internal enrollment-data, and binary paths: ACL `SYSTEM:F`, `Administrators:F`, `Users:RX` (the enrollment directory grants no `Users` access).

---

## 5. Architecture

```text
                 interactive user (e.g. fmuecke, session N)
                          │
     ┌────────────────────┴─────────────────────┐
     │ launch-as client (as the interactive user)│
     │  - opens control pipe                     │
     │  - sends LaunchRequest {profile, mode,…}  │
     │  - console mode: owns terminal, creates    │
     │    data pipes, bridges stdio               │
     └────────────────────┬─────────────────────┘
                          │ authenticated named-pipe IPC (no password ever)
                          ▼
     ┌──────────────────────────────────────────┐
     │ launch-as-broker  (LocalSystem, session 0)│
     │  1 impersonate caller → SID, session, IL  │
     │  2 authorise against profile              │
     │  3 generate + set temporary password       │
     │  4 LogonUser(INTERACTIVE) → fresh token   │
     │  5 zero password; validate token           │
     │  6 session adapter (interactive | console)│
     │  7 LoadUserProfile / CreateEnvironmentBlock│
     │  8 CreateProcessAsUserW (suspended)        │
     │  9 Job object; resume; audit               │
     └────────────────────┬─────────────────────┘
                          ▼
              LaunchAsUser child (own logon session)
        interactive → caller's WinSta0\Default (GUI)
        console     → noninteractive station + ConPTY
```

**Architectural stance:** the broker is a general-purpose alternate-account launcher for configured launch-as-managed accounts. The client selects a managed account and a mode, then supplies the executable, arguments, and working directory. It cannot read or supply the account password. Per-account execution restrictions are optional future hardening, not a current security boundary.

---

## 6. Launch primitive and service identity (committed baseline)

- Service runs as **`LocalSystem`**. Justification: `CreateProcessAsUserW` requires `SeAssignPrimaryTokenPrivilege` + `SeIncreaseQuotaPrivilege`; the `interactive` adapter's session assignment requires `SeTcbPrivilege`; `LoadUserProfile` requires administrator/SYSTEM. LocalSystem holds all three; enable them explicitly at use and drop otherwise.
- Process creation primitive: **`LogonUserW(LOGON32_LOGON_INTERACTIVE)` → `CreateProcessAsUserW`**.
- Do **not** use `LOGON32_LOGON_NEW_CREDENTIALS` (netonly) — it reuses the caller's local identity and reopens the exact sharing we are removing.

### 6.1 Spec task — token-graft probe (informs a later downgrade)

Before or during Phase 1, verify empirically whether `CreateProcessWithTokenW` (needs only `SeImpersonate`, held by `LocalService`) also grafts the interactive logon SID. Method: launch a child via `LogonUser` + `CreateProcessWithTokenW`, dump `TokenGroups`, check for the interactive user's logon SID, and run the Surface-2 probe (§18). If it does **not** graft, a later hardening step MAY downgrade the service identity from `LocalSystem` to `LocalService`. Until proven, `LocalSystem` + `CreateProcessAsUserW` is the baseline. Record the result in the repo.

**Current record (2026-08-27):** measured in the temporary `LocalSystem` broker experiment. The
broker successfully created the direct identity-probe process with `LogonUserW(INTERACTIVE)` +
`CreateProcessWithTokenW`, but the child exited `0xC0000142` (`STATUS_DLL_INIT_FAILED`) before it
could emit its `TokenGroups` or Surface-2 report. This does not establish whether the interactive
logon SID would be grafted, but it does show that this primitive is not usable for the current
console path in this environment. Phase 1 therefore remains on the `LocalSystem` +
`CreateProcessAsUserW` baseline; no `LocalService` downgrade is justified by this result.

---

## 7. Session modes (current and later adapters)

The launch core is mode-agnostic. A profile selects one adapter.

### 7.1 `console` mode (Phase 1; default for `LaunchAsUser` / Claude Code)

**CLI decision (2026-09-11):** the Phase-1 CLI intentionally has no `--mode console` option while
`console` is the only supported mode. The client selects console mode and still sends the explicit
`mode:"console"` protocol field. Add a CLI mode selector only when another client-visible mode is
implemented.

- Child stays on the **default noninteractive window station** (`Service-0x0-…`). Do **not** set `lpDesktop` to `WinSta0\Default`; do **not** hop the session.
- Do not grant or repair any access to the caller's interactive window station or desktop. Console
  terminal I/O is solely the ConPTY/named-pipe bridge below.
- I/O via **ConPTY + named pipes**: the broker launches `launch-as-conhost.exe` as `LaunchAsUser`; the host creates the pseudoconsole, runs the target inside it, and connects per-session input, output, and resize pipes back to the client's terminal. (Reuse the existing `PseudoConsoleHost` / `TerminalBridge` code; move the child-creation call behind the broker.)
- Data pipes are created by the **client** (in the interactive user's context) with a DACL granting connect+RW to `LaunchAsUser` only; names are random per session with `FILE_FLAG_FIRST_PIPE_INSTANCE`. The broker passes the names in the request; it never touches stdio and never receives enrollment-store handles.
- **Surfaces:** Surface 1 **closed** (no interactive desktop), Surface 2 **closed** (independent logon SID).

### 7.2 `interactive` mode (later GUI phase; e.g. VS Code or Claude Desktop in the user's session)

The broker remains a headless Session-0 service; it does **not** need its own interactive desktop.
It creates the restricted child in the authenticated caller's existing session and attaches that
child to that session's `WinSta0\Default`. This is a cross-session launch, not an attempt to make
the service interactive.

Requires crossing from session 0 into the caller's interactive session. Steps:

1. From the authenticated caller token, obtain the caller's **session id**; verify it belongs to the
   caller. Do not accept a client-supplied session id or blindly use `WTSGetActiveConsoleSessionId`:
   RDP, Fast User Switching, multiple logons, and disconnected sessions make the active console
   ambiguous.
2. `LogonUserW(INTERACTIVE)` → primary token (its own logon SID; session 0 by default).
3. `SetTokenInformation(TokenSessionId, callerSession)` — needs `SeTcbPrivilege`.
4. Extract the **child's own logon SID** (`GetTokenInformation(TokenLogonSid)`), and add the
   minimum scoped ACEs for **that logon SID** — not the account SID — to the caller session's
   `WinSta0` window station and `Default` desktop. `lpDesktop` selects the desktop but does not
   grant access on its own. Record exactly which ACEs this launch added so failures and teardown
   remove only those ACEs; account-SID grants can leave persistent cross-session access.
5. `LoadUserProfile` + `CreateEnvironmentBlock` (GUI apps need `HKCU`/`%APPDATA%`).
6. `STARTUPINFO.lpDesktop = L"WinSta0\\Default"`; `CreateProcessAsUserW`.
7. On process-tree exit, launch failure, or teardown: remove the temporary winsta/desktop ACEs,
   `DestroyEnvironmentBlock`, `UnloadUserProfile`, and close handles.
- **Surfaces:** Surface 2 **closed** (the token holds the child's own logon SID, never the interactive user's). Surface 1 **open and accepted** — the GUI child is physically on the shared desktop (can screenshot, enumerate, and inject laterally into same-IL windows). This is the documented, postponed residual. Use the account/logon SID scoping above so no *persistent* cross-session desktop access is left behind.

> Rationale for why Surface 2 stays closed in GUI mode: granting the child's *own* logon SID rights on the interactive desktop gives desktop access without placing the interactive user's logon SID into the child token — so the interactive user's process default-DACL ACE still does not match.

#### 7.2.1 No normal-user token helper

Do not move GUI or terminal plumbing into a helper running as the interactive user if that requires
passing it the restricted primary token. A process able to control that helper could duplicate or
misuse the token, reopening a privileged-launch boundary. A session-local helper may only be used
after a separate design proves it cannot receive credentials or a reusable restricted token; the
broker retains both and performs `CreateProcessAsUserW` directly. Phase 1 avoids this issue by
keeping terminal ownership in the client and connecting the broker-launched console host through
SID-scoped named pipes.

---

## 8. IPC

Local named pipe `\\.\pipe\launch-as-broker.v1`:

- explicit security descriptor: `SYSTEM:F`; permitted caller SIDs (from profile) connect+RW; deny anonymous and remote (`no NETWORK`, reject `NULL` session);
- message mode; bounded message size; versioned protocol; every field validated; request timeout;
- **never transmits credentials.**

Do not rely on the pipe DACL alone. Per request:

1. `ImpersonateNamedPipeClient`;
2. query the caller token → caller SID, session id, integrity level;
3. `RevertToSelf` immediately;
4. authorise the captured identity against the selected profile.

Impersonation failure is a **hard failure** (otherwise the request would proceed under the service identity). Secondary check: `GetNamedPipeClientProcessId` → verify the client process user matches.

### 8.1 Request (client → broker)

```json
{
  "version": 1,
  "requestId": "uuid",
  "operation": "launch",
  "profileId": "LaunchAsUser",
  "mode": "console",
  "arguments": ["--resume"],
  "workingDirectory": "C:\\dev\\LaunchAsUser\\repo",
  "console": {
    "pipeIn":  "\\\\.\\pipe\\launch-as-<rnd>-in",
    "pipeOut": "\\\\.\\pipe\\launch-as-<rnd>-out",
    "pipeResize": "\\\\.\\pipe\\launch-as-<rnd>-resize",
    "cols": 120, "rows": 30
  }
}
```

`mode:"console"` is the only supported launch mode in Phase 1. A structurally valid
`mode:"interactive"` request carries no `console` block and receives
`reasonCode:"mode_not_supported"` with `ERROR_NOT_SUPPORTED`; it is not dispatched to a launch
handler. A missing or unknown mode is `invalid_request`. This keeps the explicit switch while
making GUI opt-in when its later phase is implemented.

### 8.2 Response (broker → client)

```json
{ "version": 1, "requestId": "uuid",
  "status": "ok|denied|error",
  "processId": 12345,
  "reasonCode": "…",
  "win32Error": 0 }
```

Responses never contain secrets or internal detail beyond a stable reason code + Win32 error.

---

## 9. Profiles and launch policy

Phase 1 accepts multiple configured launch-as-managed local accounts. The account name is the profile id, all accounts
use the `console` adapter, and the installer authorises one caller SID. The current service checks
that caller identity and the SID-pinned internal configuration record; the client also requires an existing
absolute executable and working directory. It deliberately accepts the caller's command, arguments,
and working directory as a general-purpose alternate-account launch.

A managed account may have more than one live console session. Sessions for the same account
share its account SID, `%USERPROFILE%`, HKCU hive, caches, and any other account-scoped resources;
they are cooperating siblings, **not** a security boundary from one another. Sessions for different
managed accounts use different account SIDs, profiles, HKCU hives, and logon sessions. Every launch,
including a sibling launch for the same account, still receives a fresh logon token and logon SID.

A richer profile record that separates launch policy from the Windows account remains a later
GUI/policy-phase extension:

```text
profileId              e.g. "LaunchAsUser"
displayName
accountName            ".\LaunchAsUser"
accountSid             (resolved, pinned)
enrollmentRef          → enrollments\LaunchAsUser.enrollment
authorisedCallerSids   [ SID, … ]           (who may launch)
executionPolicy        passthrough (general-purpose); optional future restrictions
workingDirectoryPolicy any existing directory; optional future root restrictions
environmentPolicy      inherited; optional future allow-list
sessionMode            "console" | "interactive"
profileLoad            bool (LoadUserProfile)
jobLifetime            "control-connection" | "detached"
enabled                bool
```

When that profile policy is implemented, it must validate, default-deny:

- caller SID ∈ `authorisedCallerSids`; profile enabled;
- executable == configured canonical path (canonicalised; reparse/symlink resolved);
- executable **not writable by `LaunchAsUser`**, and not writable by an untrusted caller unless the profile explicitly accepts it;
- arguments comply with `argumentPolicy`;
- working directory inside an approved root (canonical comparison, not string-prefix);
- no unauthorised environment injection;
- for `interactive`: requested/derived session belongs to the caller.

---

## 10. Password model (per launch)

One non-secret internal configuration record per profile pins the local account SID under
`%ProgramData%\launch-as\enrollments\<profileId>.enrollment`. It contains no account password.

- For each launch the service generates a password, sets it with `NetUserSetInfo`, obtains a logon
  token, and immediately zeroes the mutable buffer. The reset-through-`LogonUserW` sequence is
  serialized so another launch cannot replace an account password between reset and logon. No
  reusable account password is persisted.
- The broker admits at most **four** starting or active sessions globally and at most **two** for
  one account. It does not queue excess launches. A launch over either limit receives
  `session_limit_reached` / `ERROR_BUSY`; named-pipe transport contention is not reported as the
  semantic limit.
- The control pipe admits at most **eight** workers total, including authenticated sessions and
  connections that have not completed request parsing. Further clients remain outside the worker
  pool and encounter normal named-pipe contention until capacity returns.
- A service crash closes the kill-on-close job. The next launch generates a new password.
- Passwords never appear in `std::wstring`, exceptions, logs, command lines, environment, registry,
  or IPC.

Every account created or explicitly taken over by the broker is configured `PasswordNeverExpires`
and `UserMayChangePassword=false` so the broker fully owns its password.

---

## 11. Account management operations (create, forget, delete)

A separate **elevated** `launch-as-admin.exe` owns these operations. Normal `launch` requests can
never reach them. `Setup-LaunchAs.ps1` is an interactive convenience wrapper around that executable;
it is not part of the service runtime. Run the admin executable during setup and thereafter for
maintenance.

- **`create <account>`** creates a named standard account, writes a managed-account comment,
  hardens it, and records its SID. The name must not already exist.
- **`create --takeover <account>`** requires an existing eligible account, resets its
  password, hardens it, and records it as launch-as-owned. A disabled target requires `--force` to
  re-enable it. A same-name account with a different recorded SID also requires `--force`.
- **`forget <account>`** removes only the SID-pinned account configuration; it does not change the Windows
  account. **`delete <account>`** verifies the managed SID, refuses while that account has a
  starting or active broker session, deletes the Windows account, and removes its configuration. It
  does not remove the profile directory or other account-scoped residue.

---

## 12. Process-creation flow (per accepted launch)

1. authorise (§8, §9), reserve a global and per-account session slot, and count it as `starting`.
2. under the launch gate, generate and set a fresh password for the managed account.
3. `LogonUserW(accountName, ".", pw, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token)`.
4. zero the password buffer immediately. The launch gate covers reset through logon and the
   process-wide privilege changes used for process creation.
5. validate token: `TokenUser` SID == pinned `accountSid`; `TokenGroups` must **not** contain the local Administrators SID (reuse the client's existing `ProcessHasAccountSid` / `ValidateNonAdministrativeToken` checks, relocated here).
6. optional `CreateRestrictedToken` (disable non-essential privileges; **keep Medium integrity** — Low IL breaks the MSVC toolchain).
7. apply the **session adapter** (§7): `console` → noninteractive + ConPTY host; `interactive` → session hop + desktop-DACL grant.
8. if `profileLoad`: acquire the account's profile lease, loading the profile on its first session,
   and create an environment block. Release the lease and unload only after the account's last
   session has ended. (`LOGON_WITH_PROFILE`-style loading can stall on heavily-used machines.)
9. prepare only explicitly approved inherited handles (console mode: none from the broker; the host connects pipes by name). All broker handles non-inheritable by default.
10. `CreateProcessAsUserW(token, exe, …, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT[ | EXTENDED_STARTUPINFO_PRESENT], env, workingDir, &si, &pi)`.
11. `ProcessHasAccountSid(pi.hProcess)` re-check; on mismatch, terminate and fail.
12. create a **Job object**, `AssignProcessToJobObject` before resume.
13. `ResumeThread`; mark the reserved session `active` and release the launch gate.
14. audit; return PID.
15. teardown: close only this session's Job, ConPTY, control-pipe, token, thread, and process handles;
   release its profile lease and session slot; zero any residual secret buffers.

---

## 13. Lifecycle / Job object

Per launch, one control connection, broker worker, ConPTY pipe set, console host, and Job object.
The implemented counter tracks reserved sessions per account and globally. The target lifecycle
registry adds distinct `starting`, `active`, and `draining` states plus account-scoped profile
leases. Closing one connection tears down only that session; service stop sets the shared stop
event, kills every Job, and joins every worker. Lifetime is **per-profile policy**:

- **`control-connection`** (default for `console`): the Job handle's lifetime is tied to the client's **control-pipe connection** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Client exit/crash/Ctrl-C → control pipe breaks → broker closes the Job handle → the whole child tree (agent + spawned compilers) dies. This is the dead-man switch, for free. Exit is observed by the client as **data-pipe EOF**; the broker need not relay exit codes.
- **`detached`** (default for `interactive`/GUI): the GUI app (VS Code) should outlive the launching client. Assign to a Job for tracking/limits but **without** kill-on-close, or hand the Job to a session-scoped owner. Do not kill on client disconnect.

A Job object is **not** a security boundary — the account, filesystem ACLs, network policy, and token remain the isolation boundaries.

---

## 14. Installation / setup phase (demand-start, prompt-free launches)

The installer/setup runs **elevated once** and must:

- install the service binary under `%ProgramFiles%\launch-as\`, path fully qualified and quoted;
- create the service `launch-as-broker` as **`LocalSystem`**, **`start= demand`**;
- **delegate `SERVICE_START` to the launcher's caller SID (or a dedicated group)** via `sc sdset` / `SetServiceObjectSecurity`, so day-to-day launches start the service with **no UAC prompt**;
- create `%ProgramData%\launch-as\{,enrollments}` with restrictive ACLs (§4);
- register the Event Log source;
- create the configured `LaunchAsUser` account and record it as managed (§11);
- on update, install the new broker first and then take over the configured default account,
  replacing its broker-owned password; report failure if either operation fails;
- optionally create Firewall rules (separate, out of scope here);
- deny ordinary users any right to replace/reconfigure the service or its files;
- support clean uninstall with optional secure credential deletion.

Runtime: the client calls `StartService` (permitted by the delegated DACL, no prompt) → connects → broker self-stops after idle.

> `sudo`/admin elevation is **not** an alternative: it reaches only High-integrity admin (still lacks `SeAssignPrimaryToken`) and prompts every time. The one-time install + `SERVICE_START` delegation is what gives prompt-free on-demand launches.

---

## 15. Audit logging (Windows Event Log)

The broker writes secret-free Application events for allowed/rejected launches and configuration
operations. Each event includes: requestId, operation, account/profile id, caller SID, caller
session id, allow/deny result, resulting PID when applicable, and Win32 error. The Event Log
adds the timestamp and source identity.

Never log: passwords, internal account-configuration records, full sensitive command lines, secret-bearing env vars, raw tokens. Use the Event Log, not a user-writable text file.

---

## 16. Failure behaviour (fail closed)

Phase 1 fails closed when caller identity cannot be captured or authorised, the request is malformed or
uses an unsupported mode, the account configuration does not match, password reset or `LogonUser` fails,
the resulting token is administrative or has the wrong account SID, child logon-SID validation fails,
or the terminal/job setup fails. Responses return a stable reason code and Win32 error without
sensitive internals.

The future GUI/policy phase must additionally fail closed for disabled profiles, config-integrity
failures, canonical-path/ACL policy failures, ambiguous sessions, unavailable desktop access, and
all future handle-validation checks.

---

## 17. Threat-sensitive invariants

1. The child token is created by an **independent `LogonUser`** and never carries the interactive user's logon SID.
2. Passwords never cross the client↔broker boundary.
3. The caller chooses a configured **managed account + console command**, never a password. Phase 1 is
   intentionally a general-purpose launcher; executable allow-listing is not an implemented
   security boundary.
4. Authorisation is based on the **actual caller token**, not a claimed name.
5. Managed-account configuration changes require a distinct elevated path.
6. The client validates absolute executable and working-directory paths; the deprivileged console
   host revalidates them before launch. The broker validates only the working directory exists.
   Any future executable or directory restriction must use canonical paths + ACL inspection,
   never string-prefix checks.
7. No client-supplied handle is trusted without validation; no broker handle is inheritable by default.
8. Interactive-mode desktop ACEs are granted to the child **logon SID** (not account SID) and removed on teardown.
9. Every failure path zeroes secrets and closes handles.
10. All IPC/config parsing is length-bounded and versioned.

---

## 18. Acceptance criteria

Credential / authorization:

- an authorised caller can launch the profile; an unauthorised caller cannot connect or launch;
- neither an interactive-user process nor an agent process can read the active password via any supported interface;
- authorised callers may launch arbitrary executables through a managed account; this is intentional general-purpose behaviour, not an executable-policy bypass;
- passwords never appear in logs, command lines, environment, or IPC captures;
- killing one client exposes no broker resources and terminates only its session; failed
  impersonation → immediate rejection;
- two overlapping launches for the same account both succeed, have distinct logon SIDs, and share
  the documented account/profile state; disconnecting either leaves the other running;
- overlapping launches for different managed accounts both succeed and retain distinct account
  SIDs, profiles, HKCU hives, logon SIDs, control connections, and Jobs;
- the third starting/active launch for one account and the fifth globally fail immediately with
  `session_limit_reached` / `ERROR_BUSY`, without disturbing admitted sessions;
- service restart terminates active jobs; the next launch resets the password. Uninstall leaves no
  service or IPC endpoint.

**Derived-token / Surface-2 regression (the core new tests):**

- inside the launched child, `whoami /logonid` returns a logon SID **different** from the interactive user's;
- the child's token `TokenGroups` does **not** contain the interactive user's logon SID;
- the Surface-2 `OpenProcess` probe from the child against the interactive user's processes returns **`VM_READ`/`TERMINATE` DENIED**;
- `console` mode: `EnumWindows` from the child cannot see the interactive user's windows (Surface 1 closed);
- `interactive` mode: the child's token session id equals the authenticated caller's session id, and
  both its process window station and thread desktop identify the caller session's
  `WinSta0\Default`; a desktop named `Default` alone is not sufficient evidence;
- `interactive` mode: Surface 2 tests pass (DENIED) even though the child renders on the shared desktop (Surface 1 intentionally open); after the child exits, the temporary `WinSta0`/`Default` ACEs for the child logon SID are gone;
- `interactive` mode: exercise an RDP or Fast User Switching case and reject an ambiguous or
  disconnected caller session; console-only tests do not establish this path;
- no process running as the interactive caller receives a reusable restricted primary token.

---

## 19. Phases and implementation order

**Phase 1 — shippable broker + boundary, `console` (ConPTY) mode only:**
service scaffold (SCM, demand-start, `sc sdset` delegation), bounded multi-session named-pipe IPC with impersonation-based auth, multiple managed accounts, SID-pinned internal configuration records and per-launch passwords, `LogonUser` + `CreateProcessAsUserW`, Job object, Event Log audit. Ship the **`console` (ConPTY) adapter** on the default noninteractive station, reusing the existing `TerminalBridge`/`PseudoConsoleHost` with the child-creation call moved behind the broker (client owns the terminal and the SID-DACL'd data pipes). This is the daily-driver path for console agents and closes **both** surfaces. It is complete only when the §18 console acceptance checks, including the real installed-console run, pass. Run the §6.1 token-graft probe; its current result retains the `LocalSystem` + `CreateProcessAsUserW` baseline. Client: remove all credential/`CreateProcessWithLogonW` logic; relocate the two token-validation checks into the broker.

**Phase n — `interactive` GUI adapter + optional hardened policy:** when GUI support is selected,
implement the adapter (§7.2): derive and validate the caller's session from the authenticated pipe
token; `SetTokenInformation(TokenSessionId)`; child-logon-SID-only, minimum `WinSta0`/`Default`
ACEs with failure-safe teardown; `LoadUserProfile`/`CreateEnvironmentBlock`; and detached Job
lifetime. The Session-0 broker remains the direct process creator and never transfers a reusable
restricted token to a normal-user helper. Test the path in real RDP/Fast User Switching scenarios,
not merely the console path, before accepting it for VS Code or Claude Desktop in the caller's
session (Surface 2 closed, Surface 1 accepted). This later phase can also select multi-profile
config + admin tooling, optional executable allow-listing, canonical-path/ACL checks, working-dir
environment policy, credential rotation schedule, config integrity protection, and rate limits.
The §6.1 result does not support a `LocalService` downgrade.

**Later GUI hardening phase (postponed):** evaluate a private window station/desktop or a separate session for GUI where feasible; `SetWindowDisplayAffinity`-style mitigations are out of the child's control, so this likely means a dedicated session rather than co-locating on the human's desktop.

---

## 20. First concrete implementation decision

- C++ Windows service, `LocalSystem`, demand-start, `SERVICE_START` delegated to the caller SID;
- named pipe `\\.\pipe\launch-as-broker.v1`, message mode, SID-DACL, `ImpersonateNamedPipeClient` auth;
- account name is the Phase-1 profile id; `create` makes a named managed account and explicit
  takeover converts an eligible existing local account into a managed account;
- SID-pinned authenticated record per managed account; each launch generates another temporary
  password;
- `LogonUserW(INTERACTIVE)` + `CreateProcessAsUserW`;
- **`console` (ConPTY) adapter** as the shippable Phase-1 slice; **`interactive` (GUI) adapter** only in a later selected phase;
- Job object (kill-on-close for console, detached for GUI);
- at most four starting/active sessions globally and two per account, with immediate rejection and
  no queue; every session owns an independent control connection, token/logon SID, ConPTY state,
  console host, Job, and dead-man switch;
- Event Log audit; no Windows Hello/master password in v1.

The essential improvement over the current client: the agent runs under an **independent logon session** (Surface 2 closed) and the interactive user and agent can request a launch but can never retrieve the account password.

---

## 21. Implemented Phase-1 service contract

This section is the current contract. It preserves the applicable behavior of the retired
pre-broker launcher design; Credential Manager, `register`, `--credential-mode`, direct
`CreateProcessWithLogonW`, and `--terminal` are not broker interfaces.

- `launch-as.exe [run] --user <managed-local-user> [--working-directory <directory>] --
  <absolute-executable> [arguments...]` is the console-launch CLI. `run` is optional. The
  client requires an existing absolute executable and, when supplied, an existing absolute
  working directory; otherwise it uses its current directory. It intentionally exposes no mode
  option until more than one client-visible mode is implemented; it sends `mode:"console"` to the
  broker.
- The client starts the demand-start `launch-as-broker` service and connects to its local,
  message-mode control pipe. The pipe rejects remote clients. Its DACL admits the authorised
  caller, but the service also impersonates the pipe client, captures its SID/session/integrity,
  immediately reverts, and cross-checks the client-process SID before authorising the request.
- Phase 1 supports only explicit `mode:"console"`. `mode:"interactive"` is recognised but
  rejected with `mode_not_supported` / `ERROR_NOT_SUPPORTED` (50); missing or unknown modes are
  invalid requests. No Phase-1 process is placed on `WinSta0\\Default` or given access to the
  caller's interactive window station or desktop.
- The `LocalSystem` service resets a broker-generated password for the SID-pinned managed local
  account, calls `LogonUserW(LOGON32_LOGON_INTERACTIVE)`, clears the password buffer, loads the
  user profile/environment, and creates the console host suspended with `CreateProcessAsUserW`.
  Password reset through logon and the process-wide privilege changes used by process creation are
  serialized. The host is checked not to share the caller's logon SID before it resumes.
- Console terminal I/O remains in the caller's pane through ConPTY. The client creates random,
  one-instance, SID-scoped input, output, and resize named pipes; the broker-launched
  `launch-as-conhost.exe` connects to them and starts the requested command in the
  pseudoconsole. Windows 10 version 1809 or newer is required. Output is untrusted terminal
  content and can spoof prompts or terminal-supported presentation actions.
- Each console host is assigned to a kill-on-close Job before it resumes. The control connection
  is the dead-man switch: client disconnect, service stop, or launch failure closes the Job and
  terminates that host's process tree. Bounded parallel sessions are the selected contract: four
  starting/active sessions globally and two per account, rejected beyond the limit with
  `session_limit_reached` / `ERROR_BUSY`. The implementation dispatches each accepted control
  connection to one of at most eight workers and enforces both session limits. Same-account
  concurrency and independent disconnect teardown are acceptance-tested; account-scoped profile
  leasing and cross-account lifecycle acceptance remain required before the full contract is
  complete.
- After terminal output finishes, the broker reports the launched command's exit code over the
  control connection and `launch-as.exe` returns it unchanged. Launcher-originated failures use
  the documented Win32-style outcomes (notably `1` for general failure and `87` for usage); child
  exit codes may collide with them.

The installed console suite covers identity, `TokenGroups`, window/process access, exit propagation,
disconnect teardown, same-account overlap, the per-account limit, and released-slot reuse. It must
be rerun after security-sensitive changes; unit tests and parser checks alone do not demonstrate an
installed, cross-session boundary.

---

## 22. Open account-lifecycle decisions

The current implementation has one managed-account lifecycle. `create` creates a dedicated
account; explicit takeover converts an existing account into a managed account. The SID-pinned,
HMAC-protected record is the ownership proof. Legacy records remain unclaimed until an explicit
takeover.

### Decisions pending

- Separate a broker **profile** (launch policy and authorised callers) from its Windows account. A managed account name may use a recognisable `launch-as-` prefix while the profile has a stable, human-facing name.
- **Phase-1 decision:** `create` fails for an existing account. `create --takeover` is the
  only operation that claims an existing account. It resets the password and establishes managed
  ownership; `--force` is required to re-enable a disabled or same-name replacement account.
- `forget` is the safe handoff: it removes only launch-as metadata. `delete` is the destructive
  teardown and never removes profile data implicitly.
- Takeover and delete require client confirmation. Plain create needs no confirmation because it
  fails rather than modifying an existing account. The service receives confirmation separately
  from the explicit takeover `force` bit, so a normal confirmation cannot silently authorize a
  re-enable.

### Implementation todos after those decisions

- Define account eligibility beyond Administrators membership: built-in, domain, protected, service, scheduled-task, and loaded-profile accounts.
- Never pass a supplied password on a command line or log it. Define secure interactive input and an explicit automation input path; zero plaintext buffers after validation and storage.
- Make account changes and enrollment-metadata updates recoverable when one step succeeds and a later step fails.
- Define per-profile caller authorisation and account-selection semantics. The default execution policy remains general-purpose; add profile-specific restrictions only if a future use case requires them.
- Complete the selected bounded-session design: account-scoped profile leases, profile-specific and
  global draining for management operations, cross-account acceptance, and stable audit fields for
  session admission and rejection.
- Audit attach, take-over, create, password rotation, disable, unregister, and deletion without recording secrets.
