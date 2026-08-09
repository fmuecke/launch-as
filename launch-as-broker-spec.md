# launch-as-broker — Implementation Specification

Status: draft for implementation · Language: C++ (native Windows service) · Supersedes the earlier `spec.md`

---

## 1. Objective

Move restricted-account credentials **and** privileged process creation out of the interactive `launch-as` client into a dedicated Windows service (`launch-as-broker`), so that an agent process is launched under a **clean, independent logon session** instead of one derived from the interactive user's logon.

The service provides one narrow operation:

> An authorised interactive user asks the broker to start a predefined program as a predefined restricted Windows account, in a chosen session mode.

The caller never receives, reads, or decrypts the restricted account password, and the resulting child process never carries the interactive user's logon SID.

---

## 2. Why this exists (the problem being fixed)

The current client launches with `CreateProcessWithLogonW(user, ".", pw, LOGON_WITH_PROFILE, …)`. That call routes through the secondary-logon service and, by design, **grafts the interactive user's logon SID onto the new token** so the child can reach `WinSta0\Default`. The child's `TokenUser` is genuinely `AgentSandbox` (file ACLs isolate correctly), but the grafted logon SID has a second, unwanted effect:

- Every process carries a default DACL ACE granting its **logon SID** the mask `0x121411` (`TERMINATE | VM_READ | QUERY_INFORMATION | QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE`).
- Because the agent token now contains the interactive user's logon SID as a group, the agent can `OpenProcess` the interactive user's processes and **read their memory or terminate them** — no `SeDebugPrivilege` required.

This is **Surface 2** (process/kernel-object reach). It exists purely because the token shares the interactive logon session. A genuine, independent `LogonUser(AgentSandbox)` mints a **new** logon session with its **own** logon SID, which no longer matches the interactive user's process DACLs → Surface 2 closes.

There is also **Surface 1** (UI/desktop reach): any process on `WinSta0\Default` can enumerate windows, screen-capture the framebuffer (not integrity- or UIPI-gated), and inject input laterally. Surface 1 is a property of *being on the shared desktop*, independent of the token's SIDs.

**Primary goal of this service:** close Surface 2 for all launches, by never deriving the child token from the interactive logon.
**Secondary goal:** keep the account password out of the client and out of IPC (broker-owned credential).
**Explicitly in scope but not hardened yet:** Surface 1 for the GUI mode — see §7.

---

## 3. Security goals and non-goals

Protect against:

- an agent process (running as `AgentSandbox`) reading/terminating the interactive user's processes (**Surface 2**);
- an agent process or an ordinary interactive-user process reading the stored account password;
- password exposure via files, command lines, environment, logs, dumps, or IPC;
- unauthorised local users invoking the broker.

First version does **not** protect against:

- a compromised local administrator or kernel-level malware;
- a compromised service binary or installer;
- LSASS credential theft by an administrator;
- **Surface 1 in `interactive` (GUI) mode** — a GUI child shares the caller's desktop by necessity. Documented residual, hardening postponed.

---

## 4. Naming and fixed identifiers

| Thing | Value |
|---|---|
| Service name | `launch-as-broker` |
| Restricted account (local) | `AgentSandbox` (referenced as `.\AgentSandbox`) |
| Default profile id | `agent-sandbox` |
| Control pipe | `\\.\pipe\launch-as-broker.v1` |
| Config + credential root | `%ProgramData%\launch-as\` |
| Credential store | `%ProgramData%\launch-as\credentials\` |
| Service binary | `%ProgramFiles%\launch-as\launch-as-broker.exe` |
| Console host helper | `%ProgramFiles%\launch-as\launch-as-conhost.exe` (console mode only) |

All config/credential/binary paths: ACL `SYSTEM:F`, `Administrators:F`, `Users:RX` (credential dir: no `Users` access at all).

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
     │  3 CryptUnprotectData → account password  │
     │  4 LogonUser(INTERACTIVE) → fresh token   │
     │  5 validate token (SID match, non-admin)  │
     │  6 session adapter (interactive | console)│
     │  7 LoadUserProfile / CreateEnvironmentBlock│
     │  8 CreateProcessAsUserW (suspended)        │
     │  9 Job object; resume; audit               │
     └────────────────────┬─────────────────────┘
                          ▼
              AgentSandbox child (own logon session)
        interactive → caller's WinSta0\Default (GUI)
        console     → noninteractive station + ConPTY
```

**Architectural stance:** the broker is a **capability broker**, not a remote `runas`. The client selects a *profile* and a *mode*; it cannot specify an arbitrary account, executable, or password.

---

## 6. Launch primitive and service identity (committed baseline)

- Service runs as **`LocalSystem`**. Justification: `CreateProcessAsUserW` requires `SeAssignPrimaryTokenPrivilege` + `SeIncreaseQuotaPrivilege`; the `interactive` adapter's session assignment requires `SeTcbPrivilege`; `LoadUserProfile` requires administrator/SYSTEM. LocalSystem holds all three; enable them explicitly at use and drop otherwise.
- Process creation primitive: **`LogonUserW(LOGON32_LOGON_INTERACTIVE)` → `CreateProcessAsUserW`**.
- Do **not** use `LOGON32_LOGON_NEW_CREDENTIALS` (netonly) — it reuses the caller's local identity and reopens the exact sharing we are removing.

### 6.1 Spec task — token-graft probe (informs a later downgrade)

Before or during Phase 1, verify empirically whether `CreateProcessWithTokenW` (needs only `SeImpersonate`, held by `LocalService`) also grafts the interactive logon SID. Method: launch a child via `LogonUser` + `CreateProcessWithTokenW`, dump `TokenGroups`, check for the interactive user's logon SID, and run the Surface-2 probe (§18). If it does **not** graft, a later hardening step MAY downgrade the service identity from `LocalSystem` to `LocalService`. Until proven, `LocalSystem` + `CreateProcessAsUserW` is the baseline. Record the result in the repo.

---

## 7. Session modes (adapters)

The launch core is mode-agnostic. A profile selects one adapter.

### 7.1 `console` mode (default for `agent-sandbox` / Claude Code)

- Child stays on the **default noninteractive window station** (`Service-0x0-…`). Do **not** set `lpDesktop` to `WinSta0\Default`; do **not** hop the session.
- I/O via **ConPTY + named pipes**: the broker launches `launch-as-conhost.exe` as `AgentSandbox`; the host creates the pseudoconsole, runs the target inside it, and connects per-session input, output, and resize pipes back to the client's terminal. (Reuse the existing `PseudoConsoleHost` / `TerminalBridge` code; move the child-creation call behind the broker.)
- Data pipes are created by the **client** (in the interactive user's context) with a DACL granting connect+RW to `AgentSandbox` only; names are random per session with `FILE_FLAG_FIRST_PIPE_INSTANCE`. The broker passes the names in the request; it never touches stdio and never receives credential-store handles.
- **Surfaces:** Surface 1 **closed** (no interactive desktop), Surface 2 **closed** (independent logon SID).

### 7.2 `interactive` mode (GUI, e.g. VS Code in the user's session)

Requires crossing from session 0 into the caller's interactive session. Steps:

1. From the authenticated caller token, obtain the caller's **session id**; verify it belongs to the caller (do not blindly use `WTSGetActiveConsoleSessionId`).
2. `LogonUserW(INTERACTIVE)` → primary token (its own logon SID; session 0 by default).
3. `SetTokenInformation(TokenSessionId, callerSession)` — needs `SeTcbPrivilege`.
4. Extract the **child's own logon SID** (`GetTokenInformation(TokenLogonSid)`), and add scoped ACEs for **that logon SID** — not the account SID — to the caller session's `WinSta0` window station and `Default` desktop (KB165194 pattern). Track the ACEs for removal on teardown.
5. `LoadUserProfile` + `CreateEnvironmentBlock` (GUI apps need `HKCU`/`%APPDATA%`).
6. `STARTUPINFO.lpDesktop = L"WinSta0\\Default"`; `CreateProcessAsUserW`.
7. On process-tree exit or teardown: remove the temporary winsta/desktop ACEs, `DestroyEnvironmentBlock`, `UnloadUserProfile`, close handles.
- **Surfaces:** Surface 2 **closed** (the token holds the child's own logon SID, never the interactive user's). Surface 1 **open and accepted** — the GUI child is physically on the shared desktop (can screenshot, enumerate, and inject laterally into same-IL windows). This is the documented, postponed residual. Use the account/logon SID scoping above so no *persistent* cross-session desktop access is left behind.

> Rationale for why Surface 2 stays closed in GUI mode: granting the child's *own* logon SID rights on the interactive desktop gives desktop access without placing the interactive user's logon SID into the child token — so the interactive user's process default-DACL ACE still does not match.

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
  "profileId": "agent-sandbox",
  "mode": "console",
  "arguments": ["--resume"],
  "workingDirectory": "C:\\dev\\AgentSandbox\\repo",
  "console": {
    "pipeIn":  "\\\\.\\pipe\\launch-as-<rnd>-in",
    "pipeOut": "\\\\.\\pipe\\launch-as-<rnd>-out",
    "pipeResize": "\\\\.\\pipe\\launch-as-<rnd>-resize",
    "cols": 120, "rows": 30
  }
}
```

`console` block present only for `mode:"console"`. `mode:"interactive"` carries no pipe names.

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

Phase 1 ships a **single fixed profile** (`agent-sandbox`); the multi-profile capability is a Phase-2 extension. A profile record:

```text
profileId              e.g. "agent-sandbox"
displayName
accountName            ".\AgentSandbox"
accountSid             (resolved, pinned)
credentialRef          → credentials\agent-sandbox.blob
authorisedCallerSids   [ SID, … ]           (who may launch)
executablePath         canonical, fixed per profile
argumentPolicy         allow-list / passthrough flag
workingDirRoots        [ approved root, … ]
environmentPolicy      allow-list
sessionMode            "console" | "interactive"
profileLoad            bool (LoadUserProfile)
jobLifetime            "control-connection" | "detached"
enabled                bool
```

The broker validates, default-deny:

- caller SID ∈ `authorisedCallerSids`; profile enabled;
- executable == configured canonical path (canonicalised; reparse/symlink resolved);
- executable **not writable by `AgentSandbox`**, and not writable by an untrusted caller unless the profile explicitly accepts it;
- arguments comply with `argumentPolicy`;
- working directory inside an approved root (canonical comparison, not string-prefix);
- no unauthorised environment injection;
- for `interactive`: requested/derived session belongs to the caller.

---

## 10. Credential model (broker-owned, DPAPI)

One encrypted blob per profile under `%ProgramData%\launch-as\credentials\<profileId>.blob`.

- Protect with **`CryptProtectData` under the service (SYSTEM) identity — NOT `CRYPTPROTECT_LOCAL_MACHINE`.** SYSTEM-scope means only SYSTEM can unprotect; the machine-scope flag would let any local account unprotect and lean entirely on the file ACL (weaker). Bind with additional entropy derived from `profileId`.
- Blob carries format version + integrity metadata.
- Plaintext password exists only during enrolment/rotation and during `LogonUser`, in a mutable secure buffer (`SecureZeroMemory` immediately after). Never in `std::wstring`, exceptions, logs, command lines, environment, or registry.

The stored account is configured `PasswordNeverExpires` and `UserMayChangePassword=false` so the broker fully owns the secret and can rotate it unattended.

---

## 11. Credential/account management operations (enroll, update, rotate, test, unenroll)

A separate **elevated** admin path (config subcommand of the broker binary, or a co-installed `launch-as-admin.exe`). Normal `launch` requests can never reach these. Run during the setup phase and thereafter for maintenance.

- **`enroll <profileId>`** (default: broker-generated password):
  1. ensure the account exists (`NetUserAdd` if absent; else leave membership as-is), Standard user only, hardened (never-expires, user-cannot-change, deny network+RDP logon, hidden from welcome screen) — or delegate account creation to the existing `Setup-*` script and only manage the credential here;
  2. generate a strong random password (`BCryptGenRandom`, mapped to policy);
  3. set it on the account (`NetUserSetInfo`, `USER_INFO_1003`);
  4. `CryptProtectData` → write blob (SYSTEM-scope, entropy = profileId);
  5. `SecureZeroMemory`. Operator is never shown the password.
  - Option `--supply-password`: read a password from a secure prompt instead of generating (for an externally managed account); broker stores the blob (and optionally sets it).
- **`update`/`rotate <profileId>`**: regenerate → `NetUserSetInfo` → re-protect → verify. Rotation invalidates the previous blob.
- **`test <profileId>`**: `LogonUser` with the decrypted blob; report success/`ERROR_LOGON_FAILURE` without echoing the secret. On stale blob at launch time, the broker fails closed with a distinct reason code telling the operator to re-enroll (no silent self-heal).
- **`unenroll <profileId>`**: delete the blob; optionally disable the account.

---

## 12. Process-creation flow (per accepted launch)

1. authorise (§8, §9).
2. `CryptUnprotectData` → password buffer.
3. `LogonUserW(accountName, ".", pw, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token)`.
4. `SecureZeroMemory(pw)` immediately.
5. validate token: `TokenUser` SID == pinned `accountSid`; `TokenGroups` must **not** contain the local Administrators SID (reuse the client's existing `ProcessHasAccountSid` / `ValidateNonAdministrativeToken` checks, relocated here).
6. optional `CreateRestrictedToken` (disable non-essential privileges; **keep Medium integrity** — Low IL breaks the MSVC toolchain).
7. apply the **session adapter** (§7): `console` → noninteractive + ConPTY host; `interactive` → session hop + desktop-DACL grant.
8. if `profileLoad`: `LoadUserProfile` + `CreateEnvironmentBlock` (note: `LOGON_WITH_PROFILE`-style profile loading can stall for minutes on heavily-used machines — load only when the mode/app needs `HKCU`/`%APPDATA%`; a headless console child often does not).
9. prepare only explicitly approved inherited handles (console mode: none from the broker; the host connects pipes by name). All broker handles non-inheritable by default.
10. `CreateProcessAsUserW(token, exe, …, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT[ | EXTENDED_STARTUPINFO_PRESENT], env, workingDir, &si, &pi)`.
11. `ProcessHasAccountSid(pi.hProcess)` re-check; on mismatch, terminate and fail.
12. create a **Job object**, `AssignProcessToJobObject` before resume.
13. `ResumeThread`.
14. audit; return PID.
15. teardown: for `interactive`, remove temporary winsta/desktop ACEs, `DestroyEnvironmentBlock`, `UnloadUserProfile`; always close token/thread/process handles and zero any residual secret buffers.

---

## 13. Lifecycle / Job object

Per launch, one Job object. Lifetime is **per-profile policy**:

- **`control-connection`** (default for `console`): the Job handle's lifetime is tied to the client's **control-pipe connection** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Client exit/crash/Ctrl-C → control pipe breaks → broker closes the Job handle → the whole child tree (agent + spawned compilers) dies. This is the dead-man switch, for free. Exit is observed by the client as **data-pipe EOF**; the broker need not relay exit codes.
- **`detached`** (default for `interactive`/GUI): the GUI app (VS Code) should outlive the launching client. Assign to a Job for tracking/limits but **without** kill-on-close, or hand the Job to a session-scoped owner. Do not kill on client disconnect.

A Job object is **not** a security boundary — the account, filesystem ACLs, network policy, and token remain the isolation boundaries.

---

## 14. Installation / setup phase (demand-start, prompt-free launches)

The installer/setup runs **elevated once** and must:

- install the service binary under `%ProgramFiles%\launch-as\`, path fully qualified and quoted;
- create the service `launch-as-broker` as **`LocalSystem`**, **`start= demand`**;
- **delegate `SERVICE_START` to the launcher's caller SID (or a dedicated group)** via `sc sdset` / `SetServiceObjectSecurity`, so day-to-day launches start the service with **no UAC prompt**;
- create `%ProgramData%\launch-as\{,credentials}` with restrictive ACLs (§4);
- register the Event Log source;
- provision/har­den the `AgentSandbox` account and run `enroll agent-sandbox` (§11) to set + store its credential;
- optionally create Firewall rules (separate, out of scope here);
- deny ordinary users any right to replace/reconfigure the service or its files;
- support clean uninstall with optional secure credential deletion.

Runtime: the client calls `StartService` (permitted by the delegated DACL, no prompt) → connects → broker self-stops after idle.

> `sudo`/admin elevation is **not** an alternative: it reaches only High-integrity admin (still lacks `SeAssignPrimaryToken`) and prompts every time. The one-time install + `SERVICE_START` delegation is what gives prompt-free on-demand launches.

---

## 15. Audit logging (Windows Event Log)

Log: requestId, timestamp, caller SID, caller session id, profileId, mode, executable identity, allow/deny, denial reason code, resulting PID, Win32 error, config changes, credential enrol/rotate events.

Never log: passwords, credential blobs, full sensitive command lines, secret-bearing env vars, raw tokens. Use the Event Log, not a user-writable text file.

---

## 16. Failure behaviour (fail closed)

Fail closed when: caller identity unresolved; impersonation fails; profile missing/disabled; config integrity check fails; executable not canonicalisable or ACL check fails; credential undecryptable or `LogonUser` fails; session ambiguous (interactive mode); desktop access cannot be prepared; handle validation fails; protocol version unsupported. Return a stable reason code + Win32 error; no sensitive internals.

---

## 17. Threat-sensitive invariants

1. The child token is created by an **independent `LogonUser`** and never carries the interactive user's logon SID.
2. Passwords never cross the client↔broker boundary.
3. The caller chooses a **profile + mode**, not a credential, account, or executable.
4. Authorisation is based on the **actual caller token**, not a claimed name.
5. Config/credential changes require a distinct elevated path.
6. Executable/dir checks use canonical paths + ACL inspection; no string-prefix checks.
7. No client-supplied handle is trusted without validation; no broker handle is inheritable by default.
8. Interactive-mode desktop ACEs are granted to the child **logon SID** (not account SID) and removed on teardown.
9. Every failure path zeroes secrets and closes handles.
10. All IPC/config parsing is length-bounded and versioned.

---

## 18. Acceptance criteria

Credential / authorization:

- an authorised caller can launch the profile; an unauthorised caller cannot connect or launch;
- neither an interactive-user process nor an agent process can read the stored password via any supported interface;
- arbitrary executables cannot be launched through the fixed profile; path-traversal / reparse tricks are rejected;
- passwords never appear in logs, command lines, environment, or IPC captures;
- killing the client exposes no broker resources; concurrent requests cannot mix caller identities/profiles; failed impersonation → immediate rejection;
- service restart preserves the credential but no plaintext; rotation invalidates the old blob; uninstall leaves no service or IPC endpoint.

**Derived-token / Surface-2 regression (the core new tests):**

- inside the launched child, `whoami /logonid` returns a logon SID **different** from the interactive user's;
- the child's token `TokenGroups` does **not** contain the interactive user's logon SID;
- the Surface-2 `OpenProcess` probe from the child against the interactive user's processes returns **`VM_READ`/`TERMINATE` DENIED**;
- `console` mode: `EnumWindows` from the child cannot see the interactive user's windows (Surface 1 closed);
- `interactive` mode: Surface 2 tests pass (DENIED) even though the child renders on the shared desktop (Surface 1 intentionally open); after the child exits, the temporary `WinSta0`/`Default` ACEs for the child logon SID are gone.

---

## 19. Implementation phases

**Phase 1 — broker + boundary, `console` (ConPTY) mode only:**
service scaffold (SCM, demand-start, `sc sdset` delegation), named-pipe IPC with impersonation-based auth, single fixed profile, broker-owned SYSTEM-scope DPAPI credential + `enroll`/`rotate`/`test`, `LogonUser` + `CreateProcessAsUserW`, Job object, Event Log audit. Ship the **`console` (ConPTY) adapter** on the default noninteractive station, reusing the existing `TerminalBridge`/`PseudoConsoleHost` with the child-creation call moved behind the broker (client owns the terminal and the SID-DACL'd data pipes). This is the daily-driver path (Claude Code) and closes **both** surfaces, so it validates the full trust boundary end-to-end. Run the §6.1 token-graft probe. Client: remove all credential/`CreateProcessWithLogonW` logic; relocate the two token-validation checks into the broker.

**Phase 2 — `interactive` (GUI) adapter + hardened policy:** the GUI adapter (§7.2) — session resolution, `SetTokenInformation(TokenSessionId)`, child-logon-SID `WinSta0`/`Default` ACEs with teardown, `LoadUserProfile`/`CreateEnvironmentBlock`, `detached` Job lifetime — launching e.g. VS Code into the caller's session (Surface 2 closed, Surface 1 accepted). Plus: multi-profile config + admin tool, executable allow-listing, canonical-path/ACL checks, working-dir + environment policy, credential rotation schedule, config integrity protection, concurrency/rate limits, optional `LocalService` downgrade if §6.1 passes.

**Phase 3 — Surface-1 hardening for GUI (postponed):** evaluate a private window station/desktop or a separate session for GUI where feasible; `SetWindowDisplayAffinity`-style mitigations are out of the child's control, so this likely means a dedicated session rather than co-locating on the human's desktop.

---

## 20. First concrete implementation decision

- C++ Windows service, `LocalSystem`, demand-start, `SERVICE_START` delegated to the caller SID;
- named pipe `\\.\pipe\launch-as-broker.v1`, message mode, SID-DACL, `ImpersonateNamedPipeClient` auth;
- single fixed profile `agent-sandbox` → `.\AgentSandbox`;
- broker-owned SYSTEM-scope DPAPI credential; `enroll` generates + sets the account password;
- `LogonUserW(INTERACTIVE)` + `CreateProcessAsUserW`;
- **`console` (ConPTY) adapter** as the Phase-1 slice; **`interactive` (GUI) adapter** in Phase 2;
- Job object (kill-on-close for console, detached for GUI);
- Event Log audit; no Windows Hello/master password in v1.

The essential improvement over the current client: the agent runs under an **independent logon session** (Surface 2 closed) and the interactive user and agent can request a launch but can never retrieve the account password.

---

## 21. Open account-lifecycle decisions

The current broker implementation is not the decision record for these points. Resolve them before treating multi-account registration as a stable interface.

### Decisions pending

- Separate a broker **profile** (launch policy and authorised callers) from its Windows account. A managed account name may use a recognisable `launch-as-` prefix while the profile has a stable, human-facing name.
- Support three explicit enrollment modes rather than overloading `enroll`:
  - **attach** an existing account after the operator supplies its password; validate it and store it, without changing the account password;
  - **take over** an existing account by generating and setting a new password; this cannot restore the old password later;
  - **create** a broker-managed account with a recognisable name, allowing account-specific hardening.
- Record registration mode and account ownership as protected metadata. A name prefix alone is not proof that the broker owns an account.
- Define symmetric teardown per mode:
  - attached accounts: remove broker credential/metadata only;
  - taken-over accounts: remove broker credential/metadata only unless a separately confirmed destructive action is chosen;
  - broker-managed accounts: decide whether normal teardown disables or deletes the account, and handle its profile, processes, services, and scheduled tasks.
- Destructive operations—password rotation/take-over, replacement of a registration, disabling or deleting an account, and bulk teardown—must prompt in the client unless `--force` is supplied. The service must reject a destructive IPC request unless it includes an explicit confirmation/force indication; confirmation is an accidental-action safeguard, not an authorisation boundary.

### Implementation todos after those decisions

- Define account eligibility beyond Administrators membership: built-in, domain, protected, service, scheduled-task, and loaded-profile accounts.
- Never pass a supplied password on a command line or log it. Define secure interactive input and an explicit automation input path; zero plaintext buffers after validation and storage.
- Make account changes and DPAPI/metadata updates recoverable when one step succeeds and a later step fails.
- Define per-profile caller authorisation, fixed executable policy, and account-selection semantics. Supporting multiple accounts must not permit arbitrary executable launches.
- Specify `unenroll-all` preview, confirmation, partial-failure reporting, and audit records.
- Audit attach, take-over, create, password rotation, disable, unregister, and deletion without recording secrets.
