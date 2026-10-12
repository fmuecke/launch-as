# Limiting a Windows user's writes to specific directories

Goal: a process tree (e.g. a coding agent) can **read** per normal ACLs but **write** only to explicitly authorized directories. No admin rights at runtime, no changes to system ACLs. Validated on Windows 11 26200/26300. Evidence: `REPORT.md`.

## Recommended: Low integrity level

### 1. One-time setup (elevated)
Label each authorized directory tree Low:
```
icacls C:\AgentSandbox         /setintegritylevel (OI)(CI)low /T /C /L /Q
icacls C:\Users\AgentSandbox   /setintegritylevel (OI)(CI)low /T /C /L /Q
```
- `(OI)(CI)`: new files and folders inherit the label automatically.
- `/T` labels existing children, because icacls does not propagate the label itself. In-use files (`NTUSER.DAT`) fail; that is fine.
- Never label `C:\`, `Windows`, `Program Files`, `ProgramData`, or `Users`. `Setup-LowScope.ps1` adds these guards.
- The user still needs a normal Modify ACE on these trees. The label only adds a restriction.

### 2. Launcher (runs unconfined as the same user, or in the broker)
```cpp
HANDLE src;   // NOTE: TOKEN_ADJUST_DEFAULT is required - see pitfalls
OpenProcessToken(GetCurrentProcess(),
    TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &src);
HANDLE tok;
CreateRestrictedToken(src, DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 0, nullptr, &tok);
// S-1-16-4096 = Low
TOKEN_MANDATORY_LABEL tml{{lowSid, SE_GROUP_INTEGRITY}};
SetTokenInformation(tok, TokenIntegrityLevel, &tml, sizeof tml + GetLengthSid(lowSid));
CreateProcessAsUserW(tok, ...);   // descendants inherit Low automatically
```
Reference implementation: `poc\AgentScope.cpp --low`.

### 3. Result
- A write needs the normal DACL **and** a Low label on the target. Everything unlabelled counts as Medium and is read-only to the agent.
- whoami, cmd, pwsh, git, cmake, node, dotnet and cdb work unmodified.
- The agent cannot read or inject into unconfined (Medium) processes of the same user. It *can* still terminate them.
- Raising the integrity level, AdjustToken* calls, and borrowing another process's token all fail.

## Alternative: WRITE_RESTRICTED (only if Low IL is impossible)
1. Create a local group `AgentWriteScope` with no members, and grant it `(OI)(CI)(M)` on the authorized roots. Inheritance covers subfolders; no per-folder upkeep.
2. Call `CreateRestrictedToken(src, WRITE_RESTRICTED | DISABLE_MAX_PRIVILEGE, …, restricting SIDs = { AgentWriteScope, Everyone (S-1-1-0) })`.
   - **Everyone is mandatory.** Without it, `bcrypt.dll` fails to load because `\Device\KsecDD` can only be written by Everyone/AppContainer SIDs. That surfaces as `0xC0000142` in cmake, cdb and .NET/pwsh, and git and `>nul` break as well.
   - The logon SID and `RESTRICTED` / `WRITE RESTRICTED` (S-1-5-33) do **not** help.
3. Append `ACCESS_ALLOWED_ACE(AgentWriteScope, TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS)` to the restricted token's **`TokenDefaultDacl`** before `CreateProcessAsUserW`. This makes whoami work in every descendant. Patching the child's token object does not propagate, because each process gets a fresh token whose DACL is rebuilt from the default DACL.
4. Refuse to launch if the token has any group that is not mandatory or deny-only. Otherwise TOKEN_ADJUST_GROUPS allows deny-ACE bypass.

Costs:
- Writes are also allowed wherever **Everyone** can write: 164 extra dirs on the test machine (ProgramData app folders, game dirs).
- The agent can read the memory of, and terminate, unconfined same-user processes.
- Stacked on a Low base it adds nothing over Low alone.

## Pitfalls (each one cost time)
- `CreateRestrictedToken` returns a handle with the **same access as the source handle**. Open the source with `TOKEN_ADJUST_DEFAULT`, or the integrity level and default DACL cannot be set (error 5).
- Do **not** `DuplicateTokenEx` before restricting. The token must derive from the caller's primary token, otherwise `CreateProcessAsUserW` fails with 1314 (needs SeAssignPrimaryTokenPrivilege).
- `WRITE_RESTRICTED` with zero restricting SIDs denies all writes.
- Quote command-line arguments only when needed. Quoting everything turns `/c` into `"/c"` and breaks `cmd.exe`.
- Coverage is lost on items with inheritance disabled, and on folders *moved* in from elsewhere on the same volume (moves keep their old ACL/label; copies inherit).

## Verify
```
pwsh -File tests\Run-ScopeTests.ps1 -Mode Low      # from a Medium (unconfined) shell for full assertions
research\writeaudit.exe <SID> 6 C:\               # non-destructive: lists every dir a confined token could write
```
Expect: writes only in the authorized trees, plus any pre-existing Low-labelled, user-writable dirs. Three were found here: `ProgramData\Microsoft\DeviceSync`, `ProgramData\NVIDIA Corporation\Drs`, `Users\Public\Documents\AdobeGCInfo`. Review your own list; fixing them means tightening those directories' own ACLs or labels.

## Not covered by either design
- Reads and network exfiltration. Use a network filter.
- SMB shares (checked server-side, where no integrity level or restricting SID applies) and FAT/exFAT media.
- HKCU writes are denied, except `Software\AppDataLow` under Low.
- Anything an unconfined process of the same user later runs from the writable profile (shell profiles, Startup folder). Run nothing unconfined as that user beyond the minimal host.
- COM/RPC/pipe servers that act on the agent's behalf (confused deputies).
