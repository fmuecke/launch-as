# Task Scheduler as Broker Replacement — Console-Only Spike

## Context

`launch-as` currently has a working broker service that launches agent processes under the restricted `AgentSandbox` account.

For the console-only use cases (S0–S3), investigate whether the Windows Task Scheduler can replace this custom privileged broker. The motivation is not missing functionality: the broker already works. The motivation is reducing custom privileged code, complexity, security surface, and long-term maintenance.

The existing threat model identifies:

- **Surface 1 — shared desktop:** avoided entirely by console-only execution.
- **Surface 2 — derived logon session:** must be closed by giving `AgentSandbox` an independent logon session/logon SID.
- **Surface 3 — shared writable repo + elevated build:** unaffected by either broker or Task Scheduler and should be handled separately.

The existing analysis already identifies Task Scheduler + S4U as a candidate for closing Surface 2.

## Target architecture

The preferred minimal architecture to investigate is:

```text
Windows Terminal
    |
    +-- launch-as.exe                regular interactive user
            |
            | trigger fixed scheduled task
            | + IPC
            v
        Windows Task Scheduler      Windows privileged component
            |
            | TASK_LOGON_S4U
            v
        agent-host.exe              AgentSandbox
            |
            +-- Job Object
            +-- optional ConPTY
            +-- claude.exe / shell / build tools
```

Task Scheduler should perform only the privileged operation that Windows already knows how to perform: creating the process under the isolated identity.

Everything else should preferably run unprivileged.

## Why S4U

Investigate `TASK_LOGON_S4U` rather than storing the `AgentSandbox` password.

Desired properties:

- no password storage in `launch-as`
- no password rotation/lifecycle code
- independent logon session
- independent logon SID
- no delegatable network credentials, which is desirable for the restricted account

If S4U provides the required token, a significant portion of the existing broker's privileged functionality can potentially disappear.

## First experiment: prove the security primitive

Do **not** start with ConPTY integration.

Create a fixed S4U scheduled task running a small diagnostic executable as `AgentSandbox`.

Validate:

1. Dump token information and `whoami /logonid`.
2. Compare its logon SID with the interactive user's logon SID.
3. Run the existing Surface-2 `OpenProcess` probe against processes belonging to the interactive user.
4. Verify `PROCESS_VM_READ` and `PROCESS_TERMINATE` are denied.
5. Run `EnumWindows` and confirm that the interactive user's windows are not visible.

The first four items are the primary go/no-go criterion.

If Surface 2 is not closed, stop investigating Task Scheduler as a broker replacement.

## Functional validation

If token isolation succeeds, validate the actual console-agent environment.

### Profile and development environment

Check:

```text
%USERPROFILE%
%APPDATA%
%LOCALAPPDATA%
HKCU
TEMP/TMP
Git configuration
Claude configuration
PowerShell profile/environment
VS Developer Shell
cl.exe / MSBuild / CMake
```

In particular, verify that the S4U session provides enough profile functionality for Claude Code and native Windows build tooling.

### Launch interface

Prefer a **fixed, protected scheduled task**.

The normal user may trigger it but should not be able to turn it into a generic privileged process launcher.

Investigate passing per-launch information through Task Scheduler runtime parameters and/or IPC rather than modifying the registered task definition for every launch.

The task executable, principal and security-sensitive configuration should be immutable to both:

- `AgentSandbox`
- ordinary unprivileged processes that should not be able to repurpose the launcher

Define explicitly which actor is trusted to request an agent launch.

## Console / ConPTY

Windows Terminal itself should **not** be treated as the ConPTY broker. `wt.exe` is primarily a GUI terminal frontend and does not expose the required mechanism for attaching an arbitrary Task Scheduler process to the caller's terminal.

Instead investigate two alternatives.

### A. ConPTY owned by `agent-host.exe`

```text
Windows Terminal
   +-- launch-as.exe
          <---- named pipes ---->
       agent-host.exe
          +-- ConPTY
                 +-- claude.exe
```

`agent-host.exe` runs as `AgentSandbox` and handles:

- `CreatePseudoConsole`
- stdin/stdout forwarding
- resize
- Ctrl-C
- child process launch
- exit status

This keeps terminal machinery outside the privileged component.

### B. ConPTY owned by `launch-as.exe`

Also investigate whether the regular-user launcher can create the ConPTY and IPC resources before triggering the scheduled task, with the scheduled process receiving/accessing the necessary endpoints.

If viable, this could make `agent-host.exe` even smaller or eliminate it.

Prefer this architecture if it does not weaken the security boundary.

## Windows Terminal reuse

Windows Terminal can remain the user-facing terminal:

```text
Windows Terminal
    +-- launch-as.exe
```

But do not depend on Windows Terminal internals.

Use the public ConPTY API directly. Microsoft's small ConPTY/EchoCon sample may provide reusable/reference implementation for:

- pipe creation
- `CreatePseudoConsole`
- process setup
- input/output forwarding

Avoid implementing terminal emulation; ConPTY should perform that role.

## Process lifetime

This is likely the main area where the custom broker currently has an advantage.

Required behavior:

```text
user closes launcher / terminal
          |
          v
agent process tree terminates
```

Test:

1. Start Claude/build through the scheduled task.
2. Spawn child processes such as compiler processes.
3. Kill `launch-as.exe`.
4. Verify what survives.
5. Kill/cancel the scheduled task.
6. Verify what survives.

The desired solution is probably for `agent-host.exe` to create a Job Object with kill-on-close semantics and place the complete agent process tree inside it.

Determine whether Task Scheduler itself provides sufficient lifecycle behavior before adding custom supervision.

## Authorization/security checks

A Task Scheduler replacement is only an improvement if it does not become a more generic privilege boundary.

Verify ACLs and permissions around:

```text
scheduled task definition
agent-host.exe
configuration
IPC endpoints
runtime arguments
working directory
AgentSandbox profile
```

Specifically test whether either the regular agent process or another standard-user process can:

- modify the task definition
- change its principal
- change the executable
- change security-sensitive arguments
- replace `agent-host.exe`
- impersonate another launch through IPC
- connect to another invocation's IPC endpoints

Prefer per-invocation unpredictable identifiers and ACL-protected named pipes.

## Surface 3 is explicitly separate

Do not use Surface 3 as a criterion for choosing broker versus Task Scheduler.

Both architectures leave this problem:

```text
AgentSandbox
    |
    | writes malicious build input
    v
agent worktree/repository
    |
    | user builds
    v
elevated Visual Studio
```

This remains a separate trust-boundary/promotion/worktree problem.

## Comparison criterion

After the spike, compare:

| Property | Existing broker | Task Scheduler |
|---|---|---|
| Independent logon SID | required/already implemented | verify |
| S4U/no password | potentially implement | native candidate |
| Privileged custom code | significant | minimal/none |
| ConPTY | already implemented | external host required |
| Job/process lifetime | strong control | verify |
| Per-launch flexibility | strong | potentially awkward |
| Authorization model | custom and explicit | verify carefully |
| Maintenance | ours | largely Windows |
| Surface 1 | closed in console mode | expected closed |
| Surface 2 | closed | must prove |
| Surface 3 | unaffected | unaffected |

## Decision rule

Replace the broker if all of the following hold:

- Task Scheduler S4U demonstrably closes Surface 2.
- Console development tooling works correctly.
- Task execution can be exposed without creating a generic privileged-launch capability.
- Agent process-tree teardown can be made reliable.
- ConPTY/IPC requires only a small unprivileged component.
- The resulting architecture is materially smaller than the existing broker.

Do **not** replace the broker merely because Task Scheduler can launch `AgentSandbox`.

The relevant comparison is:

> Does Task Scheduler allow us to delete meaningful privileged/security-sensitive custom code without introducing equivalent complexity elsewhere?

If yes, prefer the Windows-maintained primitive even though the existing broker already works.

## Suggested implementation order

1. Create minimal `TASK_LOGON_S4U` diagnostic task.
2. Prove independent logon SID and Surface-2 protection.
3. Verify profile + VS build environment.
4. Verify task ACL/authorization model.
5. Investigate process-tree lifetime.
6. Test simplest possible stdin/stdout IPC.
7. Add ConPTY only if required for interactive S1 usage.
8. Compare resulting implementation size and security surface with the existing broker.
9. Decide whether to remove the broker.

Do not refactor the existing broker until steps 1–5 demonstrate that Task Scheduler is a viable replacement.