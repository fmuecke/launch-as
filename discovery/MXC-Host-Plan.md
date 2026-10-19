# MXC host implementation plan

Date: 2026-10-18. Status: design proposal; the initial runtime compatibility gate
failed in the current console-only launch-as workflow.

Related investigation: [How Codex uses MXC on Windows](MXC-SANDBOX.md).

## Observed compatibility blocker

The user tested the installed `wxc-exec.exe` 1.0.1 with the local configurations:

| Context and workload | Observed result |
| --- | --- |
| Normal account, PowerShell | User reported success |
| AgentSandbox console, `cmd.exe /d /c echo MXC_OK` | Printed `MXC_OK` |
| AgentSandbox console, absolute `pwsh.exe` with a finite `Write-Output` command | `STATUS_DLL_INIT_FAILED` (`0xC0000142`) |
| Same PowerShell test with only `processContainer.ui.isolation: "desktop"` added | Same failure |

Read-only live process metadata shows a launch-as-hosted `pwsh.exe` in session 0.
Both policies have `ui.disable: false`; the alternate UI setting did not resolve
the failure. The original configuration remains unchanged.

This pattern closely matches open [Microsoft MXC issue #1465][mxc-session-zero].
Its reporters describe USER32-dependent workloads failing in noninteractive
session 0 despite allowing UI and desktop resources. They also report that a
private-desktop experiment did not resolve PSEC startup. These are upstream
reports, not a locally established Windows-internal root cause.

Treat PSEC inside the existing session-0 console workflow as blocked pending a
supported resolution. A wrapper or another UI-policy toggle is not an established
fix. The implementation phases below remain proposals contingent on this gate;
basic `cmd.exe` startup does not qualify PowerShell, Claude, or the build tools.

Retaining session 0 with a different containment backend would change the agreed
mandatory-PSEC requirement. A different session/desktop architecture would need
separate design and boundary validation; shared interactive-desktop mode is not
an equivalent substitute for the console-only boundary.

## Intended outcome

Build a standalone `sandbox-host.exe` that wraps arbitrary console programs, with
Claude Code as its first integration. Launch it inside the existing restricted
account. Keep `launch-as` responsible for account separation and use MXC/PSEC for
restrictions inside that account.

## Agreed contract

| Area | MVP behavior |
| --- | --- |
| Invocation | Run inside the existing restricted account |
| Backend | PSEC required; refuse unsupported hosts or policies |
| Files | Project and entire restricted-account profile read/write; required Windows/tool paths read-only |
| File exceptions | None inside the two writable roots initially |
| Web | One shared destination allowlist |
| Inbound | Allow localhost listeners; deny unsolicited LAN/Internet connections |
| Processes | Preserve the account boundary; terminate remaining descendants when Claude exits |
| Policy ownership | Restricted account may edit configuration |

User-editable policy is an intentional trust choice. Claude can also modify
configuration within its writable reach. The current run uses a fixed snapshot,
but later runs may use the changed policy. This provides containment according to
the selected policy, without preventing the account from broadening it.

Profile changes persist between runs. Installed launcher binaries and owner-side
proxy runtime state remain outside the writable project/profile roots. The existing
administrator-installed WFP policy remains the outer network limit.

The existing account boundary is sufficient for the MVP. Isolation between
unrelated processes within the same restricted account is not a requirement.
A job object provides process-tree ownership and cleanup, not a separate
process-access boundary.

## 1. Prove the boundary with a small launcher spike

Build a minimal standalone Rust executable using pinned MXC dependencies. Rust
lets the host reuse the native integration without creating another set of
Windows API bindings.

Start with hard-coded project/profile grants, loopback networking, inherited
terminal I/O, and process-tree teardown. Require the actual PSEC path and disable
fallback to other mechanisms.

The existing SDK supplies policy serialization and process/job ownership, but its
general runner supports other paths, so PSEC-only behavior needs an explicit guard.
See Microsoft's [policy builder][mxc-builder] and [native runner][mxc-runner].

The first acceptance gate is to demonstrate filesystem denial, working localhost
listeners, blocked remote inbound, and descendant cleanup on the intended Windows
host. Inbound enforcement remains a requirement to prove.

## 2. Define the generic launch contract

Proposed interface:

```powershell
sandbox-host.exe check --config C:\path\policy.json

sandbox-host.exe run --config C:\path\policy.json `
    --working-directory C:\AgentSandbox\project `
    -- C:\Users\AgentSandbox\.local\bin\claude.exe --resume
```

`check` validates configuration, account identity, PSEC support, and installed
networking prerequisites. `run` repeats those checks, snapshots policy, launches
the exact executable/arguments, forwards terminal interaction, and returns the
workload's exit code.

The lifecycle is:

```text
Validate -> snapshot policy -> establish PSEC -> launch suspended
         -> assign job -> resume -> wait -> terminate descendants -> release policy
```

Unsupported policy, failed preparation, and missing networking prerequisites stop
execution. Daily launches require no elevation; privileged policy installation
remains part of `agent-win-sandbox` setup.

## 3. Keep configuration small

A proposed initial shape:

```json
{
  "version": 1,
  "filesystem": {
    "readOnlyPaths": [],
    "readWritePaths": []
  },
  "web": {
    "allowedHosts": [
      "api.anthropic.com:443",
      "claude.ai:443"
    ]
  }
}
```

The filesystem arrays add explicit roots to the default project/profile and
Windows/runtime grants. Resolve the profile from the account identity, require
absolute additional paths, and reject unknown settings. Other filesystem access
requires explicit grants.

Leave deny globs, nested exceptions, hot reload, and multiple policy profiles for
later. Web policy means destination `host:port` control through `allowproxy`;
HTTPS content inspection is outside the MVP.

## 4. Compose the existing components

| Component | Planned change |
| --- | --- |
| `launch-as` | Preserve its existing account/logon/terminal role |
| `sandbox-host` | Own PSEC policy, validation, workload launch, and cleanup |
| `wfp-lock` | Retain the outer outbound TCP/UDP policy; use proxy-only endpoints for this workflow |
| `allowproxy` | Retain destination filtering under its separate owner identity |
| `agent-win-sandbox` | Install the host, prepare configuration access, apply shared web policy, and wire the Claude command |

The existing `wfp-lock` contract covers outbound account-attributed TCP/UDP.
PSEC must establish the selected inbound behavior; it cannot be assumed from the
existing WFP lock.

To avoid adding a service, the existing proxy-owner launcher applies the
user-editable allowlist before entering AgentSandbox. Place that policy where the
restricted account can edit it and the proxy owner can read it. Executable, log,
PID, and runtime-state locations remain controlled by installation.

The in-account wrapper verifies that the requested web list matches the applied
list. Changing it requires closing active sessions and reopening AgentSandbox.
Filesystem changes take effect on the next invocation.

Localhost listeners remain permitted, while outbound localhost connections still
face the WFP endpoint restrictions. Replies to permitted outbound connections are
allowed; the inbound restriction concerns unsolicited connections from
LAN/Internet peers.

The resulting workflow is:

```text
Proxy-owner launcher
  -> validate and apply shared web allowlist to allowproxy
  -> launch-as enters the restricted account
       -> restricted-account shell
            -> sandbox-host validates policy, PSEC, and networking prerequisites
                 -> Claude and its descendants run inside PSEC
                      -> permitted web traffic uses allowproxy
                 -> Claude exits; remaining descendants are terminated
```

## 5. Integrate Claude after the generic path passes

Make the existing `claude` wrapper resolve the installed executable and invoke
`sandbox-host`.

Require Claude to be installed for the first version. Move any automatic update
execution inside the sandbox boundary. Preserve the bootstrap shell's
`-NoProfile` behavior so it does not execute writable profile code before
containment.

Test existing Claude authentication, resume, file tools, PowerShell, Git, builds,
and locally started MCP servers. The boundary wraps the whole Claude process and
its descendants, including its own file operations and locally started tools.

## 6. Make acceptance behavioral

| Test | Required evidence |
| --- | --- |
| Files | Existing project/profile files writable; unrelated user files inaccessible |
| Alternate paths | Junction, hardlink, and alternate-spelling probes respect the intended boundary |
| Web | Allowed destinations work; denied destinations and direct connections fail |
| DNS | Controlled receiver or capture establishes whether queries leave the host |
| Inbound | Host localhost client succeeds; controlled LAN peer fails, including wildcard-bound listeners and IPv6 |
| Lifecycle | Normal exit, cancellation, and launcher failure leave no surviving workload descendants |
| Terminal | Claude works interactively with resize, Ctrl+C, and its normal PowerShell paths |
| Configuration | Current policy stays fixed; later edits require the documented application step |

The first implementation milestone is the standalone launcher spike with these
boundary probes. Integrate it into orchestration after those probes establish
that PSEC can satisfy the selected contract.

This plan does not establish runtime enforcement. The observations above are
startup compatibility tests, not confinement acceptance. No production
implementation or host-policy changes have been made as part of defining it.

[mxc-builder]: https://github.com/microsoft/mxc/blob/6cd3d58f05d3447e67109cfb75e042803b843ca4/src/backends/appcontainer/common/src/base_container_helpers.rs
[mxc-runner]: https://github.com/microsoft/mxc/blob/6cd3d58f05d3447e67109cfb75e042803b843ca4/src/backends/appcontainer/common/src/base_container_runner.rs
[mxc-session-zero]: https://github.com/microsoft/mxc/issues/1465
