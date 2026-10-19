# Existing agent sandbox launchers

Research date: 2026-10-18. Read-only upstream source/package research; no candidate was installed or executed. Requirements read from `discovery/MXC-Host-Plan.md`. Microsoft MXC CLI and Sandboxie are investigated separately by other researchers.

## Does Anthropic already offer a native Windows replacement?

### Takeaway

Yes: **Anthropic's standalone `sandbox-runtime` now has a published native Windows alpha backend**. This corrects a broad claim that Anthropic has no Windows sandbox, but it is separate from whether Claude Code actually ships/enables native Windows shell sandboxing. It is a serious existing alternative if the dedicated-account architecture is acceptable; it does not implement the agreed same-account PSEC contract. [Repository](https://github.com/anthropics/sandbox-runtime), [v0.0.80 release](https://github.com/anthropics/sandbox-runtime/releases/tag/v0.0.80).

### Cited Findings

- Latest published release inspected: **v0.0.80, 2026-10-16**. npm registry `latest` is `0.0.80`. Downloaded the official tarball to a temporary file and listed it without running it: it contains both `package/vendor/srt-win/x64/srt-win.exe` and `package/vendor/srt-win/arm64/srt-win.exe`. This is published support, not merely unreleased `main`. [Release](https://github.com/anthropics/sandbox-runtime/releases/tag/v0.0.80), [registry metadata](https://registry.npmjs.org/@anthropic-ai%2Fsandbox-runtime), [published artifact](https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/-/sandbox-runtime-0.0.80.tgz).
- Windows support started with restricted-token/network facilities in **v0.0.53, 2026-06-04**; the separate-account launch appeared in **v0.0.62, 2026-06-29**; **v0.0.63, 2026-07-01** added full session filesystem grants and made sandbox-user mode the only TS path. The explicit Windows platform README followed in v0.0.64. [v0.0.53](https://github.com/anthropics/sandbox-runtime/releases/tag/v0.0.53), [v0.0.62](https://github.com/anthropics/sandbox-runtime/releases/tag/v0.0.62), [v0.0.63](https://github.com/anthropics/sandbox-runtime/releases/tag/v0.0.63), [v0.0.64](https://github.com/anthropics/sandbox-runtime/releases/tag/v0.0.64).
- General-purpose CLI and TypeScript library; Apache-2.0; Node >=22.12.0. npm installs `srt`. One-time `windows-install` elevates to provision the account and WFP filters. The CLI explicitly selects its bundled helper when no path was configured; library embedding must set `windows.srtWin.path` explicitly. [Versioned package metadata](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/package.json), [versioned CLI](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/src/cli.ts), [Windows helper configuration](https://github.com/anthropics/sandbox-runtime/releases/tag/v0.0.67).
- Windows uses native host executable execution, a separate local account defaulting to `srt-sandbox`, account-SID WFP egress filtering, restricted token, private desktop, explicit handle list and job objects. It does **not** use MXC/PSEC. The account name is configurable by `srt-win install --sandbox-user`, but changing the name does not turn it into a same-account per-run PSEC wrapper. [Versioned Windows implementation](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/src/sandbox/windows-sandbox-utils.ts), [CLI account option](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/cli.rs), [launch path](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/launch.rs).
- Launch is broker -> `CreateProcessWithLogonW` runner -> restricted-token workload. `USERPROFILE`, TEMP and HKCU belong to the sandbox account. Caller PATH and generated proxy environment are overlaid. Therefore it changes the identity/profile behavior selected for this project, even if launched by the existing AgentSandbox account. `seclogon` must work. [Broker launch](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/logon.rs), [runner](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/runner.rs).
- Session `allowRead`/`allowWrite` grants are explicit on-disk ACEs for the sandbox SID, later revoked. Per-command grants are unsupported, although per-command denies exist. This is stateful ACL preparation, not an immutable PSEC filesystem policy. [Windows ACL wrapper](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/src/sandbox/windows-sandbox-utils.ts), [ACL implementation](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/acl.rs).
- Domain policy supports optional destination ports. An external HTTP proxy can be supplied, but command-specific registered network lists do not apply to an external proxy; the external proxy decides the policy. The account WFP permit must include its loopback port range. [Network configuration](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/src/sandbox/sandbox-config.ts), [proxy setup](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/src/sandbox/sandbox-manager.ts).
- WFP source installs filters at **ALE_AUTH_CONNECT_V4/V6 only**, permits loopback in the configured port range, and blocks the sandbox user's other connects. There is no inbound receive/accept or listen-layer filtering in this implementation. Therefore do not credit it with the requested localhost-only ingress policy. [Versioned WFP implementation](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/wfp.rs).
- Job kill-on-close is enabled before suspended assignment; the workload's job disallows breakaway. The runner waits for the main workload, explicitly drops the job, then returns its exit code, killing remaining ordinary descendants. Broker->runner has a separate cleanup job. This covers ordinary process-tree lifetime, not an independent guarantee for service-mediated process creation. [Job implementation](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/job.rs), [workload exit path](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/launch.rs), [broker](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/logon.rs).
- Interactive compatibility needs investigation: the Windows implementation uses anonymous stdin/out/err pipes and `CREATE_NO_WINDOW`, not an evident ConPTY session. Native commands are supported, but that does not establish Claude's full-screen TUI, resize and Ctrl+C behavior. [Broker pipes](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/logon.rs), [child stdio](https://github.com/anthropics/sandbox-runtime/blob/v0.0.80/vendor/srt-win-src/src/launch.rs).

### Inferences

- **Evaluate, do not adopt blindly:** this could replace much of `launch-as` + account WFP + ACL preparation if those roles were intentionally consolidated. Adding it inside the current account instead creates another account layer and a different profile; it is not a small drop-in replacement for the proposed PSEC host.
- Existing machine-installed `wfp-lock` policies match the existing account SID. A child launched under the Anthropic account would depend on Anthropic's own installed fence or explicitly updated orchestration; nesting the command under AgentSandbox does not carry its SID filter across the account switch.
- Whole-Claude wrapping is possible in principle because the CLI wraps arbitrary commands, unlike a hook that merely approves tools. Interactive behavior, profile/authentication and filesystem boundaries remain acceptance tests.

### Gaps

- No installed/elevated/in-account/interactive tests were run. Ability of the existing restricted token/logon environment to operate Anthropic's broker, desktop setup and ACL preparation is unverified.
- No proof of localhost-only inbound denial, full-profile RW compatibility or existing-account policy reuse.
- The upstream README explicitly acknowledges system DNS resolver traffic is not fenced by its user-SID WFP rules. DNS confinement must be tested separately rather than inferred from denied direct TCP/UDP.
- A separate coordinator check of current Claude Code product docs is required: published standalone Windows alpha does not prove that the native Claude `/sandbox` feature uses it.

## Are ready-to-use Windows-hosted VM or WSL tools alternatives?

### Takeaway

**Docker Sandboxes is now a real Windows offering**, and nono runs on Windows through WSL2. Both are useful for Linux development but change the native Windows toolchain requirement. OpenSandbox can also supply an actual Windows guest, with a Linux/KVM control plane. [Docker install](https://docs.docker.com/ai/sandboxes/install/), [nono platform support](https://github.com/nolabs-ai/nono/blob/main/README.md), [OpenSandbox Windows guide](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/guides/windows-sandbox.md).

### Cited Findings

| Candidate | Verified current support | Relevance to this plan |
| --- | --- | --- |
| Docker Sandboxes `sbx` | Native Windows CLI, Windows 11 x64, Windows Hypervisor Platform; per-user MSI/WinGet installation does not require elevation, enabling hypervisor does. Latest inspected stable v0.48.0 dated 2026-10-13. [Install](https://docs.docker.com/ai/sandboxes/install/), [releases](https://docs.docker.com/ai/sandboxes/release-notes/) | Ready-made Claude integration, but workloads have a **Linux kernel in a microVM**, so it cannot run the existing native MSVC/Win32 environment. [Isolation architecture](https://docs.docker.com/ai/sandboxes/security/isolation/) |
| nono | Apache-2.0; official current README explicitly says Windows **WSL2**. v0.80.0 published 2026-10-13. [README](https://github.com/nolabs-ai/nono/blob/main/README.md), [release](https://github.com/nolabs-ai/nono/releases/tag/v0.80.0) | Wraps entire processes/Claude with Landlock in WSL2. Native Windows enforcement is a proposal, not established shipping functionality: NEP-0005 draft merged 2026-10-01 as documentation. [WSL2 explanation](https://www.nono.sh/blog/nono-wsl2-windows-support), [proposal PR](https://github.com/nolabs-ai/nono/pull/2032) |
| OpenSandbox | Apache-2.0 runtime platform/API/SDKs, Docker or Kubernetes. A Windows profile **does exist**: Windows guest using dockur/windows within Linux KVM/QEMU, requiring `/dev/kvm` and `/dev/net/tun`, minimum 2 CPUs, 4 GiB memory, 64 GiB disk. [README](https://github.com/opensandbox-group/OpenSandbox), [Windows profile](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/guides/windows-sandbox.md) | Can execute native Windows binaries **inside the guest**, not wrap host processes inside the existing restricted account. Separate guest installation/toolchain and lifecycle infrastructure. |

- Docker outbound TCP is routed through a host proxy; UDP is off by default; DNS is policy-aware. Workspaces can be directly mounted RW, cloned from an RO source, or kept entirely in the VM. Sandboxes persist across stop/restart until removal; therefore a Claude exit does not inherently imply the selected terminate-all-on-exit contract. [Isolation layers](https://docs.docker.com/ai/sandboxes/security/isolation/), [persistence/lifecycle](https://docs.docker.com/ai/sandboxes/architecture/).
- Docker supports network policy, agent credentials and dedicated in-VM Docker. Its code is proprietary, with downloadable releases; open GitHub release packaging does not mean the sandbox runtime source is open. [Official release repository](https://github.com/docker/sbx-releases), [license](https://github.com/docker/sbx-releases/blob/main/LICENSE).
- OpenSandbox offers both whole coding-agent examples and MCP-server integration. The MCP tool path by itself does not sandbox the parent Claude process: the complete agent must run in the guest to meet this plan. [Claude example](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/examples/claude-code.md), [MCP architecture](https://github.com/opensandbox-group/OpenSandbox#MCP).

### Inferences

- If the workflow can switch to Linux tools, Docker is worth evaluating before building anything; it is much closer to a complete product than a new host.
- If native host Windows binaries/profile continuity are fixed requirements, Docker and nono do not replace this plan. OpenSandbox Windows would replace the environment with a VM rather than satisfy an in-account wrapper.

### Gaps

- No VM/WSL/runtime was started; no compatibility or performance claims were measured.
- No attempt made to make WSL interoperable `.exe` launches part of the Linux sandbox: Linux Landlock must not be assumed to restrict a Windows process launched across WSL interoperability.

## What should the implementation decision change?

### Takeaway

Keep the native same-account/PSEC goal distinct from the broader search for an agent sandbox. Existing upstream tools justify an adoption spike before new code, especially the MXC CLI covered by the other researcher; Anthropic's alpha is the strongest separately maintained native agent-runtime comparison. [MXC](https://github.com/microsoft/mxc), [Anthropic runtime](https://github.com/anthropics/sandbox-runtime).

### Cited Findings

- A documented existing MXC+Claude recipe uses `@microsoft/mxc-sdk` and a small Node script, or Microsoft's `wxc-exec.exe`. It is an integration example rather than another independently maintained host product. It warns that MXC host allow/block lists are not enforced on Windows in that recipe, so proxy policy remains important. [Varlock MXC guide](https://varlock.dev/sandboxes/mxc/).
- Anthropic has already implemented arbitrary-command native Windows account, filesystem, WFP and process lifetime mechanics in an Apache-2.0 package. Its source also exposes the integration differences needing review. [Versioned Windows backend](https://github.com/anthropics/sandbox-runtime/tree/v0.0.80/vendor/srt-win-src/src).

### Inferences

1. First test whether Microsoft's existing CLI can launch Claude and meet PSEC-only/lifetime/terminal requirements with configuration alone.
2. Compare Anthropic standalone Windows alpha only if accepting its separate-account/profile/ACL model; preserve the distinction from product-native `/sandbox` support.
3. A new host remains justified only for gaps established by these probes, such as fail-closed PSEC selection, terminal handling or lifecycle policy. Prefer a small composition wrapper over reimplementing either kernel integration.

### Gaps

- This search does not prove that no other existing host exists. It identifies the closest credible upstream candidates and the reasons their architectures match or differ.
- No enforcement audit of Anthropic, Docker, nono or OpenSandbox was performed; documented design and source behavior are not exploit-resistance evidence.
