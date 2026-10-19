# Native Windows sandbox launcher alternatives

Research date: 2026-10-18. Scope: established native sandboxes and lightweight
AppContainer/restricted-token launchers against the agreed MXC host contract.
Evidence is official project documentation, repositories and release pages only.
Nothing was installed or executed. Documentation claims below are not runtime
acceptance results.

## Which native tools are genuinely close?

### Takeaway

Sandboxie Plus is the strongest established alternative; Sandy is the closest small
native wrapper. Neither implements the agreed PSEC backend. Both deserve evaluation
before writing a new general launcher, provided changing that requirement is acceptable.

### Cited Findings

- **Sandboxie Plus/Classic**: both editions share core security/compatibility
  components; Classic's interface is no longer developed. Plus is the appropriate
  edition for current security options. Its repository contains the driver/service
  machinery as well as the UI. — [Official repository](https://github.com/sandboxie-plus/Sandboxie)
- Sandboxie has an existing arbitrary-program launcher. Example shape:
  `Start.exe /box:Claude /wait <claude.exe> <arguments>`. `/wait` waits for the
  launched process, not all descendants. Termination commands request cleanup and
  their zero exit status does not prove every process stopped. — [Start CLI](https://sandboxie-plus.github.io/sandboxie-docs/Content/StartCommandLine/)
- `LeaderProcess=claude.exe` can terminate the other processes in a box when no
  configured leader image remains after leaders were observed. This is box-wide,
  image-based lifetime management, not ownership of one specific root PID.
  — [Leader process](https://sandboxie-plus.github.io/sandboxie-docs/Content/LeaderProcess/)
- The official latest-release redirect resolved to **1.18.8 / 5.73.8**, released
  October 17, during this investigation. This is clear current maintenance evidence.
  — [Pinned release](https://github.com/sandboxie-plus/Sandboxie/releases/tag/v1.18.8)
- **Sandy (`ahrvoje/sandy_cli`)** explicitly targets arbitrary native executables,
  agent workflows, persistent profiles and transient launches. It is a single
  native executable using AppContainer, LPAC or restricted tokens. Normal launches
  do not need elevation; ACL grants require `WRITE_DAC`, and loopback exemptions
  require an administrator. The README explicitly describes console-handle
  passthrough and mentions Claude Code compatibility; that is a project claim,
  not validation on this host. — [Official README](https://github.com/ahrvoje/sandy_cli)
- Sandy's latest-release redirect resolved to **v0.9996**, released October 11.
  The project has an MIT license. Main-branch documentation may describe changes
  after that release; pin and inspect the intended release before evaluation.
  — [Release](https://github.com/ahrvoje/sandy_cli/releases/tag/v0.9996),
  [License](https://github.com/ahrvoje/sandy_cli/blob/main/LICENSE)
- Sandy already exposes `-c config.toml -x executable args`, saved-profile creation,
  `--check`/dry-run validation and cleanup/status commands. This is substantially
  the proposed generic CLI surface. — [Usage](https://ahrvoje.github.io/sandy_cli/usage.html)

### Inferences

- A separate Sandboxie box per Claude invocation avoids unrelated sessions sharing
  `LeaderProcess` shutdown. Its installed privileged infrastructure and policy
  permissions need explicit orchestration work. — [Leader process](https://sandboxie-plus.github.io/sandboxie-docs/Content/LeaderProcess/)
- Sandy could remove most custom filesystem/launch/console work, while existing
  WFP/proxy components retain networking responsibility. This would replace PSEC
  with ACL/token confinement rather than fulfill the current backend contract.
  — [Sandy architecture](https://ahrvoje.github.io/sandy_cli/internals.html)

### Gaps

- No restricted-account launch, Claude authentication/resume, PowerShell, MSVC,
  existing profile, or descendant-cleanup acceptance was run for either tool.
- Sandboxie's exact standard-user configuration editing and per-user launch ACLs
  were not established from the inspected pages. Treat install-once/daily-launch
  compatibility as plausible, requiring validation, rather than a proven fit.
- Neither candidate was found to provide MXC/PSEC. If PSEC remains mandatory,
  neither is a drop-in backend.

## How well do filesystem, networking, lifecycle and licensing match?

### Takeaway

Sandboxie has the broadest controls but adds a driver, service, virtualization
semantics and paid-feature considerations. Sandy stays lightweight but mutates
host ACLs and its AppContainer loopback model does not provide loopback-only
networking.

### Cited Findings

- Sandboxie's ordinary model permits reads from host files and redirects changes
  into the sandbox. That default alone does **not** provide the proposed
  filesystem read allowlist. — [Sandbox hierarchy](https://sandboxie-plus.com/sandboxie/sandboxhierarchy/)
- Its Privacy Mode changes the default so most unsandboxed data cannot be read,
  with Windows and Program Files exceptions; user registry reads are also limited.
  Resource rules create exceptions. It requires a supporter certificate.
  — [Privacy mode](https://sandboxie-plus.github.io/sandboxie-docs/PlusContent/privacy-mode/)
- `OpenFilePath` allows direct updates to host files, making project/profile RW
  feasible without copy-back. By default it does not apply to executables loaded
  from inside the virtual sandbox, an important downloaded-tool/build-output
  compatibility detail. Path-pattern boundaries also require care.
  — [Direct host file access](https://sandboxie-plus.github.io/sandboxie-docs/Content/OpenFilePath/)
- `ReadFilePath` and `ClosedFilePath` supply read-only and denied path treatment.
  The resource-rule model distinguishes programs executing from the host and
  virtualized sandbox. — [Read-only](https://sandboxie-plus.github.io/sandboxie-docs/Content/ReadFilePath/),
  [Denied](https://sandboxie-plus.github.io/sandboxie-docs/Content/ClosedFilePath/),
  [Resource access](https://sandboxie-plus.github.io/sandboxie-docs/Content/ResourceAccess.html)
- Sandboxie's `NetworkAccess` accepts process, IP address/range, port and protocol
  rules. Unmatched traffic is allowed unless a broad deny rule is supplied.
  Its user-mode hooks can be bypassed; WFP mode evaluates tracked processes at
  outbound-connect and inbound receive/accept authorization layers.
  — [Network rules](https://sandboxie-plus.github.io/sandboxie-docs/Content/NetworkAccess/)
- WFP enforcement uses driver callouts and must be enabled globally with
  `NetworkEnableWFP=y` (default off). Other WFP products can coexist, but effective
  policy depends on arbitration and installed filters. Documentation explicitly
  does not promise fail-closed behavior for every WFP failure.
  — [WFP support](https://github.com/sandboxie-plus/sandboxie-docs/blob/main/docs/PlusContent/WFPSupport.md)
- Sandboxie DNS filtering intercepts name lookups; it is not a domain-based
  network security boundary for arbitrary protocols/direct addresses. It requires
  an applicable certificate. Retaining the external proxy plus kernel endpoint
  restrictions is preferable for the agreed web policy.
  — [DNS filtering](https://sandboxie-plus.github.io/sandboxie-docs/Content/NetworkDnsFilter/)
- The project publishes GPL-3.0 licensing, while its distributed feature/usage
  entitlement matrix requires a **Business Certificate for commercial or
  educational use**. Privacy/security enhanced boxes require paid supporter
  entitlements. WFP is listed in Free Plus. Proxy Injection and DNS Filtering
  require an Advanced Feature Pack except for certificate types that include it.
  Do not collapse source licensing and vendor binary feature entitlements into
  one statement. — [Repository](https://github.com/sandboxie-plus/Sandboxie),
  [Official entitlement matrix](https://sandboxie-plus.com/feature-comparison/)
- Sandy directly grants host paths through ACLs. Recursive and single-object
  scopes support read, write, execute and other rights. `all` excludes
  `WRITE_DAC`, `WRITE_OWNER` and `FILE_DELETE_CHILD`. It is not a virtual
  filesystem/copy-on-write system. — [Configuration](https://ahrvoje.github.io/sandy_cli/config.html)
- Sandy tracks ACL changes, container state and per-user logon recovery tasks.
  Crashes or forced termination can require later cleanup; inherited ACEs on
  moved files may change as Windows recomputes inheritance. Persistent profiles
  deliberately leave their grants until profile deletion.
  — [Internals and cleanup](https://ahrvoje.github.io/sandy_cli/internals.html),
  [Profile lifecycle](https://github.com/ahrvoje/sandy_cli#profiles)
- Sandy AppContainer/LPAC loopback requires `privateNetworkClientServer` and an
  administrator-added exemption. Its documentation explicitly says this is not
  localhost-only; private networking is also allowed. Restricted-token mode has
  no AppContainer network isolation. No domain allowlist proxy is described.
  — [README network notes](https://github.com/ahrvoje/sandy_cli#notes)
- Sandy documents child-process controls, timeout/tree termination and Ctrl+C
  cleanup. Host ACL recovery after forced termination is deferred. Documentation
  alone does not prove the exact normal-root-exit/remaining-descendants contract.
  — [Official overview](https://ahrvoje.github.io/sandy_cli/),
  [Usage](https://ahrvoje.github.io/sandy_cli/usage.html)

### Inferences

- Sandboxie WFP rules could potentially allow loopback peers while rejecting
  remote inbound and retaining the existing proxy policy. Both IPv4/IPv6,
  wildcard-bound listeners and WFP coexistence need behavioral tests.
  — [Network rules](https://sandboxie-plus.github.io/sandboxie-docs/Content/NetworkAccess/)
- A persistent Sandy profile could let elevated setup create the loopback
  exemption once and keep daily launch unprivileged. Transient identities would
  need a new exemption each time; this conflicts with an entirely unprivileged
  transient loopback workflow. Neither solves LAN inbound denial by itself.
  — [Profile and loopback documentation](https://github.com/ahrvoje/sandy_cli#profiles)
- Using Sandy restricted-medium mode could favor native tool/pipe compatibility
  while WFP/proxy enforce web egress. It still needs a new inbound enforcement
  component and review of read confinement, protected descendants and ACL races.
  — [Mode guidance](https://ahrvoje.github.io/sandy_cli/)

### Gaps

- No documented proof was found for the full contracted mix of live host profile
  RW, read allowlisting, localhost inbound, remote inbound denial and normal-root
  descendant cleanup on either candidate.
- Sandboxie authentication/profile registry compatibility and build output
  execution require tests. Entire profile file access does not imply the same
  unsandboxed registry/credential behavior.
- The vendor entitlement matrix is cited as product policy, not legal advice.

## Are the other AppContainer launchers better reuse candidates?

### Takeaway

The other credible tools are libraries or examples with narrower contracts.
None found is a stronger ready-to-use fit than Sandy or Sandboxie.

### Cited Findings

- **Microsoft LaunchAppContainer** runs arbitrary executables in AppContainer or
  LPAC with capability SIDs, optional wait and profile retention. It documents no
  filesystem policy language, proxy policy or descendant lifetime workflow.
  — [Microsoft tool README](https://github.com/microsoft/SandboxSecurityTools/blob/main/LaunchAppContainer/README.md)
- **forderud/RunInSandbox** is an MIT-licensed C++ sample for executable/COM launch
  with AppContainer or integrity levels. Filesystem access is prepared through
  ACLs/`icacls`; the example suggests broad ALL APPLICATION PACKAGES grants rather
  than a complete policy manager. It is useful reference code, not equivalent to
  the planned orchestration contract. Do not confuse it with Windows Sandbox
  VM launch scripts also named Run-in-Sandbox.
  — [Official repository](https://github.com/forderud/RunInSandbox)
- **wincage** supplies Python-facing AppContainer plus job APIs and host ACL grants.
  However it explicitly supports **zero capabilities**, so no AppContainer network
  capability can be requested; it advises against treating itself as hostile-code
  containment. MIT licensed, with limited maintainer commitment stated.
  — [Official repository](https://github.com/rymorrisj/wincage)
- **Convira sandbox** is an Apache-2.0 TypeScript/C++ runtime with AppContainer/job
  Windows confinement and host probes. Unsupported hosts use an explicitly
  unconfined passthrough adapter. It is a library, not a turnkey generic CLI;
  native builds require node-gyp/Visual Studio tooling. Adoption would require a
  fail-closed adapter and a new host integration anyway.
  — [Official repository](https://github.com/Convira/convira-sandbox)
- **winexecsafe** offers a jail directory, additional read paths and coarse
  `--allow-network` switch. Its documented model does not expose the multiple RW
  roots, domain policy, loopback-only inbound or job teardown required here.
  It is a small project rather than evidence of an established all-in-one tool.
  — [Official repository](https://github.com/zarguell/winexecsafe)
- **hhnl.ProcessIsolation** is an MIT .NET AppContainer library, not an existing
  generic workflow host matching these policies.
  — [Official repository](https://github.com/anhaehne/hhnl.ProcessIsolation)

### Inferences

- If the existing MXC CLI already exposes the needed base-container contract,
  reusing it keeps native PSEC support and avoids adding an AppContainer/ACL
  backend plus its cleanup machinery. This research does not establish the MXC
  CLI contract; the coordinator's MXC investigation must decide that.

### Gaps

- This was a broad discovery pass followed by deeper official-source reading
  of Sandboxie and Sandy, not an exhaustive security audit of every small repo.
- Maintenance dates of the minor libraries were not independently established;
  their mere presence on GitHub is not evidence of long-term support.
- Same-account process isolation is deliberately not used as an acceptance
  criterion: the user accepted the existing account boundary. Tree lifetime
  management remains necessary and is separate from access isolation.
