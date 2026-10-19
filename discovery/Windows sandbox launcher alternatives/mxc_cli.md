# Microsoft MXC standalone Windows executor

## Can an existing executable replace the proposed native sandbox host?

### Takeaway

Yes, the strongest first candidate is Microsoft's existing `wxc-exec.exe`, rather than writing another Rust/PSEC launcher. The released v1.0.1 executor accepts arbitrary native commands after `--`, JSON filesystem/network policy, inherited console I/O, and job-owned descendant cleanup; the selected localhost-ingress requirement makes this particular policy fail closed when PSEC cannot service it. This is source-verified suitability, not tested Claude compatibility. [CLI source](https://github.com/microsoft/mxc/blob/v1.0.1/src/tools/wxc/src/main.rs), [PSEC runner](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs), [tier guard](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/fallback_detector.rs).

### Cited Findings

- Current release checked 2026-10-18: v1.0.1, published 2026-10-17 00:55:03 UTC, commit `fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`; stable request schema remains `1.0.0`. All source findings below refer to that tag, not mutable main. [Release](https://github.com/microsoft/mxc/releases/tag/v1.0.1), [release API](https://api.github.com/repos/microsoft/mxc/releases/latest).
- Release offers signed binaries in `mxc-release-binaries.zip` (542,051,775 bytes); published asset digest `sha256:0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9`. Download/package contents and signatures were not independently inspected. [Download](https://github.com/microsoft/mxc/releases/download/v1.0.1/mxc-release-binaries.zip), [asset metadata](https://api.github.com/repos/microsoft/mxc/releases/assets/649098596).
- Windows executor binary name is `wxc-exec`, package `wxc`; CLI supports positional policy JSON, `--config` inline JSON, `--config-base64`, `--probe`, debug logging, and command override after `--`. `process.commandLine` can be omitted for normal launch when overridden by command argv. Upstream examples explicitly show `wxc-exec policy.json -- python --version`. [CLI](https://github.com/microsoft/mxc/blob/v1.0.1/src/tools/wxc/src/main.rs), [binary declaration](https://github.com/microsoft/mxc/blob/v1.0.1/src/tools/wxc/Cargo.toml).
- The command-vector serializer has Windows CreateProcess argument escaping and unit cases for whitespace, empty strings, embedded quotes, backslashes, and shell metacharacters. Invoke a full `.exe` path; a `.cmd` shim needs explicit command-processor treatment. [Argument serializer](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/core/mxc_common/cmdline.rs).
- Stable schema provides `filesystem.readonlyPaths`, `filesystem.readwritePaths`, `filesystem.deniedPaths`, `process.cwd`, `process.env`, `process.inheritDefaultEnv`, `process.timeout` (milliseconds; zero is no timeout), and lifecycle settings. It rejects unknown properties. [Stable schema](https://github.com/microsoft/mxc/blob/v1.0.1/schemas/stable/mxc-config.schema.1.0.0.json), [schema guide](https://github.com/microsoft/mxc/blob/v1.0.1/docs/schema.md).
- A supplied environment replaces defaults unless `inheritDefaultEnv:true`; defaults come from the user's profile environment, not arbitrary wrapper-shell variables. Therefore explicitly supply proxy/runtime variables to preserve the intended launcher contract. Windows requires `SYSTEMROOT` and `LOCALAPPDATA`. [Environment documentation](https://github.com/microsoft/mxc/blob/v1.0.1/docs/schema.md), [environment builder](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs).
- Normal PSEC execution inherits the existing console when stdout and stderr are terminals. When either is redirected it uses the parent's standard handles; streaming SDK capture is separate. CLI normally reserves stdout/stderr for the workload and returns the workload response exit code; backend errors can add a JSON error envelope to stderr. CLI does not require a captured-JSON protocol for normal runs. [PSEC spawn implementation](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs), [CLI output and exit](https://github.com/microsoft/mxc/blob/v1.0.1/src/tools/wxc/src/main.rs).
- Children are created suspended, assigned to a job, then resumed. Job creation/assignment failure terminates the child and rejects execution. Jobs have `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; normal wait terminates remaining descendants, and kill/drop/timeout paths also own tree termination. Drain observation normally has a five-second bound and can warn rather than conclusively fail if the job does not empty. [Runner](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs), [job implementation](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/job_object.rs).
- License is MIT, including permission to use/modify/redistribute while retaining copyright/license text. [License](https://github.com/microsoft/mxc/blob/v1.0.1/LICENSE.md).

### Inferences

- Keep the proposed generic UX if useful, but implement it initially as orchestration/configuration around the pinned executor. Most planned native launch/lifetime/stdio code would duplicate upstream. [CLI](https://github.com/microsoft/mxc/blob/v1.0.1/src/tools/wxc/src/main.rs), [runner](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs).

### Gaps

- No binary download, executable launch, host policy change, Claude test, terminal test, or network/filesystem enforcement test was performed. Exact required files inside the large signed release payload remain to be inspected before packaging.
- The fixed policy, applied external allowproxy list, account identity, runtime path roots, and outer wfp-lock status are orchestration responsibilities; upstream executor does not establish this repository's cross-component contract.

## Does the existing CLI enforce the selected PSEC-only boundary and network posture?

### Takeaway

`containment:"processcontainer"` alone is not PSEC-only: generic requests can fall back to AppContainer/BFS/DACL. For the agreed contract, explicitly requiring `network.ingress.hostLoopback:"allow"` causes v1.0.1 tier selection to reject the request whenever PSEC cannot service the complete request; set `fallback.allowDaclMutation:false` too. Use direct numeric loopback egress rules plus explicit proxy environment variables, not MXC's separate built-in runtime proxy mode. [Tier selection](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/fallback_detector.rs), [networking guide](https://github.com/microsoft/mxc/blob/v1.0.1/docs/backends/process-container/networking.md).

### Cited Findings

- `choose_backend_tier` evaluates `BaseContainerRunner::can_backend_service_request` for the complete request. Before entering fallback logic it returns `IngressUnsupported` if host-loopback allow was requested and BaseContainer cannot service it; enumeration-only paths have a similar guard. This is also unit-tested. There is no standalone `requirePsec` schema switch; `allowDaclMutation:false` only forbids DACL fallback and does not independently rule out BFS. [Guard and tests](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/fallback_detector.rs), [fallback schema](https://github.com/microsoft/mxc/blob/v1.0.1/schemas/stable/mxc-config.schema.1.0.0.json).
- Released `BaseContainerRunner` uses the PSEC two-phase API and attaches `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` to `CreateProcessW`. Native API resolution uses official `CreateProcessSecurityEnvironment`, `QueryProcessSecurityEnvironmentSupport`, and `CloseProcessSecurityEnvironment`; version support and capability queries fail closed. This is not a legacy BaseContainer launch hidden behind the selected tier name. [Native API](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/secenv.rs), [runner](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs).
- `wxc-exec --probe policy.json` provides request-aware JSON selection diagnostics without spawning the workload: expect `tier:"base-container"`, `needsDaclAugmentation:false`, no `error`, and applicable capability facts such as `baseContainerSupportsIngressHostLoopbackAllow`. CLI probe does not apply the command argv override, so include a harmless valid `process.commandLine` in probeable policy files. Probe is not purely read-only on all states: CLI runs orphaned DACL-state recovery before its detection-only branch. [CLI probe path](https://github.com/microsoft/mxc/blob/v1.0.1/src/tools/wxc/src/main.rs), [probe fields](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/probe.rs).
- Direct mode allows `egress.default:"deny"` with CIDR/protocol/destination-port rules, `ingress.default:"deny"`, and independent `ingress.hostLoopback:"allow"`. Nonloopback network capabilities are derived from directional policy; localhost capability/peer grant is added separately. PSEC serializes direct egress rules to the native security environment. [Network capability derivation](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/network_policy_helpers.rs), [PSEC policy builder](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/base_container_helpers.rs), [schema](https://github.com/microsoft/mxc/blob/v1.0.1/schemas/stable/mxc-config.schema.1.0.0.json).
- The native runtime proxy feature (`runtimeConfig.networkProxy`) is different: it requires `ingress.default:"allow"`, which grants bidirectional private-network capability, and cannot combine with direct egress rules. Its identity-less proxy mapping additionally documents broken host-to-container listener connections on one tested build. These limitations do not establish failure of the selected direct-loopback mode; avoid that feature for this plan. [Networking guide](https://github.com/microsoft/mxc/blob/v1.0.1/docs/backends/process-container/networking.md).
- Process-container OS support table: Windows 11 24H2 `26100.9278`, 25H2 `26200.9278`; loopback-hosting support arrives at `26100.9550`/`26200.9550` according to networking docs. Table also lists 26H2 `26300.9550` and 26H1 `28000.2804`; runtime feature probes remain necessary rather than trusting version strings. [OS support](https://github.com/microsoft/mxc/blob/v1.0.1/docs/backends/process-container/os-version-support.md), [network support progression](https://github.com/microsoft/mxc/blob/v1.0.1/docs/backends/process-container/networking.md).
- `wxc-exec` never elevates itself. `wxc-host-prep` is a separate privileged tool for AppContainer/DACL host preparation, not a required daily PSEC launch step. PSEC applies scoped enforcement through the OS elevated context with no per-launch UAC prompt. [Host preparation](https://github.com/microsoft/mxc/blob/v1.0.1/docs/backends/process-container/host-prep.md), [network enforcement](https://github.com/microsoft/mxc/blob/v1.0.1/docs/backends/process-container/networking.md).

### Inferences

- For the agreed mandatory host-loopback policy, an extra native PSEC-only launcher is unnecessary to prevent fallback in this pinned release. A wrapper can inspect the probe for diagnostics and still rely on actual launch's request-level guard; a probe alone would be insufficient if the config were changed afterwards. Recheck this guard when updating MXC. [Tier selection](https://github.com/microsoft/mxc/blob/v1.0.1/src/mxc-sdk/src/backends/process_container/common/fallback_detector.rs).
- The following is a source-derived candidate (unexecuted). Replace account/project/tool roots and proxy port with actual installed values. Keep a harmless command in JSON so request-aware probing works; actual launch overrides it. `inheritDefaultEnv` means profile defaults plus these explicit variables, not all current shell state. [CLI](https://github.com/microsoft/mxc/blob/v1.0.1/src/tools/wxc/src/main.rs), [schema guide](https://github.com/microsoft/mxc/blob/v1.0.1/docs/schema.md).

```json
{
  "version": "1.0.0",
  "containment": "processcontainer",
  "fallback": { "allowDaclMutation": false },
  "process": {
    "commandLine": "C:\\Windows\\System32\\cmd.exe /d /c exit 0",
    "cwd": "C:\\AgentSandbox\\project",
    "inheritDefaultEnv": true,
    "timeout": 0,
    "env": [
      "HTTP_PROXY=http://127.0.0.1:8080",
      "HTTPS_PROXY=http://127.0.0.1:8080",
      "http_proxy=http://127.0.0.1:8080",
      "https_proxy=http://127.0.0.1:8080"
    ]
  },
  "filesystem": {
    "readwritePaths": ["C:\\AgentSandbox\\project", "C:\\Users\\AgentSandbox"],
    "readonlyPaths": ["C:\\Windows", "C:\\Program Files"]
  },
  "network": {
    "egress": {
      "default": "deny",
      "allow": [{
        "to": [{ "cidr": "127.0.0.1/32" }],
        "ports": [{ "protocol": "tcp", "port": 8080 }]
      }]
    },
    "ingress": { "default": "deny", "hostLoopback": "allow" }
  }
}
```

```powershell
# Source-derived syntax, not a tested launch recipe:
& 'C:\Program Files\mxc\wxc-exec.exe' --probe 'C:\path\policy.json'
& 'C:\Program Files\mxc\wxc-exec.exe' 'C:\path\policy.json' -- `
    'C:\Users\AgentSandbox\.local\bin\claude.exe' --resume
```

### Gaps

- Need runtime acceptance on the actual restricted-account host: RO/RW roots (existing contents and alternate paths), IPv4/IPv6/wildcard listener ingress from localhost versus controlled LAN peer, proxy-only egress and DNS receiver evidence, interactive Claude/authentication/MCP/build tools, Ctrl+C/resize, normal exit, timeout, abrupt launcher death, and existing launch-as job/console nesting.
- The configuration example illustrates upstream schema, not a security-reviewed minimal Windows/runtime allowlist. Broad Program Files read-only access may be unnecessary and should be replaced with exact tool roots during integration.
- Standard-user/no-install PSEC usage is documented and source-supported; local feature availability, Windows update state, installed service dependencies, executable signatures, and successful unelevated operation were not verified here.
