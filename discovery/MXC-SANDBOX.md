# How Codex uses MXC on Windows

Investigated: 2026-10-17. Scope: the supplied `mxc-sandbox` adapter, its matching
Codex integration, and the exact Microsoft MXC dependency pinned by that integration.
This is source analysis; native enforcement was not tested.

## Main findings

Codex embeds Microsoft's MXC SDK and selects its native **BaseContainer / Process
Security Environment (PSEC)** path for Windows sandboxed commands. This path shares
the host Windows kernel and operates on host files. It does not start a Windows
Sandbox VM. The adapter creates neither dedicated sandbox users nor a setup or
elevation flow, and disables host DACL mutation. Existing Codex Windows sandboxes
remain separate backends. [Local overview][local-readme], [native launch][local-native].

The main boundary is an OS policy attached when the workload process is created.
Codex translates its permission profile into filesystem, network, capability, and
UI restrictions; MXC serializes that policy and calls Windows to create the security
environment. A job object owns the process tree and its lifetime. [PSEC builder][mxc-builder],
[Windows bindings][mxc-secenv], [process lifecycle][mxc-runner].

Two limits materially affect workflows:

- Managed networking permits broad, bidirectional host-loopback access, including
  local servers; it is not confined to the configured proxy ports.
- Remaining descendants are terminated when the foreground process exits, so
  detached development servers do not survive that command.

These limits are documented in both the [adapter README][local-readme] and
[official Windows sandbox guidance][official-windows].

## Evidence and source versions

The seven supplied Rust files, `Cargo.toml`, and `README.md` match the public Codex
files at revision `ce0323f2f2d3b25e82806cd555237da3db4e1897`, after normalizing line
endings and trailing end-of-file whitespace. The supplied directory is untracked
in this repository and is a workspace member copied without its parent Rust
workspace.

The matching [Codex workspace manifest][codex-manifest] pins `appcontainer_common`,
`learning_mode_windows`, and `wxc_common` to Microsoft MXC revision
`6cd3d58f05d3447e67109cfb75e042803b843ca4`. All Microsoft implementation links below
use that pin. Newer MXC code has reorganized modules and evolved its contracts;
it should not be substituted when explaining this adapter.

Evidence levels in this report:

| Evidence | What it establishes |
| --- | --- |
| Supplied Rust source | Adapter validation, policy translation, and launch requests |
| Matching Codex source | Backend selection, helper dispatch, shared transport, and dependency pin |
| Pinned Microsoft source | SDK policy serialization, Windows API calls, and process ownership |
| Test source inspection | Intended regression coverage and assertions, without a passing test result |
| Official documentation | Current product configuration guidance, separate from this source snapshot |

The internal Windows enforcement implementation is outside these sources. Reading
SDK code does not prove that a particular installed Windows build enforces every
restriction correctly.

## Launch path

```text
Codex executor: effective permission profile + exact argv + filtered environment
  -> sandbox manager selects WindowsMxc
  -> launches the executor's Codex executable with --__codex-windows-mxc
       typed JSON request carried in launcher-only environment chunks
  -> early helper dispatch, before ordinary CLI parsing
  -> decode and scrub transport variables
  -> resolve command-local Windows paths and build MXC ExecutionRequest
  -> BaseContainerRunner::spawn(..., StdioMode::Inherit)
       -> serialize PSEC policy as a FlatBuffer
       -> CreateProcessSecurityEnvironment(...)
       -> attach handle using PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT
       -> CreateProcessW(..., CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT)
       -> assign child to kill-on-close job
       -> ResumeThread
  -> wait for foreground exit
  -> terminate remaining descendants, then release enforcement state
```

The [sandbox manager][codex-manager] wraps the command using the executor's own
executable. [Early dispatch][codex-arg0] enters the helper. The local
[`lib.rs`][local-lib], [`windows.rs`][local-windows], and [`native.rs`][local-native]
implement the adapter side. The pinned [runner][mxc-runner] implements native launch
and teardown.

### The Windows primitive

MXC loads the system `processmodel.dll` using `LOAD_LIBRARY_SEARCH_SYSTEM32` and
resolves `CreateProcessSecurityEnvironment`,
`QueryProcessSecurityEnvironmentSupport`, and `CloseProcessSecurityEnvironment`.
The policy buffer produces an opaque `HPROCESS_SECURITY_ENVIRONMENT` handle.
`SecurityEnvironmentStartupInfo` places that handle into an extended process
attribute list. The resulting process is created through normal `CreateProcessW`.
The pinned builder emits a version 1.0 PSEC specification containing capabilities,
Win32k/UI restrictions, filesystem lists, and network policy. [API bindings][mxc-secenv],
[policy serialization][mxc-builder].

The adapter calls `BaseContainerRunner` directly instead of MXC's general
AppContainer dispatcher. It first requires a usable PSEC environment, rejects
`permissiveLearningMode`, checks deny-path support when needed, and supplies no
least-privilege mode, legacy MXC proxy, or denial-capture request. Those constraints
keep this request on the native PSEC path. This is narrower than the range of
backends and fallbacks supported by MXC as a whole. [Adapter guards][local-native],
[runner compatibility checks][mxc-runner].

### Availability and fallback

`is_available()` calls MXC's cached create/close probe. The probe actually creates
a minimal security environment and checks construction of its startup attributes;
it does not launch a workload. DLL/export presence or an OS build number alone is
insufficient. Native deny paths additionally require `PSE_SUPPORT_FS_DENY` from
`QueryProcessSecurityEnvironmentSupport`. [Adapter availability][local-lib],
[native probe][mxc-runner], [capability query][mxc-secenv].

Selection has two distinct forms:

| Selection | Behavior |
| --- | --- |
| `windows.sandbox = "mxc"` | Explicit selection; unavailable or incompatible execution fails |
| `features.prefer_mxc = true` | Selects MXC locally when eligible and available; otherwise keeps the configured legacy selection/setup |
| Remote execution | Keeps its configured backend rather than inheriting the local rollout choice |

The preference is resolved during configuration loading. Policy eligibility
includes MXC opt-outs and managed-network local-binding constraints. A command
failure after MXC selection does not cause a retry through a weaker backend.
The README describes the feature as default-off in this source snapshot, with
Desktop able to supply a saved rollout override on its next launch. This does not
establish the rollout state of any particular installation. [Configuration][codex-config],
[eligibility][codex-selection], [adapter rollout notes][local-readme].

## Policy translation

### Filesystem access

The input is Codex's canonical `PermissionProfile`, not a second independent
filesystem configuration. `build_request()` translates it into MXC's
`readwrite_paths`, `readonly_paths`, and `denied_paths`.

The adapter preserves read-only subpaths and protected metadata beneath writable
roots. The inspected regression test expects `.git`, `.agents`, `.codex`, and
`.aws` carveouts. It grants a carveout read access only if the original policy
already allowed reading it. A symbolic root deny represents default denial and
is not emitted as a blanket native deny that would erase narrower grants.
[Translation][local-policy], [carveout and precedence tests][local-tests].

Path handling has several important details:

- `PathUri` supplies Windows path identity while native spellings are retained for
  the OS. MXC object-conflict normalization runs before and after volume expansion
  to reconcile aliases. Tests include alias and equal-path precedence cases.
- `:root` is materialized against logical drives, with UNC roots from the policy
  cwd and command cwd included. Uninspectable implicit network roots can be
  omitted; explicit grants follow the normal validation path.
- Native volume-root grants are nonrecursive. The adapter grants each root and
  snapshots its immediate children as additional grants. A new top-level
  directory or newly mounted volume does not acquire access in an already
  running command merely because the policy originally named `:root`.
- Deny globs are expanded into concrete matches before launch using the existing
  Windows resolver. Later matching files are outside that snapshot unless other
  permissions already deny them.
- `:tmpdir` uses absolute `TEMP` and `TMP` values from the filtered workload
  environment, matched case-insensitively. `:slash_tmp` contributes no path on
  Windows. Unresolved project-root or temporary symbols at the later translation
  boundary are errors.
- When platform defaults are requested, the adapter adds Windows, Program Files,
  Program Files (x86), and ProgramData read roots.

[Filesystem implementation][local-policy], [Windows root discovery][local-windows].

Policy cwd and execution cwd are separate: the former controls permission
resolution, while the latter becomes MXC's working directory. Both must be
absolute. Explicit non-Unicode policy paths, working directories, and environment
values fail rather than being converted lossily. Generated volume children that
cannot be represented or inspected may be skipped. [Validation][local-policy],
[environment collection][local-windows].

**Implication:** permitted writes affect host files. The adapter supplies no
copy-on-write workspace or rollback layer. Path normalization is useful evidence
of intent, but junction, hardlink, alternate-path, and race enforcement still
requires native testing; comments attributing access-time enforcement to PSEC
are not a substitute for that evidence.

### Networking

The adapter emits explicit network policy even when networking is blocked.

| Effective request | Direct egress | General ingress | Host loopback |
| --- | --- | --- | --- |
| Restricted, without managed proxy | Default deny | Default deny | Deny |
| Enabled, without managed proxy | Default allow | Default allow | Allow |
| Managed proxy context | Default deny; allow `127.0.0.0/8` and `::1/128`, without a port restriction | Default deny | Allow bidirectionally |

The managed context must contain nonempty, nonzero proxy ports and
`allow_local_binding = true`. Validation occurs at both wrapper preparation and
policy construction. **The supplied port list is validated but is not used as a
native destination-port allowlist.** The generated loopback rule has an empty
`ports` list. [Network translation][local-policy], [boundary validation][local-lib],
[exact policy assertions][local-tests].

At the pinned SDK revision, host-loopback permission also maps to the
`networkLoopback` capability and special `MXC-Loopback` peer. The adapter does not
integrate the SDK's dedicated proxy-peer identity mode. Consequently it cannot
offer proxy-client-only access while forbidding local listeners. An effective
`allow_local_binding = false` is rejected instead of silently relaxed.
[Pinned native mapping][mxc-builder], [compatibility notes][local-readme].

Proxy domain rules still apply to traffic sent through the managed proxy. Official
guidance says local binding removes the proxy's additional private-network
destination checks. The emitted policy intends to deny direct non-loopback egress,
including direct DNS; no packet capture or controlled DNS test was performed here.
[Official networking limits][official-windows].

**Implication:** any host-loopback service reachable under this policy is part of
the exposure analysis, including a service capable of forwarding requests. This
follows from the broad loopback grant; it is not evidence of a demonstrated bypass.
The policy should not be described as permitting only the managed proxy sockets.

### UI, registry, and process lifetime

The adapter requests `registryRead`. It enables Win32k calls (`ui.disable = false`)
and sets `base_process_ui.isolation = "desktop"` because PowerShell startup needs
Win32k and desktop handles. In the pinned UI resolver, `"desktop"` leaves external
UI-object handles and the global UI namespace unblocked by those isolation flags.
It does not itself create a private desktop. Defaults still request clipboard,
input-injection, IME, desktop-switching, shutdown/logoff, and system-setting
restrictions. [Adapter settings][local-policy], [SDK defaults][mxc-models],
[UI restriction resolution][mxc-ui].

The helper inherits pipes or the existing ConPTY console through
`StdioMode::Inherit`. MXC creates the child suspended, assigns it to a job configured
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and then resumes it. Job setup failure
rejects launch. The returned child object retains the security-environment owner.
Its `wait()` terminates/reaps remaining descendants before teardown; `Drop` also
attempts process-tree termination. [Adapter launch][local-native],
[runner lifetime][mxc-runner], [job implementation][mxc-job].

**Implication:** a background server cannot simply outlive a short launching shell.
Keeping it alive would require a longer-lived owner of both policy and job. The
current teardown order deliberately keeps enforcement alive until tree termination.

## Request and environment transport

`create_command_args()` packages the permission profile, policy cwd, optional
managed-network context, exact argv, and an original-empty-environment marker into
typed JSON. The helper receives only `--__codex-windows-mxc` on its command line;
the JSON travels through `CODEX_SANDBOX_LAUNCH_*` environment variables. The shared
transport validates counts and lengths and removes its variables before the
workload environment is built. Workload argv is then quoted for
`WindowsCreateProcess`; the adapter does not add a shell interpretation step.
[Wrapper][local-lib], [adapter transport][local-transport], [shared transport][codex-transport].

**README discrepancy:** the supplied README states a 1,000,000-byte payload and
4096-byte chunks. The shared implementation at the matching Codex revision uses
`MAX_BYTES = 16 * 1024 * 1024` and `CHUNK_BYTES = 16 * 1024`: **16 MiB total and
16 KiB per chunk**, splitting only at UTF-8 boundaries. The local adapter delegates
to that shared implementation and defines no smaller limits of its own. These
are transport validation bounds, not a guarantee that Windows accepts every
environment of that size. The workload still has Windows' command-line limit.
[README claim][local-readme], [actual constants][codex-transport].

The wrapper replaces caller overrides of `SystemDrive` and `LOCALAPPDATA`,
case-insensitively, with nonempty Unicode host values. For an originally empty
workload environment it also supplies host `SystemRoot` for bootstrap, then clears
the helper environment after decoding so MXC chooses its user-profile defaults.
Nonempty workload environments remain explicit apart from the host-owned values.
Windows may virtualize the child's `LOCALAPPDATA` beneath the host profile.
[Environment handling][local-transport], [documented runtime behavior][local-readme].

The native SDK logs into a buffer that the adapter does not publish because it
may contain command/environment data. Decode failures are reduced to a generic
invalid-request diagnostic to avoid exposing serialized values through Serde
errors. This narrows these error paths; it is not a claim that all diagnostics are
free of sensitive information. [Native error handling][local-native],
[decode error handling][local-windows].

## Verification status and next checks

This investigation inspected all supplied implementation and test files, matched
their contents to the fixed Codex revision, and traced the native calls through
that revision's MXC pin. It found 21 policy test definitions and one transport test
definition. Their assertions cover policy precedence, protected metadata,
volume/alias expansion, deny globs, environment handling, exact argv, separate
working directories, managed-network shape, and invalid inputs. These tests were
**read, not run**. Some coverage is platform-conditional. [Policy tests][local-tests],
[transport test][local-transport-tests].

The copied crate lacks its parent workspace and required workspace dependencies;
`cargo` and `rustc` were not available on this session's PATH. No native PSEC
workload, isolation probe, GUI test, or packet-level network test was executed.
The initial normal shell calls failed during sandbox setup, but that error alone
does not establish the active backend or diagnose MXC.

For installed-host validation, official guidance provides this startup check for
Codex CLI 0.162.0 and later:

```powershell
codex -c windows.sandbox=mxc sandbox --include-managed-config --permission-profile :workspace -- cmd.exe /d /c echo MXC_OK
$LASTEXITCODE
```

`MXC_OK` and exit code `0` establish startup under that configuration, not complete
confinement. [Official startup check][official-windows]. Follow it with focused
tests of:

- Allowed and forbidden reads/writes, including existing files, protected
  metadata, nested overrides, junctions, hardlinks, and alternate path spellings.
- Files added after deny-glob expansion and top-level directories added after
  volume-root expansion.
- `powershell.exe`, normal `pwsh.exe`, inherited pipes, and interactive ConPTY.
- Foreground exit and cancellation with live descendants, including detached servers.
- Controlled IPv4/IPv6 receivers for direct egress, DNS, proxy rules, host-loopback
  clients/listeners, and LAN ingress.
- UI interaction with controlled canary windows, clipboard, and input targets.

No vulnerability or complete security assurance is established by this review.
The strongest supported conclusion is that this adapter deliberately chooses
PSEC policy enforcement without host ACL provisioning, with explicit compatibility
tradeoffs around host loopback, PowerShell UI access, and descendant lifetime.

[local-readme]: ../mxc-sandbox/README.md
[local-lib]: ../mxc-sandbox/src/lib.rs
[local-native]: ../mxc-sandbox/src/native.rs
[local-windows]: ../mxc-sandbox/src/windows.rs
[local-policy]: ../mxc-sandbox/src/policy.rs
[local-transport]: ../mxc-sandbox/src/transport.rs
[local-tests]: ../mxc-sandbox/src/policy_tests.rs
[local-transport-tests]: ../mxc-sandbox/src/transport_tests.rs
[codex-manifest]: https://github.com/openai/codex/blob/ce0323f2f2d3b25e82806cd555237da3db4e1897/codex-rs/Cargo.toml
[codex-manager]: https://github.com/openai/codex/blob/ce0323f2f2d3b25e82806cd555237da3db4e1897/codex-rs/sandboxing/src/manager.rs#L388-L434
[codex-arg0]: https://github.com/openai/codex/blob/ce0323f2f2d3b25e82806cd555237da3db4e1897/codex-rs/arg0/src/lib.rs#L79-L82
[codex-config]: https://github.com/openai/codex/blob/ce0323f2f2d3b25e82806cd555237da3db4e1897/codex-rs/core/src/config/mod.rs#L3635-L3647
[codex-selection]: https://github.com/openai/codex/blob/ce0323f2f2d3b25e82806cd555237da3db4e1897/codex-rs/core/src/config/windows_sandbox_config.rs
[codex-transport]: https://github.com/openai/codex/blob/ce0323f2f2d3b25e82806cd555237da3db4e1897/codex-rs/windows-sandbox-rs/src/environment_transport.rs
[mxc-builder]: https://github.com/microsoft/mxc/blob/6cd3d58f05d3447e67109cfb75e042803b843ca4/src/backends/appcontainer/common/src/base_container_helpers.rs
[mxc-secenv]: https://github.com/microsoft/mxc/blob/6cd3d58f05d3447e67109cfb75e042803b843ca4/src/backends/learning_mode/windows/src/secenv.rs
[mxc-runner]: https://github.com/microsoft/mxc/blob/6cd3d58f05d3447e67109cfb75e042803b843ca4/src/backends/appcontainer/common/src/base_container_runner.rs
[mxc-job]: https://github.com/microsoft/mxc/blob/6cd3d58f05d3447e67109cfb75e042803b843ca4/src/backends/appcontainer/common/src/job_object.rs
[mxc-models]: https://github.com/microsoft/mxc/blob/6cd3d58f05d3447e67109cfb75e042803b843ca4/src/core/wxc_common/src/models.rs#L623-L671
[mxc-ui]: https://github.com/microsoft/mxc/blob/6cd3d58f05d3447e67109cfb75e042803b843ca4/src/core/wxc_common/src/ui_policy.rs
[official-windows]: https://learn.chatgpt.com/docs/windows/windows-sandbox
