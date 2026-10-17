# launch-as Windows Sandbox workflows

Project contract for the reusable Windows Sandbox test skill. Run commands from the
repository root. The host orchestrators remain the source of truth for artifact lists,
framework pins, provisioning, and assertions.

## Select and build

| Evidence | Command | Host run root |
| --- | --- | --- |
| Privileged broker integration | `.\build.ps1 -RunSandboxTests` | `out\windows-sandbox-integration` |
| Installed-service console and GUI acceptance | `.\build.ps1 -RunAcceptanceTest` | `out\windows-sandbox-acceptance` |
| Host tests, integration, then an acceptance prompt | `.\build.ps1 -RunAllTests` | The two roots above |
| Interactive-session feasibility and ACL lease probes | Build, then invoke the session runner below | `out\windows-sandbox-interactive-session-probe` |

`-RunAllTests` offers acceptance after the automated sets; declining leaves acceptance
unverified. Use `.\build.ps1 -RunAllTests -RunAcceptanceTest` to include it without the
prompt. The session probe is separate and is not included in `-RunAllTests`:

```powershell
.\build.ps1
.\tests\Invoke-InteractiveSessionProbeInWindowsSandbox.ps1 `
    -BuildDirectory .\out\build -Configuration Release
```

For current, already-built artifacts, invoke one of these host runners directly:

- [Integration](Invoke-BrokerIntegrationInWindowsSandbox.ps1)
- [Acceptance](Invoke-LauncherAcceptanceInWindowsSandbox.ps1)
- [Session probe](Invoke-InteractiveSessionProbeInWindowsSandbox.ps1)

Each takes `-BuildDirectory .\out\build -Configuration Release`; use `Debug` only with
matching Debug artifacts. Read that runner's artifact list when a binary is missing.
For prerequisites and formatting behavior, see [Build and test](../README.md#build-and-test).

## Guest context

Integration runs guest-local copies of the test executables as SYSTEM, so host integrity
labels on shared images cannot lower their process integrity. Results remain in the share.
Acceptance and the session probe connect a visible
guest desktop and bootstrap under `ExistingLogin`; they require no manual guest
commands or UAC interaction. Both runners retry login error `0x80070520` for a bounded
window; if that expires, inspect guest desktop/login readiness.

Acceptance provisions `LaunchAsDevCaller` and managed target `LaunchAsDevTestUser`
inside the guest, as described in [Build and test](../README.md#build-and-test). No
host-installed broker or host test account is required. Guest drivers and leaf
acceptance scripts are not host entry points.

## Current-run evidence

The runners print `Windows Sandbox artifacts retained at ...` on success. Use that
GUID directory; after failure, identify the directory created during the attempt under
the selected run root.

| Workflow | Required evidence in the GUID directory |
| --- | --- |
| Integration | `session-privilege-result.txt`, `audit-result.txt`, `account-provisioning-result.txt`, and `service-installer-result.txt`: each command exits zero and each file contains its runner-defined success marker |
| Acceptance | `interactive-acceptance-result.txt` contains a standalone `PASS` and the driver exits zero; `service-privilege-result.txt` contains `Installed broker process TCB is disabled` and its command exits zero |
| Session probe | `interactive-session-probe-result.txt` contains a standalone `PASS` and the driver exits zero; inspect `interactive-session-probe-command.log` for diagnostics |

Integration result files contain guest stdout/stderr. Acceptance also retains
`fixture.log`, `demand-start.log`, and `interactive-acceptance.log`, copied after each
phase and again in `finally`.

Phase updates append to the acceptance transcript. The standard caller writes its
result once, after completion and transcript cleanup. The supervisor waits for the
process to exit before reading or copying its result and logs; it does not poll a
live result file. A timeout terminates the process and waits for exit before collection.

## Coverage and maintenance

AppContainer console checks exercise zero capabilities, a capability name and its equivalent SID,
Low process integrity, writes to Medium-labelled workspace files without relabelling,
profile writes, outside/junction and previous-workspace denial, shared hard-link ACL behavior,
broker grants on Modify-only workspace roots, automatic propagation to account-owned existing
workspace and profile contents, and unchanged protected-child and foreign-owned hard-link ACLs,
new-file inheritance and repeated propagation to account-owned moved-in files,
preservation of explicit inheritable Medium labels (new-file creation remains denied),
parent-process memory/handle access denial, DNS-service API denial, descendant confinement,
`cmd.exe`, invalid SIDs and protected workspaces. The native probe runs from its prepared workspace. It does
not test a particular AI agent or the host's WFP rules. DNS/proxy feasibility was probed separately.

Acceptance covers the scripted console and normal-completion GUI cases; the remaining
interactive cases are listed in [Build and test](../README.md#build-and-test). The
feasibility probe does not replace installed-service acceptance.
The interactive target also checks named mutex creation, global event creation/opening, and
denied access to a controlled caller-owned event. ACL probes verify the exact non-inheritable
named-object directory grant, its removal, and preservation of overlapping leases.
The synthetic caller receives temporary coordinator access to the session's named-object
directory through `LauncherAcceptanceLogon.cs`; this fixture setup stays inside the guest.

Write-scope acceptance exercises the independent `--low-integrity` flag with and without
Low integrity in console and interactive modes: profile/working-tree writes, Medium
outside-file denial for Low launches (including hard-link and junction aliases), outside
writes for Medium launches, normal reads, cryptographic initialization, `whoami`, PowerShell,
and descendant inheritance.

Access restriction (`--restrict-access`) is tested with and without `--low-integrity` in
console and interactive modes. Read-scope acceptance covers descendant
inheritance, protected-child and junction denial, profile/worktree writes, two concurrent
interactive sessions with different working directories, mixed-mode rejection, restoration
after the last close, and failed-launch restoration. It runs only in the disposable guest.
Read-restricted identity checks query the native token and run `whoami`. The token retains
only an existing disabled working-set privilege for runtime compatibility.
Logged console and GUI launches also verify the caller's UTF-8 text log, folder decisions,
request IDs, teardown entries, and duplicate prevention. Unlogged launches leave that file
unchanged. The runner retains the tested file as `launch-as.log` in its GUID directory.
Overlapping logged sessions close in reverse order, followed by a failed logged launch;
the final active logger must still collect restoration under its own request ID.
The host read-scope test also verifies that directory pins block DELETE handles even on
an allowed root and release them after restoration.

For changed runner behavior, add a focused regression and inspect the parameters/CMake
registrations of the relevant contracts:

- [Integration contract](Test-SandboxIntegrationContract.ps1)
- [Acceptance contract](Test-SandboxAcceptanceContract.ps1)
- [Session probe contract](Test-InteractiveSessionProbeContract.ps1)
- [Test isolation contract](Test-TestIsolationContract.ps1)
- [Build entry-point contract](Test-BuildAllTestsContract.ps1)

Run `.\build.ps1 -RunTests` for host verification, then the affected real guest workflow.
