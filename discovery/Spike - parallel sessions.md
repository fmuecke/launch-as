# Spike: parallel sessions

> **Superseded.** The implemented broker rotates the account password for every launch; this
> document's enrollment-time password model is retained only as historical design context.

## Decision

Parallel sessions are keyed by the selected target account/profile:

- **Same target user:** sessions intentionally share `%USERPROFILE%`, HKCU, account-SID access,
  caches, and any selected working directory.
- **Different target users:** accounts, profiles, HKCU, and account-SID access remain separate.

Authorising a caller for one profile must not authorise it for every enrolled profile.

## Password model

Superseded by the implemented per-launch password rotation. Do not use an enrollment-time stored
password model.

Create a fresh logon token for every session rather than asking a running host to clone itself. This avoids the
password-reset race and gives each session a distinct logon SID. A duplicated token is possible, but would share
the logon SID and offers no benefit here.

## Session shape

Each accepted session has its own:

- authenticated control-pipe connection;
- client-owned ConPTY input, output, and resize pipes;
- host process and terminal state;
- kill-on-close Job object and process tree.

Do not make an existing host spawn a sibling session. Its child would inherit the existing Job and be tied to the
first client's lifetime, rather than owning an independent terminal and dead-man switch.

The broker needs a per-profile session registry: active sessions, a configured concurrency limit, audit data, and
a draining state. Unenroll, password reset, and service shutdown must stop new launches and then drain or end only
the affected profile's sessions.

## Consequences and validation

Pipes are not the fundamental limitation; the existing terminal bridge already creates distinct endpoints per
launch. The current single control-pipe/session implementation must become a multi-session dispatcher.

Shared-profile concurrency is deliberate, not isolation. Concurrent tools can contend for profile files, caches,
or a shared working tree; test the intended workloads, including concurrent profile loading and teardown.
