# Changelog

## Unreleased

### Added

- `Gate::narrow(grant, rights)` removes rights from a live grant before or after `lock()` and keeps the grant's id and held directory handle. A grant narrowed before `lock()` is enforced by the kernel at its narrowed rights; after `lock()`, narrowing binds gate operations only. Asking to keep a right the grant does not hold fails with `GateError::WouldWiden` and leaves the grant unchanged. Each call emits one `narrow` audit event ([RFC 0005](docs/rfcs/0005-grant-narrowing.md)).

### Changed

- Breaking: `GateError::WouldWiden` is a new variant, so exhaustive matches on `GateError` need a new arm. `AuditOp::Narrow` is additive because `AuditOp` is non-exhaustive.

## 0.1.0 (unreleased)

Prepared for the initial signed-tag release. Not yet tagged or published to crates.io.

### Added

- `Gate` grants directory handles with `READ`, `WRITE`, `CREATE`, and `LIST` rights, then authorizes `open`, `create`, `metadata`, and `read_dir` beneath those handles. Paths without a grant fail closed.
- `lock()` applies strict Linux Landlock containment. `lock_with(LockPolicy::BestEffort)` explicitly permits weaker containment and reports the achieved `LockStatus`.
- `revoke(grant)` removes a grant from subsequent gate operations, including after a lock. Already opened files and installed kernel rules are not revoked.
- `Broker` serves a gate over a Unix socket with `SCM_RIGHTS` descriptor passing. `BrokerGate` is the worker client; `fsgate-broker` starts a command with `FSGATE_BROKER_SOCKET`. A lost broker connection makes subsequent client requests fail closed.
- `Gate::set_audit_sink` delivers one structured event per authority decision, including broker requests and denials the caller discards. Kernel refusals after policy allows are recorded as allow plus errno.
- `AuditOp`, `AuditReason`, and `AuditEvent` are `#[non_exhaustive]`, so later releases can add operations, reasons, and fields without breaking callers. Matches outside fsgate need a wildcard arm, and only a `Gate` creates events. `AuditDecision` stays exhaustive.
- Public documentation is required, and the README example is compiled as a doctest in both the checkout and the packaged crate.
- The crate archive includes the README and MIT license; CI checks the license and tests the unpacked package.

### Fixed

- Rights denials report the grant selected by routing, including when multiple grants name the same directory, and record the normalized requested path ([PR #1](https://github.com/farming-labs/fsgate/pull/1)).

### Limits

Windows, per-file grants, and non-UTF-8 broker paths are unsupported. Landlock applies to the calling thread and its future descendants. The broker does not remove a worker's ambient filesystem authority; the embedder must supply that isolation. The implementation has not been independently reviewed.
