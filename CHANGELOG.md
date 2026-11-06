# Changelog

## Unreleased

Preparation for v0.1.0. Not yet tagged or published to crates.io.

### Added

- `Gate` grants directory handles with `READ`, `WRITE`, `CREATE`, and `LIST` rights, then authorizes `open`, `create`, `metadata`, and `read_dir` beneath those handles. Paths without a grant fail closed.
- `lock()` applies strict Linux Landlock containment. `lock_with(LockPolicy::BestEffort)` explicitly permits weaker containment and reports the achieved `LockStatus`.
- `revoke(grant)` removes a grant from subsequent gate operations, including after a lock. Already opened files and installed kernel rules are not revoked.
- `Broker` serves a gate over a Unix socket with `SCM_RIGHTS` descriptor passing. `BrokerGate` is the worker client; `fsgate-broker` starts a command with `FSGATE_BROKER_SOCKET`. A lost broker connection makes subsequent client requests fail closed.
- `Gate::set_audit_sink` delivers one structured event per authority decision, including broker requests and denials the caller discards. Kernel refusals after policy allows are recorded as allow plus errno.
- Public documentation is required, and the README example is compiled as a doctest in both the checkout and the packaged crate.

### Fixed

- Rights denials report the grant selected by routing, including when multiple grants name the same directory, and record the normalized requested path.

### Limits

Windows, per-file grants, and non-UTF-8 broker paths are unsupported. Landlock applies to the calling thread and its future descendants. The broker does not remove a worker's ambient filesystem authority; the embedder must supply that isolation. The implementation has not been independently reviewed.
