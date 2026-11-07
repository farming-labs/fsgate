# Changelog

## Unreleased

### Added

- Experimental, Linux only, behind the `experimental-intercept` feature and outside semver: `Gate::open_regular_strict`, the read-only open of the RFC 0004 interception profile. It needs `READ` like `open`, but refuses every symlink with `ELOOP` (even inside the grant), directories with `EISDIR`, and FIFOs, devices, sockets, and procfs or sysfs files with `EOPNOTSUPP` without opening them for I/O. It reopens the `O_PATH` handle it checked, so a rename in between cannot substitute another file. The feature adds a direct dependency on `rustix-linux-procfs`, already in the dependency graph through `cap-std`.

## 0.1.1 (2026-11-07)

The first crates.io release: [`fsgate` 0.1.1](https://crates.io/crates/fsgate/0.1.1), built from the signed tag [`v0.1.1`](https://github.com/farming-labs/fsgate/tree/v0.1.1) on `4250f31`. It adds one security fix over 0.1.0; the public API is unchanged.

### Fixed

- Descriptors the worker receives through `BrokerGate` (`open` and `create`) are close-on-exec, like the files std opens. In 0.1.0 they were inherited by every program the worker started, so a spawned child could read or write a brokered file without asking the broker. On Linux the flag is set atomically by `recvmsg`; on macOS it is set immediately after, and a concurrent fork and exec on another thread can still inherit the descriptor in that window.

### Changed

- The manifest allows publishing to crates.io (`publish = false` is removed) and adds crates.io keywords and categories.
- [The release procedure](docs/RELEASING.md) is version-generic and adds the crates.io publish and verification steps.

## 0.1.0 (2026-11-06)

The initial release: the signed tag [`v0.1.0`](https://github.com/farming-labs/fsgate/tree/v0.1.0) on `0ad477f`. Not published to crates.io; the crate remains `publish = false`.

### Added

- `Gate` grants directory handles with `READ`, `WRITE`, `CREATE`, and `LIST` rights, then authorizes `open`, `create`, `metadata`, and `read_dir` beneath those handles. Paths without a grant fail closed.
- `lock()` applies strict Linux Landlock containment. `lock_with(LockPolicy::BestEffort)` explicitly permits weaker containment and reports the achieved `LockStatus`.
- `revoke(grant)` removes a grant from subsequent gate operations, including after a lock. Already opened files and installed kernel rules are not revoked.
- `Gate::narrow(grant, rights)` removes rights from a live grant before or after `lock()` and keeps the grant's id and held directory handle. A grant narrowed before `lock()` is enforced by the kernel at its narrowed rights; after `lock()`, narrowing binds gate operations only. Asking to keep a right the grant does not hold fails with `GateError::WouldWiden` and leaves the grant unchanged. Each call emits one `narrow` audit event ([RFC 0005](docs/rfcs/0005-grant-narrowing.md)).
- `Broker` serves a gate over a Unix socket with `SCM_RIGHTS` descriptor passing. `BrokerGate` is the worker client; `fsgate-broker` starts a command with `FSGATE_BROKER_SOCKET`. A lost broker connection makes subsequent client requests fail closed.
- `Gate::set_audit_sink` delivers one structured event per authority decision, including broker requests and denials the caller discards. Kernel refusals after policy allows are recorded as allow plus errno. `grant` and `narrow` events record the rights the grant holds after the decision (`AuditEvent::rights`, the JSON `rights` key).
- `AuditOp`, `AuditReason`, `AuditEvent`, and `GateError` are `#[non_exhaustive]`, so later releases can add operations, reasons, fields, and failure kinds without breaking callers. Matches outside fsgate need a wildcard arm, and only a `Gate` creates events. `AuditDecision` stays exhaustive.
- Public documentation is required, and the README example is compiled as a doctest in both the checkout and the packaged crate.
- The crate archive includes the README and MIT license; CI checks the license and tests the unpacked package.

### Fixed

- `revoke` and `narrow` reject a `Grant` created by a different gate with `GateError::UnknownGrant`, as documented, and change no grant. Before, a grant carried only its index, so another gate revoked or narrowed whichever of its own grants held that index. The audit event for a rejected foreign grant has `grant: null`.
- Rights denials report the grant selected by routing, including when multiple grants name the same directory, and record the normalized requested path ([PR #1](https://github.com/farming-labs/fsgate/pull/1)).

### Limits

Windows, per-file grants, and non-UTF-8 broker paths are unsupported. Landlock applies to the calling thread and its future descendants. The broker does not remove a worker's ambient filesystem authority; the embedder must supply that isolation. The implementation has not been independently reviewed.
