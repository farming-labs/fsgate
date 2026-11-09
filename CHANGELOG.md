# Changelog

## Unreleased

### Added

- Experimental, Linux only, behind the `experimental-intercept` feature and outside semver: `Gate::open_regular_strict`, the read-only open of the RFC 0004 interception profile. It needs `READ` like `open`, but refuses every symlink with `ELOOP` (even inside the grant), directories with `EISDIR`, and FIFOs, devices, sockets, and procfs or sysfs files with `EOPNOTSUPP` without opening them for I/O. It reopens the `O_PATH` handle it checked, so a rename in between cannot substitute another file. The feature adds a direct dependency on `rustix-linux-procfs`, already in the dependency graph through `cap-std`.
- Experimental, same feature: `fsgate::intercept::OpenRequest` and `Gate::open_intercepted`, the audited dispatcher for intercepted open requests. It validates the copied arguments against the RFC 0004 file-open contract, authorizes with `open_regular_strict`, and emits exactly one audit event per request, including requests refused before any grant is matched.
- Experimental, same feature, Linux x86_64 only: `fsgate::intercept::Launch` and `Outcome`, a launcher for static worker binaries under the RFC 0004 profile. It checks the image (native x86_64 ELF, no interpreter, not set-ID, no file capabilities), starts the worker with only stdio and an empty environment under `no_new_privs`, a Landlock ruleset that allows executing only its own image, a seccomp filter that sends `open`, `openat`, and `openat2` to a supervisor thread, and the RFC's final syscall allowlist, then answers each request with `Gate::open_intercepted`. Not independently reviewed. The `unsafe` it needs lives in one private module with a written safety contract, and the feature adds an optional direct dependency on `libc`.
- Experimental, same feature: `Launch::spawn` and `intercept::Running`, a handle to a running worker. `revoke` and `narrow` change the gate while the worker runs; each waits for any request already being decided, and applies to every later request. Descriptors already delivered stay usable. Also `take_stdin` (standard input is now a dedicated pipe, closed by `wait` and by `run`), `kill`, `id`, and `wait`. Dropping a `Running` kills and reaps the worker. A request interrupted by a signal is answered with nothing: the supervisor drops its copy of the file and the worker gets `EINTR`.
- Experimental, same feature: `fsgate-broker --experimental-intercept`. Without `--apply` it prints the plan (the worker check, the grants, the profile) and starts nothing; with `--apply` it runs the worker under `intercept::Launch`, relays its output, and exits with its code. `--audit` writes each decision to standard error as an RFC 0002 JSON line. A refused worker image exits 3. In builds without the feature, or off Linux x86_64, the flag is a usage error. The socket mode is unchanged.
- `AuditReason::UnsupportedInput` and `AuditReason::InvalidMemory`, and the `AuditEvent` fields `syscall` and `notification`, set only for intercepted requests. Every JSON line now carries `syscall` and `notification` keys, `null` outside interception; both are additive within format v1 ([RFC 0002](docs/rfcs/0002-audit-events.md)).
- `Restrictions`, `LockOptions`, and `Gate::restrictions` ([RFC 0006](docs/rfcs/0006-lock-restrictions.md)). `lock()` applies kernel restrictions beyond the filesystem rules where the kernel supports them: `IOCTL_DEV` (Linux 6.10: ioctls on devices opened after the lock only beneath a `WRITE` grant), `ABSTRACT_UNIX_SOCKET` and `SIGNAL` (6.12: no connects to abstract sockets or signals to processes outside the sandbox), `ALL_THREADS` (7.0: every thread of the process, not just the caller), and `RESOLVE_UNIX` (7.1: no connects or sends to pathname Unix sockets created outside the sandbox, even beneath a grant). `Gate::restrictions` reports which took effect. `LockOptions::restrict` drops members and `LockOptions::require` makes them mandatory, even under `LockPolicy::BestEffort`. A missing requirement fails with `LockUnsupported` naming the kernel that provides it, before anything is applied.
- The `lock` audit event's `restrictions` key lists what took effect, in a fixed order; it is `null` for a refused lock and every other operation. Every JSON line now carries the key, additive within format v1 ([RFC 0002](docs/rfcs/0002-audit-events.md)).

### Changed

- On Linux 6.10 and later, a bare `lock()` restricts more, as listed above. Code that does any of the following after locking now fails on those kernels: issues ioctls on a device outside a `WRITE` grant, connects to an abstract socket created outside the process, signals its parent or a process started before the lock, or relies on a sibling thread staying unrestricted. On Linux 7.1 and later the same goes for connecting to a pathname Unix socket created outside the process, so a `BrokerGate` worker connects before it locks. To keep the old behavior for one of these, leave that member out with `LockOptions::restrict`. A test that locks inside the test binary needs to leave out `Restrictions::ALL_THREADS`, or the lock reaches every test thread.
- `Gate::lock_with` takes `impl Into<LockOptions>`. Calls that pass a `LockPolicy` compile unchanged; code that names `Gate::lock_with` as a function taking `LockPolicy` does not.
- `LockStatus` now describes only the filesystem rules, derived from the effective Landlock ABI. A kernel that lacks only the newer restrictions no longer turns a strict lock into an error.

### Fixed

- A `BrokerGate` that loses a response now fails every later request closed. It used to take the next response to arrive as the answer to the next request, so after a read timeout set through `from_stream` or an interrupted system call, a later `open` could return the file for an earlier request. Interrupted system calls on the broker socket are now retried, so a signal does not cost the connection.
- The broker fails a connection closed when a request carries a file descriptor. It used to hold every descriptor until the frame was complete and then serve the request, so a worker could fill the broker's descriptor table by splitting one request across many messages. RFC 0003 requests carry none, and `BrokerGate` never attaches any, so a correct client is unaffected.
- On macOS, descriptors a worker attached to a request could stay open in the broker for good. The broker received at most 8 descriptors per read, and macOS installs the ones that do not fit without reporting them, so the broker never closed them, and they were not close-on-exec. A worker could fill the broker's descriptor table, and programs the broker process started afterward inherited them. Each read now has room for as many descriptors as one message can carry, and a message the kernel reports truncated fails the connection closed. Linux closes descriptors that do not fit, so it was not affected.
- The broker acts only on a frame exactly as long as its prefix declares. It used to treat every byte after the 4-byte prefix as the request, so a request whose prefix understated its length was still served. The broker still authorized it, so this let a worker do nothing it could not do with a correct frame, but anything that framed by the prefix saw a different request from the one served. Bytes beyond the declared length now fail the connection closed, as RFC 0003 requires.
- A strict lock on a kernel without Landlock ABI v3 fails before applying anything. It used to apply a partial ruleset, then report `LockUnsupported` with the gate still unlocked, so a retry stacked a second ruleset.

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
