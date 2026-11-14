# Changelog

## Unreleased

### Fixed

- When the broker got `SIGQUIT`, from `Ctrl-\` for example, it died without killing its confined worker's process group, so programs the worker started kept running, confined, after both had exited. The broker now handles `SIGQUIT` like `SIGINT`, `SIGTERM`, and `SIGHUP`: it kills the group, then dies by the signal ([RFC 0010](docs/rfcs/0010-worker-process-group.md#changes-after-release)).
- The `lock` audit event now records what the kernel enforced for the filesystem rules, in a new `status` key (`fully_enforced`, `partially_enforced`, or `library_only`) and the `AuditEvent::status` field. Before, a best-effort lock that the kernel did not enforce was logged `allow` and `ok` with the same fields as an enforced one ([RFC 0002](docs/rfcs/0002-audit-events.md)).

### Changed

- A confined worker may read OpenSSL's configuration, `/etc/ssl/openssl.cnf` and Fedora's `/etc/pki/tls/openssl3.cnf`, where they exist ([RFC 0008](docs/rfcs/0008-confine-broker-worker.md#programs-that-read-files-in-etc)). Without it, Node.js did not start as a confined worker on Ubuntu, Debian, Fedora, Arch, or Alpine: it exited 13 with `OpenSSL configuration error` unless given `--direct` for the file. Like `/etc/ld.so.cache`, these are single files that hold no data, so a grant that contains one is not refused, and reading them is not audited.

## 0.4.1 (2026-11-13)

[`fsgate` 0.4.1](https://crates.io/crates/fsgate/0.4.1), built from the signed tag [`v0.4.1`](https://github.com/farming-labs/fsgate/tree/v0.4.1) on `b5cb02d`. Not independently reviewed. Upgrade from 0.4.0 for the fix below: before Linux 7.1, a confined worker could still send datagrams to Unix sockets outside its confinement. Nothing else changes, so this is a patch release. Everything behind the `experimental-intercept` feature is not part of this release: it builds only from the repository, and the published crate refuses the feature with a compile error.

### Fixed

- Below Linux 7.1, a confined worker could still send datagrams, and descriptors with them, to any Unix datagram socket it could name by path, or by abstract name before Linux 6.12, which [RFC 0009](docs/rfcs/0009-worker-unix-sockets.md) says it cannot. Its seccomp filter refused a Unix socket pair only for `SOCK_DGRAM`, and the kernel makes a Unix `SOCK_RAW` socket a datagram one. The filter now refuses every Unix socket pair but a stream or seqpacket one. Stream sockets, and so D-Bus, were never reachable this way.

## 0.4.0 (2026-11-12)

[`fsgate` 0.4.0](https://crates.io/crates/fsgate/0.4.0), built from the signed tag [`v0.4.0`](https://github.com/farming-labs/fsgate/tree/v0.4.0) on `101a598`. Not independently reviewed. Upgrade from 0.3.0 or earlier for the fixes listed under Fixed, among them a relative `--direct` path that let a confined worker read the whole filesystem, and a `--socket` path another user could replace. A confined worker no longer reaches Unix sockets before Linux 7.1 or leaves programs running after it exits, as listed under Changed; a worker that needs either must run with `--unconfined`. Those changes to `fsgate-broker`'s defaults are why this is a minor release. Everything behind the `experimental-intercept` feature is not part of this release: it builds only from the repository, and the published crate refuses the feature with a compile error.

### Added

- A `Broker` audits what it refuses before its gate sees a request ([RFC 0011](docs/rfcs/0011-audit-broker-refusals.md)), through the sink already installed on the gate. Each connection `serve_with` accepts is one `connect` event: `allow`, or `deny` with `peer_refused`, `connection_limit`, or `no_thread`. A request that breaks the protocol is one `request` event, with `frame_too_large`, `malformed_frame`, or `malformed_request`. Events gain a `peer_uid` key, the peer's uid on those events and `null` on every other. `AuditOp`, `AuditReason`, and `AuditEvent` gain the matching variants and field, which their `#[non_exhaustive]` allows in a minor release. A refused peer used to leave no event, as RFC 0007 had decided.

### Changed

- A confined worker may read, list, and execute beneath `/nix/store`, where Nix and NixOS keep every program, loader, and library ([RFC 0008](docs/rfcs/0008-confine-broker-worker.md#answer)). Under the default rules it could not start there, and failed with `EACCES` unless given `--direct /nix/store:rlx`. A grant that overlaps `/nix/store` is now refused, as one that overlaps `/usr` is. Where `/nix/store` does not exist, nothing changes.
- Before Linux 7.1, `fsgate-broker` installs a seccomp filter in a confined worker that refuses new Unix sockets, from `socket(AF_UNIX)` or a datagram `socketpair`, with `EACCES`, refuses `io_uring` with `ENOSYS`, and kills a process that makes an x32 call or one from another architecture ([RFC 0009](docs/rfcs/0009-worker-unix-sockets.md)). Landlock refuses Unix socket connects only from Linux 7.1, so before that a confined worker could connect to any socket it could name, such as the session bus, and ask systemd's user manager to start a program outside the confinement. The worker keeps its broker connection, sockets on its standard streams, stream and seqpacket pairs, and the network. A worker that needs a Unix socket service before 7.1, such as D-Bus, X11, or Wayland, must run with `--unconfined`. Before 7.1, a confined worker on an architecture other than x86_64 and aarch64 no longer starts. From 7.1 nothing changes.
- `fsgate-broker` kills a confined worker's process group when the worker exits, and when the broker gets `SIGINT`, `SIGTERM`, or `SIGHUP`, after which the broker dies by that signal ([RFC 0010](docs/rfcs/0010-worker-process-group.md)). A program a confined worker left running used to keep its `--direct` paths, the network, and the terminal after the worker and the broker were gone. A worker that needs a program to outlive it must run with `--unconfined`, which is unchanged. A stop signal the broker inherited as ignored, as under `nohup`, stays ignored. Not covered: a program that calls `setsid` or `setpgid`, and anything after `SIGKILL` to the broker.

### Fixed

- An audit event for a request that no grant covers, and for a `grant` refused after `lock()`, records the normalized path, as [RFC 0002](docs/rfcs/0002-audit-events.md) specifies. It recorded the path as requested, so `/srv/data/../../etc/shadow` appeared to be a request inside `/srv/data`. The decision itself was always correct.
- A request refused because a symlink leads out of its grant fails with `EXDEV` on every platform, as `openat2` reports it on Linux, and its audit event records that errno. Where cap-std's component walk refused it, which is always on macOS, the error had no errno, so the event recorded `allow` with `errno` null, the same as a success, and a broker's worker received no errno. The request was always refused.
- A broker request or response that would not fit in the protocol's 1 MiB frame fails only that request, with `GateError::Broker`, and the connection keeps serving. It used to end the connection for good: listing a directory whose names encode to more than 1 MiB, or a request for a path long enough that the error repeating it would not fit, closed the connection, and a worker on an inherited connection lost all filesystem access. A request too large to send no longer marks the connection out of step, since nothing was sent.
- On Linux, `lock()` no longer fails when a grant holds no rights, whether it was granted that way or narrowed to nothing before the lock. Landlock rejects a rule with no access, so the lock used to fail with `GateError::LockFailed` (`AddRules(Fs(Compat(Access(Empty))))`), in strict and best-effort mode alike, while the same gate locked on macOS. Such a grant now adds no rule, so the kernel refuses everything beneath it, and the gate refuses it with `RightsExceeded`.
- `fsgate-broker --direct` refuses a relative path, as `--grant` does, with a usage error that asks for an absolute one. It used to resolve one against the broker's working directory, so `--direct .:r` under a service started in `/` let the confined worker read the whole filesystem.
- `fsgate-broker` gives a usage error (exit 2) for an argument that is not valid UTF-8, naming the argument. It used to panic with exit 101.
- `Broker::serve` closes a connection it cannot start a thread for, and keeps accepting. It used to panic, which ended its accept loop for good, so later connections waited in the listen backlog and their requests hung instead of failing closed. `fsgate-broker` reports a thread it cannot start as an error (exit 1) instead of panicking (exit 101), and starts the thread that serves an inherited connection before the worker.
- `fsgate-broker --socket` refuses a path through a directory that another user owns, or can write to without the sticky bit, and exits 1 before binding. Workers find the broker by that path, so such a user could replace the socket with their own and answer the worker's requests.
- `Gate::open` and `Gate::create` no longer wait on a FIFO. Opening one blocks until its other end is opened, so a FIFO beneath a grant held the caller indefinitely, and in a broker it held the thread serving that connection. `open` now returns it at once, `create` fails with `ENXIO` while it has no reader, and the file blocks as usual afterwards.
- `fsgate-broker` refuses a grant that a confined worker could read without the broker, and exits 1 before starting it. That is a grant that overlaps a runtime directory (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`) or a `--direct` path, in either direction, and gives `READ` or `LIST` where the worker may read or list. The worker read such a grant directly, with no audit event, and revoking the grant did not stop it.
- On a kernel before Linux 5.11, `fsgate-broker` without `--unconfined` fails with the error that Landlock is unavailable, which names `--unconfined`. It failed first on `close_range`, with an error that named no remedy. The worker applies its Landlock rules before marking inherited descriptors close-on-exec, and both happen before it starts.

## 0.3.0 (2026-11-09)

[`fsgate` 0.3.0](https://crates.io/crates/fsgate/0.3.0), built from the signed tag [`v0.3.0`](https://github.com/farming-labs/fsgate/tree/v0.3.0) on `78a33ae`. Not independently reviewed. Upgrade from 0.1.1 or 0.2.0: both have the `Gate::open` defect listed under Fixed. `fsgate-broker` now confines its worker by default, as listed under Changed, which is why this is a minor release. Everything behind the `experimental-intercept` feature is not part of this release: it builds only from the repository, and the published crate refuses the feature with a compile error.

### Added

- `fsgate-broker --direct <path>:<rights>` adds a path a confined worker may open itself, with the letters `r`, `l`, and `x`. Those opens are not audited, so it is for runtime files, not data. `--env <name>` passes one variable to a confined worker.

### Changed

- `fsgate-broker` confines its worker by default ([RFC 0008](docs/rfcs/0008-confine-broker-worker.md)). On Linux the worker can open the files a program needs to start and its `--direct` paths, and reaches everything else through the broker. It has no controlling terminal, is killed if the broker dies, and inherits no descriptors beyond its connection and standard streams and no environment beyond its `--env` names. A worker that opens data directly must use `BrokerGate` or `--direct`.
- Where `fsgate-broker` cannot confine a worker, on macOS or on a kernel without Landlock ABI v3, the worker does not start. To keep the old behavior, pass `--unconfined`.
- `fsgate-broker --socket` requires `--unconfined`, because a confined worker makes no new connections.

### Fixed

- `Gate::open` refuses a directory with `EISDIR`, and the broker no longer delivers a descriptor for one. It used to open any directory beneath a grant, so a worker holding only `READ` could list a directory without `LIST`, and could open paths relative to the descriptor under its own authority, which [RFC 0003](docs/rfcs/0003-broker-protocol.md#alternatives-considered) rejects. Code that used `open` to get a directory descriptor now fails; `read_dir` lists one. The check is on the opened descriptor, so it also covers a Linux race in which a symlink replaced on ext4 during resolution reads as empty and resolves to its own parent directory.

## 0.2.0 (2026-11-09)

[`fsgate` 0.2.0](https://crates.io/crates/fsgate/0.2.0), built from the signed tag [`v0.2.0`](https://github.com/farming-labs/fsgate/tree/v0.2.0) on `aee17a7`, and the first release published by the trusted-publishing workflow. Not independently reviewed. Everything behind the `experimental-intercept` feature is not part of this release: it builds only from the repository, and the published crate refuses the feature with a compile error. The experimental entries below describe the repository.

### Added

- Experimental, Linux only, behind the `experimental-intercept` feature and outside semver: `Gate::open_regular_strict`, the read-only open of the RFC 0004 interception profile. It needs `READ` like `open`, but refuses every symlink with `ELOOP` (even inside the grant), directories with `EISDIR`, and FIFOs, devices, sockets, and procfs or sysfs files with `EOPNOTSUPP` without opening them for I/O. It reopens the `O_PATH` handle it checked, so a rename in between cannot substitute another file. The feature adds a direct dependency on `rustix-linux-procfs`, already in the dependency graph through `cap-std`.
- Experimental, same feature: `fsgate::intercept::OpenRequest` and `Gate::open_intercepted`, the audited dispatcher for intercepted open requests. It validates the copied arguments against the RFC 0004 file-open contract, authorizes with `open_regular_strict`, and emits exactly one audit event per request, including requests refused before any grant is matched.
- Experimental, same feature, Linux x86_64 only: `fsgate::intercept::Launch` and `Outcome`, a launcher for static worker binaries under the RFC 0004 profile. It checks the image (native x86_64 ELF, no interpreter, not set-ID, no file capabilities), starts the worker with only stdio and an empty environment under `no_new_privs`, a Landlock ruleset that allows executing only its own image, a seccomp filter that sends `open`, `openat`, and `openat2` to a supervisor thread, and the RFC's final syscall allowlist, then answers each request with `Gate::open_intercepted`. Not independently reviewed. The `unsafe` it needs lives in one private module with a written safety contract, and the feature adds an optional direct dependency on `libc`.
- Experimental, same feature: `Launch::spawn` and `intercept::Running`, a handle to a running worker. `revoke` and `narrow` change the gate while the worker runs; each waits for any request already being decided, and applies to every later request. Descriptors already delivered stay usable. Also `take_stdin` (standard input is now a dedicated pipe, closed by `wait` and by `run`), `kill`, `id`, and `wait`. Dropping a `Running` kills and reaps the worker. A request interrupted by a signal is answered with nothing: the supervisor drops its copy of the file and the worker gets `EINTR`.
- Experimental, same feature: `fsgate-broker --experimental-intercept`. Without `--apply` it prints the plan (the worker check, the grants, the profile) and starts nothing; with `--apply` it runs the worker under `intercept::Launch`, relays its output, and exits with its code. `--audit` writes each decision to standard error as an RFC 0002 JSON line. A refused worker image exits 3. In builds without the feature, or off Linux x86_64, the flag is a usage error. The socket mode is unchanged.
- `AuditReason::UnsupportedInput` and `AuditReason::InvalidMemory`, and the `AuditEvent` fields `syscall` and `notification`, set only for intercepted requests. Every JSON line now carries `syscall` and `notification` keys, `null` outside interception; both are additive within format v1 ([RFC 0002](docs/rfcs/0002-audit-events.md)).
- `Restrictions`, `LockOptions`, and `Gate::restrictions` ([RFC 0006](docs/rfcs/0006-lock-restrictions.md)). `lock()` applies kernel restrictions beyond the filesystem rules where the kernel supports them: `IOCTL_DEV` (Linux 6.10: ioctls on devices opened after the lock only beneath a `WRITE` grant), `ABSTRACT_UNIX_SOCKET` and `SIGNAL` (6.12: no connects to abstract sockets or signals to processes outside the sandbox), `ALL_THREADS` (7.0: every thread of the process, not just the caller), and `RESOLVE_UNIX` (7.1: no connects or sends to pathname Unix sockets created outside the sandbox, even beneath a grant). `Gate::restrictions` reports which took effect. `LockOptions::restrict` drops members and `LockOptions::require` makes them mandatory, even under `LockPolicy::BestEffort`. A missing requirement fails with `LockUnsupported` naming the kernel that provides it, before anything is applied.
- The `lock` audit event's `restrictions` key lists what took effect, in a fixed order; it is `null` for a refused lock and every other operation. Every JSON line now carries the key, additive within format v1 ([RFC 0002](docs/rfcs/0002-audit-events.md)).
- `ServeOptions` and `Broker::serve_with` ([RFC 0007](docs/rfcs/0007-broker-peers.md)). `allow_peer_uids` sets which users may connect, `any_peer` turns the check off, and `max_connections` sets the limit. This adds a direct dependency on `libc` on macOS, already in the dependency graph, for `getpeereid`.
- `fsgate-broker` without `--socket` passes its command a connection with no name in the filesystem, so no other process can connect to it, and `BrokerGate::from_inherited` adopts it ([RFC 0007](docs/rfcs/0007-broker-peers.md)). It works after `lock()` because it needs no connect. The `unsafe` that adopting a descriptor needs is in one private module with a written safety contract.

### Changed

- `fsgate-broker --socket` creates a `0600` socket instead of following the umask, and sets the mode before accepting connections. A worker of another user or group that relied on a looser umask loses access. It also reports a failure to serve and exits, where it used to stop serving silently and leave workers hanging.
- `Broker::serve` refuses peers running as another user and closes connections past 64 ([RFC 0007](docs/rfcs/0007-broker-peers.md)). To keep the old behavior, call `Broker::serve_with` with `ServeOptions::any_peer` and a higher `max_connections`. On a platform other than Linux and macOS, `serve` fails with `ErrorKind::Unsupported` unless `any_peer` is set. While the process is out of descriptors, `serve` now waits and retries, where it used to stop accepting for good.
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
