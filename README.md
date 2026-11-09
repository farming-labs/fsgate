# fsgate

**Filesystem authority as directory handles you grant up front, enforced by the kernel.**

fsgate is a Rust library for programs that run untrusted or compromise-prone code. You grant a small set of directories while the process is still trusted, then lock the process. Gate operations resolve beneath those held directory handles; paths with no grant fail. On Linux, a strict lock also restricts raw filesystem opens by the calling thread and its future descendants. There is no fallback to ambient access.

```rust,no_run
use fsgate::{Gate, Rights};

fn main() -> Result<(), fsgate::GateError> {
    let mut gate = Gate::new();
    gate.grant("/srv/data", Rights::READ | Rights::WRITE | Rights::CREATE)?;
    gate.lock()?; // kernel enforcement on; no new filesystem authority after this

    let _file = gate.open("/srv/data/users/1.json")?; // beneath the /srv/data grant
    assert!(gate.open("/etc/passwd").is_err()); // no grant: always an error
    Ok(())
}
```

```sh
cargo add fsgate             # the library
cargo install fsgate         # the fsgate-broker binary
```

## How it enforces

Two layers:

1. **Handle resolution.** Paths route to the longest covering grant and open relative to its held directory handle with `openat2(2)` + `RESOLVE_BENEATH` on Linux (component walk elsewhere), building on `cap-std`. Prefix matching selects the grant; beneath-handle resolution enforces the boundary.
2. **Process containment.** `lock()` loads a Landlock ruleset built from the grants on Linux, restricting raw opens even when native code bypasses the library (why Landlock and not seccomp: [ADR 0002](docs/decisions/0002-landlock-not-seccomp-for-paths.md)). Where the kernel supports them, the same ruleset restricts device ioctls (Linux 6.10), connects to abstract Unix sockets and signals to processes outside the sandbox (6.12), and threads that already exist (7.0) ([RFC 0006](docs/rfcs/0006-lock-restrictions.md)). On older kernels, call `lock()` before spawning threads, because existing sibling threads are not restricted. On platforms without Landlock a strict `lock()` fails closed. `fsgate-broker` can hold the grants in a trusted parent process and serve a worker over a Unix socket, passing descriptors back with `SCM_RIGHTS` ([RFC 0003](docs/rfcs/0003-broker-protocol.md)). Every broker request is authorized server-side; when the broker dies, subsequent `BrokerGate` requests fail closed. On Linux, `fsgate-broker` also confines the worker it starts, so that worker reaches data only through the broker ([RFC 0008](docs/rfcs/0008-confine-broker-worker.md)). An embedder that serves a worker through the library must remove that worker's ambient filesystem authority itself.

`lock_with(LockPolicy::BestEffort)` explicitly permits weaker filesystem rules and returns the achieved `LockStatus`: `FullyEnforced`, `PartiallyEnforced`, or `LibraryOnly`. `gate.restrictions()` reports which of the newer restrictions took effect. `lock_with(LockOptions::default().require(Restrictions::SIGNAL))` fails unless the kernel provides one; `.restrict(Restrictions::all() - Restrictions::ABSTRACT_UNIX_SOCKET)` drops one, for example for an X11 client. A lock that fails changes nothing. `narrow(grant, rights)` removes rights from a live grant and keeps its held handle; `revoke(grant)` removes the grant. Both affect future gate operations, and neither invalidates files already opened. Before `lock()`, the kernel rules are built from what remains; after it, the installed rules do not change.

```text
fsgate-broker --grant /srv/data:rl -- ./worker
# worker: BrokerGate::from_inherited() → open/create/metadata/read_dir
```

On Linux the worker starts confined. It can open the files a program needs to start, beneath `/usr`, `/lib`, `/lib64`, `/bin`, and `/sbin`, and any path given with `--direct <path>:<rights>` and the letters `r`, `l`, and `x`. Its data comes through the broker, so a program that does not use `BrokerGate` gets `EACCES` for it. It inherits no descriptors beyond its connection and standard streams, and no environment beyond the names given with `--env <name>`. If confinement cannot be applied, on macOS or on a kernel without Landlock ABI v3, the worker does not start. `--unconfined` starts it with the broker's own environment and filesystem access, and macOS needs it.

The worker inherits a connection with no name in the filesystem, so no other process can connect to it, and it keeps working after `lock()`. Programs it starts before calling `from_inherited` inherit the connection too, so adopt it first. A worker that needs several connections passes `--unconfined --socket <path>` and calls `BrokerGate::connect` with `FSGATE_BROKER_SOCKET`. That socket is owner-only whatever the umask. A worker that also calls `lock()` connects to it first: on Linux 7.1 and later, the lock refuses new connects to Unix sockets created outside it, and a connection made before it keeps working.

Experimental and unsupported, Linux x86_64 only, and built only from this repository (the published crate refuses the feature): with `--features experimental-intercept`, `fsgate-broker --experimental-intercept` runs an unmodified static binary and answers its `open`/`openat`/`openat2` calls from the grants ([RFC 0004](docs/rfcs/0004-filesystem-interception.md)). Without `--apply` it only prints the plan; it never falls back to running the worker unconfined. It needs Landlock ABI 3 and seccomp user notifications, and refuses to start without them. The worker must be a static, native x86_64 ELF. Only read-only opens of regular files by absolute path are mediated: relative paths, writes, creation, and syscalls outside the profile fail with `EOPNOTSUPP`, and every symlink fails with `ELOOP`. CI runs these tests from a release build of the packaged crate on Linux 6.6 and 7.3, each booted in a VM (and booted again without Landlock), and on the runner's own kernel.

```text
fsgate-broker --experimental-intercept --grant /srv/data:r -- ./report /srv/data/in.csv           # plan only
fsgate-broker --experimental-intercept --grant /srv/data:r --audit --apply -- ./report /srv/data/in.csv
```

## What fsgate does not do

[The threat model](docs/threat-model.md) lists each boundary, what it trusts, what it does not stop, and the test behind each claim.

- It does not sandbox the network, environment, or memory. Filesystem only.
- On kernels before Linux 7.1, `lock()` does not restrict connects to pathname Unix sockets, and before 6.12 it does not restrict abstract sockets or signals either. Through those, a locked process can still reach an unconfined process that opens files for it or passes it descriptors ([RFC 0001](docs/rfcs/0001-core-design.md#containment-lock)).
- `lock()` does not restrict file metadata. Landlock cannot restrict `stat`, `chmod`, `chown`, `utime`, or `setxattr`, so a locked process can tell whether any path exists and change the mode of files it owns outside the grants. A hard link or mount beneath a grant reaches whatever it points to, through the gate and the kernel rules alike.
- A worker can use everything its grants allow, even when confined, so keep grants small. On macOS and with `--unconfined`, nothing stops a worker from opening files directly.
- On a socket path, the broker does not tell processes of one user apart. `Broker::serve` refuses other users by default, but any process of the broker's user that can reach the socket has its grants. An inherited connection does not have this gap.
- It does not intercept `open(2)` in unmodified binaries, except through an experimental, unreviewed launcher for static Linux x86_64 binaries behind the `experimental-intercept` feature ([M6](ROADMAP.md#m6--linux-filesystem-interception-experimental), [RFC 0004](docs/rfcs/0004-filesystem-interception.md)). That launcher is not supported yet. A preload shim remains out of scope for v1.
- It does not support Windows in v1.
- It is not a container runtime and does not replace one.

## Status

**fsgate has not had an independent security review.** Early implementation, published on crates.io as [`fsgate` 0.1.1](https://crates.io/crates/fsgate/0.1.1) from the signed tag [`v0.1.1`](https://github.com/farming-labs/fsgate/tree/v0.1.1); not independently reviewed. The handle layer (M1), Linux containment (M2), broker (M3), and audit sink (M4) are implemented. Tests cover denied operations without side effects, Linux kernel enforcement in a child process, and broker failure. `Gate::set_audit_sink` observes authority decisions synchronously, including denials the caller discards and requests served by the broker. A rights denial carries the matched grant's ID; a kernel refusal after a policy allow carries an errno. `Gate::narrow` ([RFC 0005](docs/rfcs/0005-grant-narrowing.md), M7) is implemented and included since v0.1.0. The [RFC 0006](docs/rfcs/0006-lock-restrictions.md) restrictions at `lock()` (M8: device ioctls, abstract sockets, signals, all threads, and pathname sockets) are implemented and unreleased. CI tests them where the kernel provides them (Linux 7.0, and 7.3 for pathname sockets) and on Linux 6.6, where requiring one fails before anything is applied. Linux filesystem interception (M6, [RFC 0004](docs/rfcs/0004-filesystem-interception.md)) is implemented experimentally behind the `experimental-intercept` feature for static x86_64 binaries and tested in Linux CI, on Linux 6.6, Linux 7.3, and the runner's kernel. It is unreleased and unreviewed. `Launch::spawn` returns a handle that can revoke or narrow grants while the worker runs; descriptors already delivered stay usable. `fsgate-broker`'s worker confinement ([RFC 0008](docs/rfcs/0008-confine-broker-worker.md)) is implemented and unreleased. CI tests it on Linux 6.6, Linux 7.3, and the runner's kernel, and on Linux booted without Landlock, where the worker does not start.

v0.1.0 is the signed tag `v0.1.0` on `0ad477f`, prepared in [PR #1](https://github.com/farming-labs/fsgate/pull/1) and [PR #3](https://github.com/farming-labs/fsgate/pull/3). The README example compiles as a doctest, public documentation is required by `missing_docs = "deny"`, and CI tests the packaged crate as well as the checkout. v0.1.0 kept `publish = false` and is not on crates.io. 0.1.1 is the first crates.io release and adds the broker close-on-exec fix ([PR #15](https://github.com/farming-labs/fsgate/pull/15)); releases follow [the release procedure](docs/RELEASING.md). Design: [RFC 0001](docs/rfcs/0001-core-design.md); plan and evidence: [ROADMAP.md](ROADMAP.md).

## Prior art

[libpreopen](https://github.com/musec/libpreopen) (the idea), [cap-std](https://github.com/bytecodealliance/cap-std) (safe beneath-handle resolution), WASI preopens, Capsicum, Landlock.

## License

MIT.
