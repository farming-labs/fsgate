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
2. **Process containment.** `lock()` loads a Landlock ruleset built from the grants on Linux, restricting raw opens even when native code bypasses the library (why Landlock and not seccomp: [ADR 0002](docs/decisions/0002-landlock-not-seccomp-for-paths.md)). Call it before spawning threads: existing sibling threads are not restricted. On platforms without Landlock a strict `lock()` fails closed. `fsgate-broker` can hold the grants in a trusted parent process and serve a worker over a Unix socket, passing descriptors back with `SCM_RIGHTS` ([RFC 0003](docs/rfcs/0003-broker-protocol.md)). Every broker request is authorized server-side; when the broker dies, subsequent `BrokerGate` requests fail closed. The embedder must separately remove the worker's ambient filesystem authority.

`lock_with(LockPolicy::BestEffort)` explicitly permits weaker containment and returns the achieved `LockStatus`: `FullyEnforced`, `PartiallyEnforced`, or `LibraryOnly`. `narrow(grant, rights)` removes rights from a live grant and keeps its held handle; `revoke(grant)` removes the grant. Both affect future gate operations, and neither invalidates files already opened. Before `lock()`, the kernel rules are built from what remains; after it, the installed rules do not change.

```text
fsgate-broker --grant /srv/data:rl --socket /tmp/app.sock -- ./worker
# worker: BrokerGate::connect(env FSGATE_BROKER_SOCKET) → open/create/metadata/read_dir
```

Experimental and unsupported, Linux x86_64 only: built with `--features experimental-intercept`, `fsgate-broker --experimental-intercept` runs an unmodified static binary and answers its `open`/`openat`/`openat2` calls from the grants ([RFC 0004](docs/rfcs/0004-filesystem-interception.md)). Without `--apply` it only prints the plan; it never falls back to running the worker unconfined.

```text
fsgate-broker --experimental-intercept --grant /srv/data:r -- ./report /srv/data/in.csv           # plan only
fsgate-broker --experimental-intercept --grant /srv/data:r --audit --apply -- ./report /srv/data/in.csv
```

## What fsgate does not do

- It does not sandbox the network, environment, or memory. Filesystem only.
- It does not intercept `open(2)` in unmodified binaries, except through an experimental, unreviewed launcher for static Linux x86_64 binaries behind the `experimental-intercept` feature ([M6](ROADMAP.md#m6--linux-filesystem-interception-experimental), [RFC 0004](docs/rfcs/0004-filesystem-interception.md)). That launcher is not supported yet. A preload shim remains out of scope for v1.
- It does not support Windows in v1.
- It is not a container runtime and does not replace one.

## Status

Early implementation, published on crates.io as [`fsgate` 0.1.1](https://crates.io/crates/fsgate/0.1.1) from the signed tag [`v0.1.1`](https://github.com/farming-labs/fsgate/tree/v0.1.1); not independently reviewed. The handle layer (M1), Linux containment (M2), broker (M3), and audit sink (M4) are implemented. Tests cover denied operations without side effects, Linux kernel enforcement in a child process, and broker failure. `Gate::set_audit_sink` observes authority decisions synchronously, including denials the caller discards and requests served by the broker. A rights denial carries the matched grant's ID; a kernel refusal after a policy allow carries an errno. `Gate::narrow` ([RFC 0005](docs/rfcs/0005-grant-narrowing.md), M7) is implemented and included since v0.1.0. Linux filesystem interception (M6, [RFC 0004](docs/rfcs/0004-filesystem-interception.md)) is implemented experimentally behind the `experimental-intercept` feature for static x86_64 binaries and tested in Linux CI. It is unreleased and unreviewed. `Launch::spawn` returns a handle that can revoke or narrow grants while the worker runs; descriptors already delivered stay usable.

v0.1.0 is the signed tag `v0.1.0` on `0ad477f`, prepared in [PR #1](https://github.com/farming-labs/fsgate/pull/1) and [PR #3](https://github.com/farming-labs/fsgate/pull/3). The README example compiles as a doctest, public documentation is required by `missing_docs = "deny"`, and CI tests the packaged crate as well as the checkout. v0.1.0 kept `publish = false` and is not on crates.io. 0.1.1 is the first crates.io release and adds the broker close-on-exec fix ([PR #15](https://github.com/farming-labs/fsgate/pull/15)); releases follow [the release procedure](docs/RELEASING.md). Design: [RFC 0001](docs/rfcs/0001-core-design.md); plan and evidence: [ROADMAP.md](ROADMAP.md).

## Prior art

[libpreopen](https://github.com/musec/libpreopen) (the idea), [cap-std](https://github.com/bytecodealliance/cap-std) (safe beneath-handle resolution), WASI preopens, Capsicum, Landlock.

## License

MIT.
