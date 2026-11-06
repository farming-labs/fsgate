# fsgate

**Filesystem authority as directory handles you grant up front, enforced by the kernel.**

fsgate is a Rust library for programs that run untrusted or compromise-prone code. You grant a small set of directories while the process is still trusted, then lock the process. After the lock, every path lookup resolves beneath one of those grants and everything else fails. There is no fallback path.

```rust,no_run
use fsgate::{Gate, Rights};

fn main() -> Result<(), fsgate::GateError> {
    let mut gate = Gate::new();
    gate.grant("/srv/data", Rights::READ | Rights::WRITE | Rights::CREATE)?;
    gate.lock()?; // kernel enforcement on; no new filesystem authority after this

    let file = gate.open("/srv/data/users/1.json")?; // beneath the /srv/data grant
    assert!(gate.open("/etc/passwd").is_err()); // no grant: always an error
    Ok(())
}
```

## How it enforces

Two layers, both required:

1. **Handle resolution.** Paths are matched to a granted directory handle and opened relative to it with `openat2(2)` + `RESOLVE_BENEATH` on Linux (component-walk fallback elsewhere), building on `cap-std`. No string-prefix checks; symlinks and `..` cannot escape a grant.
2. **Process containment.** `lock()` loads a Landlock ruleset built from the grants on Linux, so even native code that bypasses the library cannot reach ungated paths (why Landlock and not seccomp: ADR 0002). On platforms without Landlock a strict `lock()` fails closed, and containment is structural instead: `fsgate-broker` holds the grants in a trusted parent process and serves a worker over a Unix socket, passing descriptors back with `SCM_RIGHTS` (protocol: RFC 0003). Every rights decision runs broker-side; when the broker dies, the worker's filesystem operations fail closed.

```text
fsgate-broker --grant /srv/data:rl --socket /tmp/app.sock -- ./worker
# worker: BrokerGate::connect(env FSGATE_BROKER_SOCKET) → open/create/metadata/read_dir
```

## What fsgate does not do

- It does not sandbox the network, environment, or memory. Filesystem only.
- It does not intercept `open(2)` in unmodified binaries. v1 is a library API; a preload shim is a possible later addition, not a promise.
- It does not support Windows in v1.
- It is not a container runtime and does not replace one.

## Status

Early implementation, not yet released or independently reviewed. The handle layer (M1), Linux kernel containment via `lock()` (M2), and the broker (M3) are implemented and tested — denial tests assert the forbidden side effect did not happen, a child-process test proves a raw `std::fs` call fails at the kernel on Linux, and a binary end-to-end test proves a killed broker fails the worker closed. The audit sink (M4) is not built yet. Note the honest macOS limit: the broker contains a worker that has no other filesystem authority; fsgate does not yet strip a macOS process of its ambient authority for you. Design: [docs/rfcs/0001-core-design.md](docs/rfcs/0001-core-design.md); plan and evidence: [ROADMAP.md](ROADMAP.md).

## Prior art

[libpreopen](https://github.com/musec/libpreopen) (the idea), [cap-std](https://github.com/bytecodealliance/cap-std) (safe beneath-handle resolution), WASI preopens, Capsicum, Landlock.

## License

MIT.
