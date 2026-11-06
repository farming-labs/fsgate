# fsgate

**Filesystem authority as directory handles you grant up front, enforced by the kernel.**

fsgate is a Rust library for programs that run untrusted or compromise-prone code. You grant a small set of directories while the process is still trusted, then lock the process. After the lock, every path lookup resolves beneath one of those grants and everything else fails. There is no fallback path.

```rust
let mut gate = Gate::new();
let data = gate.grant("/srv/data", Rights::READ | Rights::WRITE)?;
gate.lock()?; // kernel enforcement on; no new filesystem authority after this

gate.open("/srv/data/users/1.json")?; // resolves beneath the /srv/data grant
gate.open("/etc/passwd")?;            // Err(GateError::NoGrant) — always
```

## How it enforces

Two layers, both required:

1. **Handle resolution.** Paths are matched to a granted directory handle and opened relative to it with `openat2(2)` + `RESOLVE_BENEATH` on Linux (component-walk fallback elsewhere), building on `cap-std`. No string-prefix checks; symlinks and `..` cannot escape a grant.
2. **Process containment.** `lock()` loads a Landlock ruleset built from the grants on Linux, so even native code that bypasses the library cannot reach ungated paths (why Landlock and not seccomp: ADR 0002). On platforms without Landlock a strict `lock()` fails closed; on macOS the same guarantee will come from a broker process (M3) that holds the grants and passes descriptors over a socket.

## What fsgate does not do

- It does not sandbox the network, environment, or memory. Filesystem only.
- It does not intercept `open(2)` in unmodified binaries. v1 is a library API; a preload shim is a possible later addition, not a promise.
- It does not support Windows in v1.
- It is not a container runtime and does not replace one.

## Status

Early implementation, not yet released or independently reviewed. The handle layer (M1) and Linux kernel containment via `lock()` (M2) are implemented and tested, including denial tests that assert the forbidden side effect did not happen and a child-process test proving a raw `std::fs` call fails at the kernel. The macOS broker (M3) and audit sink (M4) are not built yet, so on macOS a `Gate` currently constrains code that goes through it, not code that bypasses it. Design: [docs/rfcs/0001-core-design.md](docs/rfcs/0001-core-design.md); plan and evidence: [ROADMAP.md](ROADMAP.md).

## Prior art

[libpreopen](https://github.com/musec/libpreopen) (the idea), [cap-std](https://github.com/bytecodealliance/cap-std) (safe beneath-handle resolution), WASI preopens, Capsicum, Landlock.

## License

MIT.
