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
2. **Process containment.** `lock()` applies Landlock rules and a seccomp filter on Linux so even native code that bypasses the library cannot reach ungated paths. On macOS the same guarantee comes from a broker process that holds the grants and passes descriptors over a socket.

## What fsgate does not do

- It does not sandbox the network, environment, or memory. Filesystem only.
- It does not intercept `open(2)` in unmodified binaries. v1 is a library API; a preload shim is a possible later addition, not a promise.
- It does not support Windows in v1.
- It is not a container runtime and does not replace one.

## Status

Design phase. There is no published crate, no test suite, and no security guarantee yet. The design is in [docs/rfcs/0001-core-design.md](docs/rfcs/0001-core-design.md) and the plan in [ROADMAP.md](ROADMAP.md). Claims are labeled: nothing here is "tested" or "reviewed" until the roadmap says so with evidence.

## Prior art

[libpreopen](https://github.com/musec/libpreopen) (the idea), [cap-std](https://github.com/bytecodealliance/cap-std) (safe beneath-handle resolution), WASI preopens, Capsicum, Landlock.

## License

MIT.
