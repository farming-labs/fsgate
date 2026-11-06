# RFC 0001: core design

- Status: accepted
- Date: 2026-11-06

## Problem

Unix filesystem APIs run on ambient authority: any code in the process can name any path and the kernel will resolve it. Sandboxing untrusted or compromise-prone code therefore requires either rewriting it against handle-based APIs or interposing the path-based ones. libpreopen proved the interposition idea for Capsicum in 2017 but is FreeBSD-bound, string-prefix based, and unmaintained. cap-std solves safe beneath-handle resolution but does not decide policy, match paths to grants, or contain the process when native code bypasses the library.

fsgate composes the missing whole: grants, resolution, kernel containment, and auditing behind one small API.

## Design

### Authority model

- All filesystem authority enters through `grant(path, Rights)`, called while the process is still trusted. A grant opens the directory immediately and holds the descriptor; the path string is never re-resolved later.
- `Rights` is a bitset: `READ`, `WRITE`, `CREATE`, `LIST`. Rights only narrow; nothing widens a grant after creation.
- `lock()` ends the granting phase irreversibly and applies kernel containment.
- Protection is by object identity (the held descriptor), never by name. A rename or bind mount after `grant()` does not change what the grant reaches.

### API surface

```rust
pub struct Gate { /* grants, locked flag, audit sink */ }

impl Gate {
    pub fn new() -> Gate;
    pub fn grant(&mut self, path: impl AsRef<Path>, rights: Rights) -> Result<Grant, GateError>;
    pub fn lock(&mut self) -> Result<(), GateError>;              // irreversible
    pub fn revoke(&mut self, grant: Grant) -> Result<(), GateError>;

    pub fn open(&self, path: impl AsRef<Path>) -> Result<File, GateError>;
    pub fn create(&self, path: impl AsRef<Path>) -> Result<File, GateError>;
    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, GateError>;
    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<ReadDir, GateError>;
}
```

Naming follows fixed verb jobs: `grant` confers authority, `lock` applies containment, `revoke` is the reverse of `grant`. Every registration has its reverse; `lock()` is the one deliberate exception and is documented as irreversible.

### Resolution

1. Normalize the requested path lexically (no filesystem access).
2. Find the longest granted prefix. No grant → `GateError::NoGrant`.
3. Check the operation against the grant's `Rights`. Insufficient → `GateError::RightsExceeded`.
4. Open the remainder relative to the grant's descriptor with `openat2(2)` and `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` (via cap-std). The kernel, not the prefix match in step 2, is what prevents escapes: a symlink or `..` that leaves the grant fails at the syscall.

Step 2 is routing, not security. If it routes to the wrong grant, the worst outcome is an operation under a directory that was still deliberately granted.

### Containment (`lock()`)

Linux: build a Landlock ruleset from the grants (same directories, mapped rights) and load a seccomp filter that denies path-taking syscalls (`open`, `openat` without `RESOLVE_BENEATH` is not distinguishable, so the filter denies the path families wholesale and the library uses `openat2` through its own held descriptors). Exact syscall list is an M2 deliverable with tests.

macOS: no Landlock equivalent, so containment is structural — a broker process (M3) holds the grants and the worker process holds nothing. The library API is identical; the transport differs.

`lock()` fails closed: if the kernel lacks Landlock ABI support, it returns an error. Callers may opt into `LockPolicy::BestEffort` explicitly; the default never degrades silently.

### Errors

One `GateError` enum with stable variants. Messages are full sentences naming the path, the missing right or grant, and the fix. Denials are reported with the same detail to the audit sink but a configurable, reduced detail to the caller if the embedder wants to avoid oracle leaks.

### Auditing

Every allow and deny emits one structured event: operation, requested path, matched grant (if any), decision, errno. Format is RFC 0002.

## Non-goals (v1)

LD_PRELOAD interposition, Windows, quotas, network capabilities, in-process multi-tenant separation (a Gate does not defend against other code in the same address space until `lock()` — that is what `lock()` and the broker are for).

## Alternatives considered

- **String-prefix checks on every call (libpreopen's matching as the boundary):** rejected; raceable and symlink-unsafe. Kernel-enforced `RESOLVE_BENEATH` replaces it.
- **Landlock only, no handle layer:** rejected; Landlock has no per-call audit, no revocation granularity, and nothing on macOS.
- **Broker everywhere:** rejected for v1 Linux; an IPC round-trip per open is needless where `openat2` + Landlock suffice. The broker remains mandatory on macOS and available as defense in depth.
- **Forking cap-std's resolver:** rejected; upstream is maintained and battle-tested. fsgate stays a consumer.

## Open questions

- seccomp filter scope vs. real-world libraries that legitimately `openat` relative descriptors (tracked for M2).
- Whether `Grant` should be cloneable with attenuated rights (`grant.narrow(Rights::READ)`) in v1 or later.
- Audit sink backpressure: drop, block, or count-and-flag (RFC 0002).
