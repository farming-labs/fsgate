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
    pub fn set_audit_sink(&mut self, sink: Arc<dyn AuditSink>);
    pub fn grant(&mut self, path: impl AsRef<Path>, rights: Rights) -> Result<Grant, GateError>;
    pub fn lock(&mut self) -> Result<LockStatus, GateError>;      // irreversible; strict
    pub fn lock_with(&mut self, policy: LockPolicy) -> Result<LockStatus, GateError>;
    pub fn narrow(&mut self, grant: Grant, rights: Rights) -> Result<(), GateError>; // RFC 0005
    pub fn revoke(&mut self, grant: Grant) -> Result<(), GateError>;

    pub fn open(&self, path: impl AsRef<Path>) -> Result<File, GateError>;
    pub fn create(&self, path: impl AsRef<Path>) -> Result<File, GateError>;
    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, GateError>;
    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<ReadDir, GateError>;
}
```

As implemented for the planned v0.1.0: `lock` reports the achieved `LockStatus` (`FullyEnforced` / `PartiallyEnforced` / `LibraryOnly`) because a best-effort lock that enforced nothing must say so; `create` requires `CREATE | WRITE`, since the returned handle writes data. The broker client (`BrokerGate`, RFC 0003) exposes `open`, `create`, `metadata`, and `read_dir` with serializable result types where needed. Granting, locking, and revocation belong to the server's `Gate`, not the worker client.

Naming follows fixed verb jobs: `grant` confers authority, `lock` applies containment, `narrow` removes rights from a live grant, `revoke` is the reverse of `grant`. Every registration has its reverse; `lock()` is the one deliberate exception and is documented as irreversible.

### Resolution

1. Normalize the requested path lexically (no filesystem access).
2. Find the longest granted prefix. No grant → `GateError::NoGrant`.
3. Check the operation against the grant's `Rights`. Insufficient → `GateError::RightsExceeded`.
4. Open the remainder relative to the grant's descriptor with `openat2(2)` and `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` (via cap-std). The kernel, not the prefix match in step 2, is what prevents escapes: a symlink or `..` that leaves the grant fails at the syscall.

Step 2 is routing, not security. If it routes to the wrong grant, the worst outcome is an operation under a directory that was still deliberately granted.

### Containment (`lock()`)

Linux: build a Landlock ruleset from the grants (same directories, mapped rights; rules are bound to the held descriptors, not path names). Landlock alone mediates filesystem paths — seccomp cannot inspect path arguments and was dropped from this role; see ADR 0002. seccomp remains reserved for shrinking the non-filesystem syscall surface in later milestones.

Landlock applies to the calling thread and its future descendants. On Linux 7.0 and later, `lock()` applies the ruleset to every thread of the process ([RFC 0006](0006-lock-restrictions.md)); on older kernels, call `lock()` before spawning threads. Revocation removes authority from subsequent gate operations, but cannot revoke already opened files or alter an installed Landlock ruleset.

The filesystem rules need Landlock ABI v3. Beyond them, [RFC 0006](0006-lock-restrictions.md) restrictions are applied where the kernel supports them and reported by `Gate::restrictions()`: device ioctls (v5, Linux 6.10), abstract socket connects and signals to processes outside the sandbox (v6, Linux 6.12), every thread of the process (v8, Linux 7.0), and connects to pathname Unix sockets created outside the sandbox (v9, Linux 7.1). Through a socket the running kernel leaves unrestricted, or a connection made before the lock, a locked process can still ask an unconfined process to act on files for it, or receive descriptors from one over `SCM_RIGHTS`. A received descriptor keeps the authority it was opened with, and the ruleset does not apply to it.

macOS: no Landlock equivalent, so a broker process (M3) holds the grants and authorizes the worker's requests. The broker does not strip a worker's ambient filesystem authority; the embedder must provide that isolation separately. The client exposes the four filesystem operations above; the transport differs.

`lock()` fails closed: if the kernel lacks Landlock ABI support, it returns an error. Callers may opt into `LockPolicy::BestEffort` explicitly; the default never degrades silently.

### Errors

One `GateError` enum, `#[non_exhaustive]`: existing variants and their fields are stable, new failure kinds are additive, and matches outside fsgate need a wildcard arm. Errors name the path, the missing right or grant, and the fix where applicable. The audit sink receives structured decision details. Configurable reduction of caller-facing error detail is not implemented for v0.1.0; embedders must redact errors at their own boundary.

### Auditing

Every allow and deny emits one structured event: operation, requested path, matched grant (if any), decision, errno. Format is RFC 0002.

## Non-goals (v1)

LD_PRELOAD interposition, Windows, quotas, network capabilities, in-process multi-tenant separation (a Gate does not defend against other code in the same address space until `lock()` — that is what `lock()` and the broker are for). The [threat model](../threat-model.md) lists what each boundary does not stop, with the test behind each claim.

## Alternatives considered

- **String-prefix checks on every call (libpreopen's matching as the boundary):** rejected; raceable and symlink-unsafe. Kernel-enforced `RESOLVE_BENEATH` replaces it.
- **Landlock only, no handle layer:** rejected; Landlock has no per-call audit, no revocation granularity, and nothing on macOS.
- **Broker everywhere:** rejected for v1 Linux; an IPC round-trip per open is needless where `openat2` + Landlock suffice. The broker remains mandatory on macOS and available as defense in depth.
- **Forking cap-std's resolver:** rejected; upstream is maintained and battle-tested. fsgate stays a consumer.

## Open questions

- ~~seccomp filter scope vs. real-world libraries that legitimately `openat` relative descriptors~~ — resolved by ADR 0002: Landlock alone mediates paths.
- ~~Audit sink backpressure: drop, block, or count-and-flag~~ — resolved in RFC 0002: delivery is synchronous and the embedder owns buffering; fsgate never drops an event itself.
- ~~Whether `Grant` should be cloneable with attenuated rights (`grant.narrow(Rights::READ)`)~~ — resolved by RFC 0005, in v0.1.0: `Gate::narrow(grant, rights)` narrows a live grant in place rather than minting an attenuated copy.
