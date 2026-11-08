# RFC 0006: restrict more than file paths at `lock()`

- Status: accepted ([#34](https://github.com/farming-labs/fsgate/pull/34)); unimplemented
- Date: 2026-11-07
- Roadmap: [M8](../../ROADMAP.md#m8--containment-beyond-file-paths-linux)
- Builds on: [RFC 0001](0001-core-design.md#containment-lock) (containment), [ADR 0002](../decisions/0002-landlock-not-seccomp-for-paths.md)

## Problem

`lock()` installs a Landlock ruleset that handles filesystem access
rights up to ABI v3 and nothing else (`containment.rs`). RFC 0001 and the
README document three gaps that follow, and nothing closes them:

1. **Unix sockets and signals.** A locked process can connect to
   abstract and pathname Unix sockets and signal processes outside the
   sandbox. Through a socket it can ask an unconfined process to act on
   files for it, or receive descriptors the ruleset does not apply to.
   Such processes are common: a tmux server (`/tmp/tmux-$UID/default`)
   runs commands as the user, and an ssh agent signs as the user.
2. **Sibling threads.** Landlock restricts the calling thread and what
   it spawns afterwards. Threads that already exist at `lock()` keep full
   filesystem access. RFC 0001 tells callers to lock before spawning
   threads, but nothing checks that they did, and libraries start threads
   their callers never see.
3. **Device ioctls.** A device opened beneath a grant accepts every
   ioctl.

The `landlock` crate fsgate pins (0.4.7) supports a kernel feature for
each gap:

| Gap | Landlock feature | ABI | Linux |
|---|---|---|---|
| Device ioctls | `AccessFs::IoctlDev` | v5 | 6.10 |
| Abstract socket connects | `Scope::AbstractUnixSocket` | v6 | 6.12 |
| Signals | `Scope::Signal` | v6 | 6.12 |
| Sibling threads | `all_threads()` (`LANDLOCK_RESTRICT_SELF_TSYNC`) | v8 | 7.0 |
| Pathname socket connects | `AccessFs::ResolveUnix` | v9 | 7.1 |

Strict `lock()` requires only v3 (Linux 6.2) today. Requiring all of
these would make it fail on every kernel before 7.1, including the 7.0
kernel CI runs on.

There is also a defect in the same path. On a kernel below v3, strict
`lock()` calls `restrict_self()` first and only then returns
`LockUnsupported`. The process is left partially restricted while the
gate reports that it is not locked, and a retry with `BestEffort` stacks
a second Landlock domain on top.

## Goals

- A bare `lock()` applies every restriction above that the running
  kernel supports.
- Strict `lock()` keeps working on every kernel where it works today.
- Callers learn exactly which restrictions took effect, and can require
  any of them.
- A failed `lock()` changes nothing: not the gate, not the process.

## Non-goals

- Network rules (Landlock ABI v4 TCP bind and connect). Network
  capabilities stay out of scope for v1 (RFC 0001).
- The experimental launcher's ruleset, which RFC 0004 builds separately.
- macOS, which has no kernel equivalent.
- A right that permits connecting to pathname sockets after `lock()`
  (see [Pathname sockets and the broker](#pathname-sockets-and-the-broker)).

## Design

### Restrictions

A new flag set names the restrictions beyond the filesystem floor,
using Landlock's names:

```rust
pub struct Restrictions(u8);

impl Restrictions {
    pub const IOCTL_DEV: Restrictions;            // ABI v5
    pub const ABSTRACT_UNIX_SOCKET: Restrictions; // ABI v6
    pub const SIGNAL: Restrictions;               // ABI v6
    pub const ALL_THREADS: Restrictions;          // ABI v8
    pub const RESOLVE_UNIX: Restrictions;         // ABI v9

    pub const fn all() -> Restrictions;
    pub const fn empty() -> Restrictions;
    pub const fn contains(self, other: Restrictions) -> bool;
}
// BitOr, BitAnd, and Debug, like `Rights`.
```

Once in effect:

- `IOCTL_DEV`: a character or block device opened after `lock()`
  accepts ioctls only beneath a grant that holds `WRITE`, apart from the
  generic commands Landlock always allows. Descriptors opened before
  `lock()`, such as an inherited terminal, are unaffected.
- `ABSTRACT_UNIX_SOCKET`: connecting or sending to an abstract socket
  created outside the process's Landlock domain fails. Sockets the
  process creates after `lock()` still work between it and its
  descendants.
- `SIGNAL`: signalling a process outside the domain fails. That covers
  the parent and anything spawned before `lock()`; children spawned
  after it are inside the domain.
- `ALL_THREADS`: the ruleset applies to every thread of the process in
  one step, not only to the calling thread.
- `RESOLVE_UNIX`: connecting or sending to a pathname socket fails
  everywhere. Sockets connected before `lock()` keep working.

`all()` means every restriction this fsgate version knows. A release
that adds one is a minor release with a changelog entry.

### Options

`lock_with` takes an options value. A `LockPolicy` converts into one, so
existing calls compile unchanged:

```rust
pub struct LockOptions { /* private */ }

impl LockOptions {
    /// `restrict` defaults to `Restrictions::all()`, `require` to empty.
    pub fn new(policy: LockPolicy) -> LockOptions;
    pub fn restrict(self, set: Restrictions) -> LockOptions;
    pub fn require(self, set: Restrictions) -> LockOptions;
}

impl Default for LockOptions {} // LockPolicy::Strict
impl From<LockPolicy> for LockOptions {}

impl Gate {
    /// `lock_with(LockOptions::default())`.
    pub fn lock(&mut self) -> Result<LockStatus, GateError>;
    pub fn lock_with(&mut self, options: impl Into<LockOptions>)
        -> Result<LockStatus, GateError>;
    /// `None` until a lock succeeds.
    pub fn restrictions(&self) -> Option<Restrictions>;
}
```

- **`policy`** keeps its meaning and governs only the filesystem floor,
  ABI v3. `Strict` fails without it; `BestEffort` accepts less.
- **`restrict`** is the set to request; unsupported members are skipped.
  A caller that needs a channel after locking removes that member, for
  example `ABSTRACT_UNIX_SOCKET` for an X11 client.
- **`require`** must take effect, or `lock()` fails with
  `LockUnsupported`. Required members are requested even when left out
  of `restrict`. `require` binds under `BestEffort` too: that policy
  relaxes the floor, never an explicit requirement. On platforms
  without Landlock a non-empty `require` always fails.

The error names the missing restriction, the kernel that provides it,
and the fix, for example: "`Restrictions::SIGNAL` needs Landlock ABI v6
(Linux 6.12), which this system does not provide; remove it from
`LockOptions::require` or run on a newer Linux kernel".

### Failing before anything is applied

Required parts are added to the ruleset under the crate's
`CompatLevel::HardRequirement`: the floor under `Strict`, and every
member of `require`. Everything else goes in under `BestEffort`. The
crate then rejects an unsupported requirement while the ruleset is being
built, before `restrict_self()`. A failed lock leaves the process
unrestricted and the gate unlocked, so the caller can retry with other
options or exit. This replaces today's order of applying first and
checking after.

### Reporting

`lock()` still returns `LockStatus`, now describing the floor alone:

- `FullyEnforced`: the ABI v3 filesystem rules are enforced.
- `PartiallyEnforced`: an older ABI, v1 or v2.
- `LibraryOnly`: no Landlock.

The status comes from the effective ABI that `restrict_self()` reports,
not from the crate's aggregate `RulesetStatus`. That aggregate reads
`PartiallyEnforced` whenever any requested feature is missing, so on
7.0 it would otherwise turn every strict lock into an error.

`Gate::restrictions()` returns the members that took effect, derived
from the same effective ABI plus the crate's `all_threads` status. The
`lock` audit event gains a `restrictions` key listing those members, in
this order: `ioctl_dev`, `abstract_unix_socket`, `signal`,
`all_threads`, `resolve_unix`. The key is `null` for other operations
and for refused locks. It is additive within format v1 (RFC 0002).

Both mappings, from effective ABI to status and from effective ABI to
restrictions, are a pure function, unit-tested for every ABI value.
That covers the decision logic for kernels CI cannot boot.

### Pathname sockets and the broker

With `RESOLVE_UNIX` in effect, connects to pathname sockets fail after
`lock()`. A worker that uses `BrokerGate` therefore connects before it
locks. The connected stream keeps working, and a lost connection already
fails closed with no reconnect. A `BrokerGate::connect` after locking
fails with `GateError::Broker`, and its message should name this order.

No fsgate right grants `ResolveUnix` in this RFC. Mapping it to `WRITE`,
which is how the crate classifies it, is rejected: `WRITE` on `/tmp` is
a common grant, and `/tmp` holds the sockets of tmux, ssh agents, and
X11, each of which acts as the user. A dedicated right can follow once a
caller needs to connect after locking.

`IoctlDev` does map to `WRITE`. A `WRITE` grant on a device directory
already lets the process write the devices beneath it, so ioctls on them
add little authority.

### Compatibility

This ships in 0.2.0.

- **Behavior.** On 6.10 and later, a bare `lock()` restricts more. Code
  that does any of the following after locking breaks there:
  - signals its parent;
  - connects to a Unix socket outside the domain;
  - issues device ioctls outside a `WRITE` grant;
  - relies on a sibling thread staying unrestricted.

  It opts out by removing that member from `restrict`. The changelog
  lists each case.
- **API.** `Restrictions`, `LockOptions`, and `Gate::restrictions` are
  new. `lock_with` accepts `impl Into<LockOptions>`: calls passing a
  `LockPolicy` compile unchanged, but code that names `Gate::lock_with`
  as a function value with a `LockPolicy` parameter does not.
  `LockStatus` and `LockPolicy` need no new variants.
- **Failure.** A failed strict lock no longer leaves the process
  partially restricted.
- **Audit.** One new key, within format v1.

## Testing

Each test follows the locked-child pattern in `tests/lock.rs`. It
asserts the refusal *and* the absence of the side effect against the
real kernel. A control run locks with that member removed and succeeds.

- **Abstract socket:** the parent listens on an abstract address; the
  locked child's connect fails and the parent accepts nothing.
- **Signal:** the locked child's signal to the parent fails and the
  parent's handler never runs.
- **Ioctl:** the locked child opens `/dev/null` beneath a `READ` grant
  on `/dev`, and `TCGETS` fails with `EACCES`. The control and a `WRITE`
  grant both see `ENOTTY`.
- **All threads:** a thread started before `lock()` makes a raw open
  outside the grants. It fails, and no file is created.
- **Pathname socket:** the same shape as the abstract socket test. It
  needs Linux 7.1, and CI does not run that yet.
- **Requirements:** on the CI kernel, requiring `RESOLVE_UNIX` fails
  with `LockUnsupported`. Afterwards the process can still open files
  outside the grants (nothing was applied), and a second lock without
  that requirement succeeds.
- **Mapping:** the effective-ABI mapping is unit-tested for every ABI.

The tests pin the errno each refusal returns. CI runs on Linux 7.0, so
everything except the pathname socket test runs there.

## Alternatives considered

- **Require every feature in strict `lock()`:** rejected. It fails on
  every kernel below 7.1, including CI's, and pushes callers to
  `BestEffort`, which gives up the floor as well.
- **Make the new restrictions opt-in:** rejected. A bare `lock()` should
  do the safe thing, and opt-in hardening reaches few callers. They are
  on by default, with a per-member opt-out.
- **A `LockStatus` or `LockPolicy` variant per level:** rejected. Five
  features combine badly, and each new variant breaks exhaustive
  matches.
- **Return a report struct from `lock()`:** rejected. It breaks every
  `let status: LockStatus = gate.lock()?`, while a getter is additive.
- **seccomp to deny `connect`, `kill`, or `ioctl`:** rejected for the
  reasons in ADR 0002. seccomp sees no paths, and denying `connect`
  outright breaks `BrokerGate` and every library using a socket opened
  before `lock()`. Landlock scopes tell the domain's own processes apart
  from everything outside it.

## Open questions

- ~~Does the crate reject an unsupported `all_threads()` under
  `HardRequirement` before `restrict_self()`?~~ Resolved: yes.
  `landlock` 0.4.7 checks the flag's compatibility when it is set, so a
  required `ALL_THREADS` fails before anything is applied.
- Does the signal scope affect signals the kernel sends on the process's
  behalf, such as `SIGCHLD` at exit or `F_SETOWN` I/O signals? The tests
  record the observed behavior, and the docs state it.
