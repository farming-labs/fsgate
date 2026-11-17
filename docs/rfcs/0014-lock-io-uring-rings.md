# RFC 0014: `io_uring` rings set up before `lock()`

- Status: draft, for the maintainer's decision
- Date: 2026-11-17
- Roadmap: [M10](../../ROADMAP.md#m10--battle-tested-tests)
- Builds on: [RFC 0006](0006-lock-restrictions.md) (restrictions at `lock()`), [ADR 0002](../decisions/0002-landlock-not-seccomp-for-paths.md) (seccomp's job), [RFC 0009](0009-worker-unix-sockets.md) (the worker's seccomp filter), the [threat model](../threat-model.md#2-the-locked-process-linux)

## Problem

An `io_uring` ring set up before `lock()` keeps the credentials it was
set up with, and Landlock checks the credentials an open runs with. So
code running after the lock can open files outside the grants through
such a ring. [#119](https://github.com/farming-labs/fsgate/pull/119)
measured two routes, each against a control that a ring without them
refuses with `EACCES`, on Linux 6.6.162, 6.12.117, 7.0, and 7.3.3:

- **A personality registered before the lock.** A submission that
  names it runs with the registered credentials.
- **A ring set up with `SQPOLL` before the lock.** Its thread issues
  every submission with the credentials saved at setup
  (`ctx->sq_creds`).

`Restrictions::ALL_THREADS` does not help: the credentials belong to
the ring, not to a thread.

Who is exposed: a process that sets up a ring before `lock()`, such as
an async runtime built on `io_uring`, and later runs code it does not
trust. `fsgate-broker`'s confined worker is not: the broker confines it
before `exec`, so it has no ring from before, and below Linux 7.1 its
seccomp filter refuses `io_uring` anyway (RFC 0009).

Today fsgate only documents this, in the README's limits, the
`Gate::lock` rustdoc, and the threat model (#119).

From the kernel source, not run:

- A ring set up after the lock is not a route. Its saved credentials
  and its personalities are the locked ones.
- `io-wq` is not a route. Work handed to `io-wq` takes the submitter's
  credentials at that moment (`io_prep_async_work`), so a worker thread
  started before the lock does not carry its own to new submissions.

## Goals

- `lock()` does not report success while the process holds a ring it
  can see that would let later code open files with pre-lock
  credentials.
- It fails closed, before applying anything, with an error that names
  the ring and the fix.
- A process with no ring sees no change.
- A caller that needs its ring after the lock keeps it by an explicit
  choice.

## Non-goals

- **Descriptors opened before the lock.** They keep their access by
  design, and the docs say so.
- **A ring hidden on purpose by code before the lock.** That code is
  trusted ([threat model](../threat-model.md#1-the-gate-before-lock)).
- **macOS,** which has no `io_uring`.

## Options

### A. Keep documenting it

Nothing changes. The gap stays open for a caller who does not read the
limits.

### B. Refuse to lock while a ring is visible

Before `restrict_self`, `lock()` reads `/proc/self/fd` and
`/proc/self/task`:

- a descriptor whose link reads `anon_inode:[io_uring]` is a ring;
- a thread named `iou-sqp-<pid>` is an `SQPOLL` thread, which finds a
  ring whose descriptor was closed after registering it.

If either exists, `lock()` returns a new `GateError` variant before
anything is applied. The message names the descriptor or thread and
the fix: close the ring before `lock()`, set it up after (where it
holds the locked credentials), or drop the check. `GateError` is
`#[non_exhaustive]`, so the variant is not a breaking change by itself.
Refusing to lock is: a caller with a ring that locks today gets an
error.

It misses:

- a ring without `SQPOLL` kept only as a registered ring
  (`IORING_REGISTER_RING_FDS`, then closing its descriptor, as liburing's
  `io_uring_close_ring_fd` does), which `io_uring_enter` reaches with
  `IORING_ENTER_REGISTERED_RING`;
- a ring descriptor in flight in a Unix socket's queue;
- a ring another thread sets up between the check and `restrict_self`.

The first two need code before the lock to put the ring there, though a
library could do the first without its caller knowing. The third is the
same race as a thread started during `lock()`.

The check needs `/proc`. No `unsafe` code: `rustix`'s `readlinkat` and
directory reads do it.

### C. B, plus refuse `io_uring` after the lock

`lock()` also installs a seccomp filter on every thread
(`SECCOMP_FILTER_FLAG_TSYNC`) that answers `io_uring_setup`,
`io_uring_enter`, and `io_uring_register` with `ENOSYS`, as the broker
does for its worker below Linux 7.1. Without `io_uring_enter`, nothing
reaches a ring without `SQPOLL`, which closes the registered ring that B
misses.

It does not replace B. An `SQPOLL` thread that is awake reads
submissions from shared memory, with no system call, so B's check is
still what catches those.

Costs:

- A seccomp filter in the library. ADR 0002 kept seccomp for exactly
  this kind of job, but it needs an isolated `unsafe` module with a
  safety contract, like the broker's, or a new dependency.
- Every `io_uring` call after the lock fails, including on rings set up
  after it, which are safe. Libraries that use `io_uring` fall back to
  ordinary calls on `ENOSYS`, which RFC 0009 relies on for the worker.
- Filters stack and cannot be removed. `lock()` is already the one
  irreversible operation, and it already sets `no_new_privs`, which a
  filter needs.

### The opt-out

B and C both break a caller that sets up a ring before `lock()` on
purpose and keeps using it. Two shapes:

1. **A `Restrictions` member, `IO_URING`.** A bare `lock()` requests it,
   and `LockOptions::restrict(Restrictions::all() - Restrictions::IO_URING)`
   drops it. Without a readable `/proc` the check cannot run, so the
   member is skipped and left out of `Gate::restrictions()`, as an
   unsupported kernel feature is today; `LockOptions::require` makes it
   a hard requirement. The `Restrictions` rustdoc says each member needs
   a Landlock ABI, which would change.
2. **A separate `LockOptions` setting.** Clearer that it is not a
   Landlock feature, but a second way to say what a lock restricts.

## Recommendation

B, as the `Restrictions::IO_URING` member, in the next minor release.
It closes both routes #119 measured, for every ring the process can
see, with no `unsafe` code, and it fails closed with the fix in the
message. 0.6.0 already carries a breaking change
([#117](https://github.com/farming-labs/fsgate/pull/117)), so it can
ship there. C is the next step if the independent review wants the
registered ring closed too.

## Testing

Kernel tests in `tests/lock.rs`, extending #119's:

- A ring with a personality, an `SQPOLL` ring, and an `SQPOLL` ring
  whose descriptor was registered and closed: each makes `lock()` fail
  with the new error, and a raw read outside the grants still succeeds,
  so nothing was applied.
- The control: the same with the member dropped keeps today's behavior,
  and both routes open the file.
- A ring set up after the lock: `lock()` succeeds and the ring's open
  fails with `EACCES`.
- With C: `io_uring_setup` after the lock fails with `ENOSYS`, and the
  registered ring cannot submit.

## Open questions

1. A, B, or C?
2. A `Restrictions` member or a separate `LockOptions` setting?
3. Without `/proc`, skip the check and report it, as proposed, or fail?
4. The variant's name, for example `GateError::IoUringRing { what }`.
