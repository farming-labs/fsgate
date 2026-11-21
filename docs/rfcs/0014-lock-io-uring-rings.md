# RFC 0014: `io_uring` rings set up before `lock()`

- Status: accepted, tested, and released in [0.6.0](../../CHANGELOG.md#060-2026-11-19). Independent review is pending.
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

Before this change, fsgate documented the risk in the README's limits,
the `Gate::lock` rustdoc, and the threat model (#119).

A ring set up after the lock uses the locked credentials, including its
registered personalities. The tests below verify that ordinary and
`SQPOLL` rings created after locking cannot open outside the grants.

From the kernel source, not separately tested: work handed to `io-wq`
takes the submitter's credentials at that moment (`io_prep_async_work`),
so a worker thread started before the lock does not carry its own
credentials to new submissions.

## Goals

- `lock()` does not report success while the process holds a ring it
  can see that would let later code open files with pre-lock
  credentials.
- It fails closed, before applying anything, with an error that names
  the ring and the fix.
- A process with no detectable ring, readable procfs, and stable threads
  and descriptors keeps working, subject to the name-prefix limit below.
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

Before `restrict_self`, `lock()` reads `/proc/self/task` and each
visible thread's `fd` directory:

- a descriptor whose link reads `anon_inode:[io_uring]` is a ring;
- a thread the kernel marks `PF_IO_WORKER` in its `stat` flags, unless
  it is an io-wq worker named `iou-wrk-<pid>`, is taken for an `SQPOLL`
  thread, which finds a ring whose descriptor was closed after
  registering it.

The kernel sets `PF_IO_WORKER` before the thread is visible. A new
`SQPOLL` thread keeps the name of the thread that set the ring up until
it first runs and names itself `iou-sqp-<pid>`, so through 0.6.0, when
the check went by that name, a ring set up, registered, closed, and
locked straight away could pass it. An internal review at `61cf0dc`
found it. An io-wq worker runs each request with the credentials of
whoever submitted it, and one can stay idle after its rings are closed,
so a worker that has named itself does not refuse the lock; one that
has not run yet does, until it has.

If either exists, `lock()` returns a new `GateError` variant before
anything is applied. The message names the descriptor or thread and
the fix: close the ring before `lock()`, set it up after (where it
holds the locked credentials), or explicitly opt out of the check. `GateError` is
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

Thread names are not an authenticated ring identity: an unrelated thread
with that prefix is conservatively refused, and renaming a polling thread
can hide it. Trusted setup must not hide resources or change them during
the check. The filesystem type of opened directories and files is checked;
a deliberately misleading procfs mount prepared by trusted setup is not
ruled out.

The check needs `/proc`. No new runtime `unsafe` code: `rustix`'s `readlinkat` and
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

### The opt-out and inspection errors

Use a separate `LockOptions::allow_existing_io_uring(bool)` setting,
false by default. `Restrictions` and `Gate::restrictions()` continue to
name kernel-enforced restrictions. A scan of visible resources is a
precondition, not a kernel restriction, and must not be reported as one.

On Linux, both `Strict` and `BestEffort` perform the check unless the
caller explicitly opts out. Missing, inaccessible, or unreadable procfs
fails before applying containment. `BestEffort` still governs only the
Landlock filesystem floor. Non-Linux behavior does not change.

The check inspects each visible thread's descriptors as well as its name,
so a thread with a separate descriptor table is covered. It holds procfs
directory descriptors while walking, verifies that opened entries belong
to procfs, and treats an incomplete scan as a failure. Callers must keep
threads and descriptor tables stable during `lock()`; the check is not
atomic with concurrent ring creation or registration.

`GateError::IoUringPresent { path }` names the descriptor or thread that
caused refusal. `GateError::IoUringInspection { path, source }` names an
inspection failure and retains its I/O cause. Both errors leave the gate
unlocked, `restrictions()` unset, and containment unapplied. Their messages
name the remedy and the explicit opt-out. A failed check emits one denied
`lock` audit event with reason `io_uring`; inspection failures retain an
errno when one exists. Closing a detected ring permits a fresh attempt.

## Decision

On 2026-11-17 the maintainer selected B: reject detectable pre-lock queues
and refuse to proceed when they cannot be inspected. C was not selected;
no new seccomp filter is installed and new rings remain usable after the
lock, subject to the locked credentials. Hidden rings remain a documented
limit. B does not prove that the process holds no pre-lock credentials.

The implementation uses the separate options setting above to preserve
RFC 0006's distinction between kernel restrictions and preconditions.
The maintainer withdrew the proposal to skip the check when procfs is
unavailable and required a minor release with migration notes. Release
approval was a separate decision.

## Testing

Test helpers extend #119's isolated unsafe module and its written safety
contract; the runtime guard uses only safe Rust. Kernel tests in
`tests/lock.rs` cover:

- Ordinary rings, registered personalities, `SQPOLL` rings, and a
  registered `SQPOLL` ring whose descriptor was closed, with its polling
  thread under its own name and under its creator's: both policies
  refuse before containment, leave the gate grantable, and emit one
  denied audit event. An outside read still succeeds after refusal.
  Closing ordinary or personality rings permits a successful retry.
- An idle io-wq worker left after its ring closed: the lock succeeds.
- The explicit opt-out: `allow_existing_io_uring(true)` preserves the
  measured personality and `SQPOLL` bypasses, while a raw outside read
  is denied by the locked credentials.
- New ordinary and `SQPOLL` rings after locking: with and without a
  registered personality, they read inside the grants and receive
  `EACCES` outside them.
- Procfs made unreadable by an outer gate: both policies return an
  inspection error without partial containment. The gate remains
  grantable; the explicit opt-out permits retry.

## Acceptance and verification

- Test ordinary rings, registered personalities, SQPOLL rings, and SQPOLL
  rings registered with their descriptor then closed. Verify each refusal
  occurs before containment by reading a real file outside the grants and
  checking that the gate still accepts grants.
- Test inspection failure against the real filesystem, without supplying
  a mock authorization answer, under both lock policies. Verify that a
  failure has no partial containment or successful lock audit event.
- Test a caller opting out, and a fresh ring created after a successful
  lock, including its inability to open outside the grants. Keep the
  existing pre-lock bypass test as the explicit opt-out control.
- On Linux CI, remove the guard and require its focused regression test
  to fail for the missing refusal, then restore the source.
- Run format, host and Linux lint, and the full suite. Linux execution,
  the packaged crate, MSRV, kernels, and architectures are verified by CI.
- Update the README, threat model, audit contract, changelog, and roadmap
  with the implementation. No independent-review claim.

[CI on `da5cff2`](https://github.com/farming-labs/fsgate/actions/runs/44157981690)
passed all 20 jobs. Each of the three new parent tests passed nine times:
the default, experimental-feature, and unpacked-crate runs in `check`;
both runs under Rust 1.85.0 in `msrv`; `arm64`; and the packaged release
build on Linux 6.6.162, 6.12.117, and 7.3.3. Every refusal run exercised all
four ring modes. The existing opt-out control passed in the same matrix.

In `check`, removing the guard made the focused refusal regression fail
with `a visible ring must prevent locking: FullyEnforced`. The source was
restored before the later passing feature and packaged-crate runs. The
four jobs in the [fuzz run](https://github.com/farming-labs/fsgate/actions/runs/44157981500)
also passed; they are not evidence of detector coverage.

Locally on macOS, `cargo fmt --all --check`, host and Linux cross-target
Clippy with warnings denied, and Linux rustdoc with warnings denied passed.
`cargo test --locked --target-dir /private/tmp/fsgate-deathsig-verify`
passed 137 tests. Linux behavior was executed in CI, not on this host.
Hidden-ring cases and deliberately misleading procfs mounts remain outside
the verified containment claims.
