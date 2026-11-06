# RFC 0004: route ordinary file opens through the broker

- Status: proposed; no interception runtime is implemented
- Date: 2026-11-06
- Roadmap: [M6, after v0.1.0](../../ROADMAP.md#m6--linux-filesystem-interception-experimental)

## Problem

An application currently calls `Gate` or `BrokerGate` to use fsgate's
resolver and audit sink. Linux `lock()` also restricts raw opens, but it
does not route those opens through the broker or emit a fsgate audit
event for each one. The existing broker launcher does not intercept its
child's syscalls or remove the child's ambient filesystem authority.

The proposed outcome is a Linux launcher that mediates a supported
binary's file opens without changing or linking that binary. Kernel
enforcement remains necessary even when a call bypasses interception.

## Scope and dependencies

M6 follows the initial library release (M5) and reuses the M1 resolver,
M2 containment mechanisms, M3 broker authorization, and M4 audit sink.
The first implementation would support read-only regular-file opens
using absolute paths through `open`, `openat`, and `openat2`, where those
syscalls exist on the declared architecture. Unsupported flags, resolve
options, and path forms must fail explicitly. This is a bounded
compatibility target, not support for arbitrary unmodified applications.

Relative paths, worker directory descriptors, writes, creation, metadata,
and directory enumeration need later designs. Linux is the first target;
macOS and Windows interception are outside this proposal. There is no
new kernel module or system-wide policy service in this scope.

## Cited findings

- [libpreopen](https://github.com/musec/libpreopen) provides libc wrappers
  around preopened directory descriptors. It adapts calls in userspace.
- [Seccomp user notifications](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
  can suspend selected syscalls for a supervisor and inject a descriptor
  with `SECCOMP_IOCTL_NOTIF_ADDFD`. The manual explicitly warns against
  using notifications as a security policy: checking mutable target
  memory and then resuming the syscall is race-prone.
- [Landlock](https://docs.kernel.org/userspace-api/landlock.html) enforces
  declared access restrictions in the kernel. Passed file descriptors
  retain their authority; receiving a descriptor is a separate delegation.
- [eBPF LSM programs](https://docs.kernel.org/bpf/prog_lsm.html) attach
  custom programs to Linux Security Module permission hooks. Loading
  them requires privileges and a supporting kernel configuration.

## Proposed design

The candidate is seccomp user notifications with broker-side opens. This
is a proposal to evaluate, not an accepted replacement for
[ADR 0002](../decisions/0002-landlock-not-seccomp-for-paths.md). That
decision still governs `Gate::lock()`: an ordinary seccomp filter cannot
authorize pathname contents. Notifications would carry requests;
held-handle resolution and kernel restrictions would enforce authority.

The proposed request flow is:

1. The launcher opens explicit grants, prepares the supervisor, removes
   unintended inherited descriptors, and establishes worker containment
   before any target code runs. Missing support aborts launch.
2. A supported file-open syscall blocks in the kernel and notifies the
   supervisor. The worker does not call `BrokerGate`.
3. The supervisor copies bounded arguments into its own memory, validates
   them, and authorizes and opens the copied request through the existing
   grant resolver. It never opens the worker's path with ambient authority.
4. The supervisor delivers the descriptor and syscall result using the
   notification API, or returns an error. It never approves a pathname
   and uses `SECCOMP_USER_NOTIF_FLAG_CONTINUE` to execute that open.
5. The existing audit sink records mediated decisions. Ordinary reads of
   an already-delivered descriptor are not new broker decisions.

Reuse broker authorization rather than the JSON socket protocol: an
unmodified worker cannot speak that protocol. Any notification syscall
wrappers requiring `unsafe` need an isolated module and a written safety
contract, as required by the crate's existing policy.

### Authority and lifecycle requirements

- The supervisor is trusted. An injected file descriptor grants access
  independently of the worker's path rules; Landlock does not reauthorize
  each read on it. The broker must enforce every delegated right.
- Direct access outside the mediated subset must remain constrained by
  kernel policy. Classify alternate routes, including `io_uring`, procfs,
  descriptor passing, and alternate syscall ABIs; deny unsupported routes
  that could escape the declared boundary. Do not claim full filesystem
  mediation from interception of the open family alone.
- Notification IDs and target identity must be checked across memory
  access, cancellation, and descriptor delivery. Copy once, then validate
  and use that same copy. An ID check does not freeze target memory.
- Establish restrictions before worker threads exist and preserve them
  across fork and exec. The worker must not inherit the listener or
  broker grant handles. Startup must have a deterministic readiness signal.
- Supervisor failure must prevent new brokered opens. Reap owned workers
  and close owned listeners and pending descriptors on teardown. Closing
  the supervisor does not invalidate descriptors already delivered.
- Revocation denies future brokered opens. It does not revoke existing
  handles or mutate the rules installed by `Gate::lock()`.

### Compatibility decisions required before implementation

Record the minimum kernel features and architecture, the privilege needed
to inspect target memory, the supported flags and errno mapping, and the
bootstrap sequence. In particular, the current `Rights` has no execute
right, so calling the existing `lock()` before `exec` is not a complete
launcher design. Executable and loader access must be explicit and must
not create an unconfined startup window.

Reuse the resolver only where its semantics match. The current `Gate`
normalizes paths lexically and exposes four high-level operations; that
alone does not preserve every syscall's symlink, flag, or error behavior.
Resolve those differences or reject the affected input. Do not silently
weaken `openat2` resolve options or broaden grants to make a binary run.

## Alternatives

- **Landlock alone:** retain it for direct enforcement. It does not route
  opens through fsgate's broker or its audit sink.
- **Preload wrappers like libpreopen:** useful for libc compatibility,
  but calls that bypass those wrappers need independent containment.
  A preload shim remains outside the first implementation.
- **eBPF LSM hooks:** the option for custom in-kernel permission checks
  and events. Privileged deployment and kernel configuration make this
  a separate backend proposal; it does not supply broker-open emulation.
- **Continue after inspecting the worker's path:** rejected because the
  worker can change arguments before the kernel uses them.

## Rollout and verification

First settle the authority and compatibility decisions above. Then build
an opt-in experiment, disabled by default, with no interception dependency
or startup work in ordinary library use. No release version is assigned.
Selecting interception must never fall back to unsandboxed execution.

Verify with standalone binaries that do not link fsgate, using libc calls
and raw syscalls. Run a release build and the unpacked crate on the
declared Linux kernels and architectures. Tests must cover:

- Granted reads with exact byte checks; denied outside reads; attempted
  creation and truncation with independent checks that no file was
  created and existing contents are unchanged.
- Symlink and rename races, `..`, mutable argument memory, unsupported
  flags and resolve options, and attempts to obtain directory authority.
- Every alternate route identified in the bypass analysis, plus thread,
  fork, and exec inheritance and rejection of unsupported syscall ABIs.
- Supervisor death, signal interruption, worker exit, descriptor cleanup,
  revocation before the next request, and auditable mediated denials.
- Missing kernel features and unsupported hosts: the target must not run.

Use explicit synchronization rather than sleeps. Keep prototype evidence,
passing tests, independent review, and release status separate. Expansion
beyond the initial subset needs its own compatibility tests and docs.

## Open questions

- Which kernel baseline, architecture, and target-memory mechanism meet
  the containment requirements without requiring a privileged service?
- How will executable and loader authority be represented and bounded?
- Which exact flag and path semantics can reuse the current resolver?
- What experimental launcher interface and notification bindings fit the
  existing CLI and dependency policy?
