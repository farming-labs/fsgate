# RFC 0004: route ordinary file opens through the broker

- Status: accepted ([#4](https://github.com/farming-labs/fsgate/pull/4)); implemented experimentally behind the `experimental-intercept` feature and tested in CI on the declared kernels; not independently reviewed or released
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
The first implementation targets Linux x86_64 native syscalls and static
ELF binaries, on Linux 6.6 and later. CI tests that baseline (6.6.162)
and a current stable kernel (7.3.3), both booted in a VM, and the GitHub
runner's kernel; other versions are not tested individually. It supports
read-only regular-file opens using absolute paths through `open`,
`openat`, and `openat2`. Unsupported flags, resolve options, and path
forms fail explicitly. This is a bounded compatibility target; dynamic
executables, scripts, x32, i386 compatibility mode, and other architectures
need separate profiles and verification.

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

Use seccomp user notifications with broker-side opens for the prototype.
This proposed profile does not replace
[ADR 0002](../decisions/0002-landlock-not-seccomp-for-paths.md). That
decision still governs `Gate::lock()`: an ordinary seccomp filter cannot
authorize pathname contents. Notifications would carry requests;
held-handle resolution and kernel restrictions enforce authority. Keep
Landlock ABI v3 as the minimum, require notification descriptor delivery
with `SECCOMP_ADDFD_FLAG_SEND`, and probe the actual features. A kernel
version string alone is not evidence that either facility is enabled.

The supervisor runs as the launching user, without a root service or new
capabilities. It requires access to the worker's procfs memory file;
policy that prevents this access causes startup to fail. Do not disable
host ptrace restrictions or elevate privileges to make the profile work.

The proposed request flow is:

1. The launcher opens explicit grants, prepares the supervisor, removes
   unintended inherited descriptors, and establishes worker containment
   before any target code runs. Missing support aborts launch.
2. A supported file-open syscall blocks in the kernel and notifies the
   supervisor. The worker does not call `BrokerGate`.
3. The supervisor copies bounded arguments into its own memory, validates
   them, and authorizes and opens the copied request through the existing
   grant resolver. It never opens the worker's path with ambient authority.
4. The supervisor delivers the descriptor and syscall result atomically
   with `SECCOMP_ADDFD_FLAG_SEND`, or returns an error. It never approves
   a pathname and uses `SECCOMP_USER_NOTIF_FLAG_CONTINUE` to execute that open.
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

### Bootstrap authority

The current `Rights` has no execute right. Keep the public grant API
unchanged: executable authority is a private launcher input, separate
from the broker's data grants. The proposed worker Landlock ruleset handles
all ABI v3 filesystem rights and permits only `READ_FILE | EXECUTE` on
the held executable file. It grants no direct data-directory access.
The supervisor's data grants never become worker Landlock rules.

The selected image must be a regular native x86_64 ELF executable with no
`PT_INTERP` entry. Reject scripts, set-ID images, and file capabilities.
Inspect and execute the same held file, without resolving its path again.
There is no loader-directory grant. A changed image requiring an interpreter
must fail under the installed rules, not trigger a wider startup grant.

Startup is an ordered protocol between trusted launcher code and the
supervisor:

1. Preflight the required Landlock ABI, seccomp notification operations,
   procfs access, and descriptor injection in a disposable trusted child.
   Open data grants only in the supervisor and pin its procfs handles,
   verifying the filesystem type and the supervisor's PID-namespace view.
2. Fork a single-threaded launcher child. Replace standard input/output/
   error with dedicated pipes, so a terminal, socket, or writable file is
   not inherited accidentally. Close every other inherited descriptor
   except the executable and startup control channels. Move the executable
   to a reserved descriptor number before generating the final filter.
3. Set `no_new_privs` and install the worker Landlock ruleset. Install a
   notification filter for the open family with `NEW_LISTENER`, send the
   listener to the supervisor, then close the child's copy and transport.
4. Stack the final syscall allowlist described below. It returns `ALLOW`
   for the open family so the earlier notification filter handles them;
   it must not return `USER_NOTIF` without its own listener. From here,
   further `seccomp` and `prctl` calls are denied.
5. Signal readiness only after both restrictions are installed. The
   supervisor verifies a bounded memory read from this restricted child,
   confirms that it owns the listener, then releases the startup barrier.
   EOF or any setup error aborts and reaps the child.
6. Execute with `execveat(exec_fd, "", argv, envp, AT_EMPTY_PATH)`. Set
   `FD_CLOEXEC` on the image and remaining control descriptors. No target
   instruction runs before containment. Failed exec terminates the child.

The final filter allows `execveat` only with the reserved image descriptor
number and `AT_EMPTY_PATH`; it denies `execve`. Descriptor-number matching
is not the execute boundary: the Landlock rule binds execution to the
selected object even if that number is later reused or an absolute path
is supplied. Tests must try both attacks. No `CONTINUE` response is needed
for startup execution. Forked children inherit the filters and rules.

### File-open contract

This profile deliberately supports fewer inputs than POSIX. Document the
restriction at launch and return the following errors; never normalize an
unsupported request into an allowed one.

| Input | Prototype behavior |
| --- | --- |
| Path | Absolute UTF-8, at most 4096 bytes including NUL. Reject `.` / `..`, repeated separators, and trailing separators with `EOPNOTSUPP` before calling the existing lexical normalizer. |
| Invalid memory, missing terminator, invalid UTF-8 | `EFAULT`, `ENAMETOOLONG`, and `EILSEQ`, respectively; an empty path returns `ENOENT`. |
| `open` / `openat` flags | `O_RDONLY`, optionally `O_CLOEXEC`, `O_NOFOLLOW`, or `O_LARGEFILE`. Unsupported bits, including create, truncate, write, and directory/path-only opens, return `EOPNOTSUPP`. |
| `openat` directory argument | Ignored for accepted absolute paths; never interpreted as a supervisor descriptor. Relative paths return `EOPNOTSUPP`. |
| `openat2` structure | Accept the 24-byte `open_how` layout only; other sizes return `EOPNOTSUPP`. Require `mode = 0`, otherwise `EINVAL`. |
| `openat2` resolve flags | Accept zero or a combination of `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_MAGICLINKS`. Reject all other options with `EOPNOTSUPP`; do not drop their semantics. |
| Symlinks | Reject every symlink in the path with `ELOOP`, including symlinks within a grant. This is stricter than ordinary `open`. |
| Missing grant or read right | `EACCES`; audit the existing `NoGrant` or `RightsExceeded` decision. |
| Object type | Return `EISDIR` for directories and `EOPNOTSUPP` for other non-regular files or procfs/sysfs objects. |
| Filesystem or delivery error | Preserve the OS errno where a response is still possible; never retry using ambient access. |

Use the existing grant selection, rights checks, and audit delivery. Add
an internal operation for this profile rather than changing public
`Gate::open` semantics. After routing, resolve the remainder with
`openat2(O_PATH | O_CLOEXEC, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS)` relative to the held grant. Inspect the resulting
handle with `fstat` and `fstatfs` before opening it for I/O.

For an accepted regular file, reopen that exact handle read-only through
the supervisor's pinned `/proc/self/fd` directory. The decimal descriptor
name is generated internally; it is never a worker-supplied path. Keep the
owned `O_PATH` handle alive through reopening and verify the resulting
file identity. Do not reopen the original pathname after checking its
type: that would allow replacement with a device or FIFO. None of these
supervisor control handles are delivered to the worker.

### Memory, delivery, and audit

Read arguments from a fresh `/proc/<tid>/mem` handle for each notification,
using the TID supplied by the kernel. Validate the notification ID after
opening the memory handle and again after copying. Bound pathname reads
by pages and the path limit; copy `open_how` once into owned memory.
Never reopen a PID pathname after validating it and assume it identifies
the same request. A cancelled request releases every local handle.

An argument copy may race with worker memory changes. Validate and use
only the resulting local bytes, so any observed request still needs a
grant. Neither repeated reads nor an ID check make worker memory immutable.
If the target becomes unreadable after launch, deny the request without
changing host policy.

Use `SECCOMP_ADDFD_FLAG_SEND` without `SETFD` so allocation and the reply
are atomic. Preserve the caller's `O_CLOEXEC` choice in `newfd_flags` while
all supervisor-owned handles remain close-on-exec. If delivery fails,
close the local file and respond only while the notification remains
valid. Do not install a descriptor and send success as separate steps.

Serialize grant revocation with authorization and delivery: a revoke
acknowledgement follows any earlier in-flight request, and later requests
recheck the current grants. Delivered descriptors keep their authority.
Loss of the last listener makes future notified calls fail in the kernel;
do not claim that this also closes previously delivered descriptors.

The dispatcher needs reasons for unsupported input and invalid memory,
plus optional syscall and notification IDs. Emit one decision for each
notified request, including refusals before grant selection. Use
`path = null` when no valid path was copied. A filter-only refusal is not
a broker audit event, and a restarted syscall can create a new notification.
These wire additions require an RFC 0002 update, now made: the reasons
`unsupported_input` and `invalid_memory`, and the keys `syscall` and
`notification`. The Rust event struct
and the operation and reason enums are non-exhaustive (see
[RFC 0002](0002-audit-events.md#rust-compatibility)), so the new reasons
and optional fields are additive for Rust callers.

### Syscall boundary and bypass analysis

The final filter checks `AUDIT_ARCH_X86_64`, rejects the x32 syscall bit,
and kills unsupported ABI invocations. All unlisted native syscalls return
`EOPNOTSUPP`. The runtime allowlist starts with these explicit groups;
adding a syscall requires a compatibility test and a boundary review.

- Descriptor I/O: `read`, `write`, `readv`, `writev`, `pread64`, `pwrite64`,
  `close`, `lseek`, `fstat`, `dup`, `dup2`, `dup3`, `poll`, `ppoll`, `select`,
  and `pselect6`. Read-only injected handles cannot be written through.
- Memory/runtime: `mmap`, `mprotect`, `munmap`, `mremap`, `madvise`, `brk`,
  `futex`, `sched_yield`, `sched_getaffinity`, `set_tid_address`,
  `set_robust_list`, `rseq`, and `arch_prctl` restricted to setting/getting
  FS/GS bases. `fcntl` permits only descriptor duplication, `GETFD`,
  `SETFD`, and `GETFL`; other commands are refused.
- Signals/time/identity: `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`,
  `sigaltstack`, `nanosleep`, `clock_nanosleep`, `clock_gettime`,
  `gettimeofday`, `getrandom`, `getpid`, `getppid`, `gettid`, `getuid`,
  `geteuid`, `getgid`, `getegid`, `uname`, and `getrlimit`.
- Lifecycle: `exit`, `exit_group`, `wait4`, `waitid`, `fork`, and `vfork`.
  Native `clone` permits only `CLONE_VM`, `CLONE_FS`, `CLONE_FILES`,
  `CLONE_SIGHAND`, `CLONE_THREAD`, `CLONE_SYSVSEM`, `CLONE_SETTLS`,
  `CLONE_PARENT_SETTID`, `CLONE_CHILD_SETTID`, `CLONE_CHILD_CLEARTID`, and
  `CLONE_VFORK`, with termination signal zero or `SIGCHLD`. Other bits
  are refused. Kernel validation still applies to flag combinations.
- Mediated/bootstrap: the three open syscalls pass to the notification
  filter; `execveat` has the bootstrap restrictions above.

| Alternate route | Boundary in this profile |
| --- | --- |
| Direct syscalls, fork, threads, exec | Filters and Landlock precede target execution and remain inherited. Test descendants using raw syscalls. |
| `io_uring`, `open_by_handle_at`, new or unlisted syscalls | Refused by the allowlist; no path operation can silently take an unmediated compatibility route. |
| Unix sockets and `SCM_RIGHTS`, `pidfd_getfd` | No inherited socket; socket creation, descriptor receipt, and cross-process descriptor duplication are refused. |
| Procfs magic links and pseudo-files | Reject symlinks and procfs/sysfs data objects; supervisor procfs use is separate trusted control I/O. |
| Path metadata, enumeration, mutation, mounts | Corresponding syscalls are not on the allowlist. Landlock adds direct filesystem restrictions; it is not claimed to hide metadata by itself. |
| `ptrace`, `process_vm_*`, privilege changes, namespaces, new filters | Refused, including `clone3`, namespace clone bits, `seccomp`, and `prctl` after bootstrap. |
| Inherited descriptors and writable mappings | Only explicit pipe endpoints survive startup. Exec removes launcher mappings; brokered regular files are read-only. |
| Supervisor exit | The child has closed its listener copy, so no stale listener keeps future opens waiting for a nonexistent supervisor. Previously granted handles remain valid. |

The [threat model](../threat-model.md#4-the-experimental-launcher-linux-x86_64)
maps these routes to the tests that cover them.

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

Accepting this profile completes the first design task in M6; it is not
Linux execution evidence or independent review. The remaining M6 tasks
stay unchecked until their own acceptance criteria and merge evidence
are recorded.

Implement behind an optional Cargo feature, disabled by default, with no
interception dependency or startup work in ordinary library use. Reuse
the existing broker binary with an explicit experimental mode, keeping
the socket protocol mode unchanged. The experimental mode must show its
profile and grants before an explicit `--apply` starts the worker. No
release version is assigned. Selecting interception must never fall back
to unsandboxed execution.

Use the existing `seccompiler` decision for filter construction and safe
`rustix` operations where available. As of `seccompiler` 0.5.0 it cannot
express `SECCOMP_RET_USER_NOTIF` or install a filter with
`SECCOMP_FILTER_FLAG_NEW_LISTENER`, so the step 1 probe wrote its
notification filter by hand; settle the filter builder before the launcher.
The allowlist needs a per-syscall errno as well (`ENOSYS` for `clone3`, so
libc falls back to the checked `clone`), which `seccompiler` cannot express
either, so the launcher (`fsgate::intercept`, formerly the probe) builds
both filters itself and checks them with a BPF evaluator in its unit tests. Static glibc reads limits with `prlimit64` and
`fstat`s with `newfstatat`, which are not on the list above; both fail with
`EOPNOTSUPP` and glibc falls back to its defaults. The profile's strict `O_PATH` resolver
is a deliberate extension of ADR 0001: the current public cap-std open
cannot reject special objects before opening them for I/O. Keep routing
and rights checks shared; do not replace the existing cap-std operations.
Resolve binding versions at
implementation time. Isolate any required notification or fork/exec
`unsafe` wrappers, including ownership and post-fork allocation contracts.
Do not add dependencies in this documentation change.

Verify with standalone binaries that do not link fsgate, using libc calls
and raw syscalls. Run a release build and the unpacked crate on the
declared Linux kernels and architectures. CI's `kernels` job does this: it
builds the packaged crate's tests with `--release`, boots each declared
kernel under virtme-ng, and runs them there, then boots it again with
`lsm=capability` to run the tests for a kernel without Landlock. Tests
must cover:

- Granted reads with exact byte checks; denied outside reads; attempted
  creation and truncation with independent checks that no file was
  created and existing contents are unchanged.
- Symlink and rename races, `..`, mutable argument memory, unsupported
  flags and resolve options, and attempts to obtain directory authority.
- Every alternate route identified in the bypass analysis, plus thread,
  fork, and exec inheritance and rejection of unsupported syscall ABIs.
- Supervisor death, signal interruption, worker exit, descriptor cleanup,
  revocation before the next request, and auditable mediated denials.
- Missing kernel features, denied procfs access, unsupported hosts or
  images, and every failed startup transition: a target-side marker must
  remain absent. Check executable descriptor reuse and absolute-path
  substitution against the execute rule, and inspect inherited handles.
- Special-file substitution between resolution and reopening: the broker
  must never open the replacement for I/O or block on a FIFO.

Use explicit synchronization rather than sleeps. Keep prototype evidence,
passing tests, independent review, and release status separate. Expansion
beyond the initial subset needs its own compatibility tests and docs.

## Implementation order

1. Build a disposable Linux probe for the exact startup sequence,
   supervisor memory access, and atomic descriptor delivery. It must
   prove the expected denials before a launcher is exposed to users.
2. Add the internal regular-file resolver operation, its real-filesystem
   race tests, argument validation, and the audited request dispatcher.
3. Integrate the experimental launcher, startup plan, cleanup, and
   descendant tests. Document the exact supported static fixtures.
4. Run the release and unpacked-crate tests from M6. Broader flags,
   symlinks, interpreters, and architectures require separate changes.

## Sources for the prototype profile

- [Landlock ABI table](https://man7.org/linux/man-pages/man7/landlock.7.html):
  ABI v3 includes truncation restrictions and predates the selected test baseline.
- [Seccomp filters](https://man7.org/linux/man-pages/man2/seccomp.2.html):
  filter composition, inheritance, architecture checks, and syscall allowlists.
- [Descriptor execution](https://man7.org/linux/man-pages/man2/execveat.2.html):
  `AT_EMPTY_PATH` executes a held file; scripts have additional descriptor requirements.
- [Open flags](https://man7.org/linux/man-pages/man2/open.2.html) and
  [openat2 resolution](https://man7.org/linux/man-pages/man2/openat2.2.html):
  `O_PATH` permits inspecting an object without opening it for I/O.
- [Procfs memory](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html)
  and [descriptor entries](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html):
  supervisor access remains subject to host permission checks.

The profile, rejection choices, and startup protocol are design decisions
derived from these interfaces. They have not been validated on a Linux
runtime in this follow-up.
