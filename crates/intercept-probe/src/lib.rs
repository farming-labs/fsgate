//! Disposable probe for [RFC 0004](https://github.com/farming-labs/fsgate/blob/main/docs/rfcs/0004-filesystem-interception.md)
//! implementation step 1: prove the startup sequence, supervisor memory
//! access, and atomic descriptor delivery on a real Linux kernel before any
//! launcher is exposed to users.
//!
//! **Not a product.** This crate is unpublished, has no stable API, and is
//! deleted once the interception runtime lands in fsgate behind its own
//! feature. It builds to nothing outside Linux x86_64.
//!
//! What `run` does:
//!
//! 1. Opens the worker image once and checks the RFC's image rule on that
//!    descriptor: a regular, native x86_64 ELF executable with no
//!    `PT_INTERP`, not set-ID, and without file capabilities. Scripts and
//!    dynamically linked binaries are refused before anything is launched.
//!    It then builds a Landlock ruleset that handles every ABI v3
//!    filesystem right and allows only `READ_FILE | EXECUTE` on that image.
//! 2. Forks. Before exec, the child marks every descriptor above stdio
//!    close-on-exec, sets `no_new_privs`, applies the ruleset, installs a
//!    seccomp filter with `NEW_LISTENER` that notifies `open`, `openat`, and
//!    `openat2` (and kills non-x86_64 and x32 calls), sends the listener to
//!    the supervisor, and closes its own copy. It moves the image to a
//!    reserved descriptor (1000), stacks the final allowlist, reports that
//!    both filters are in place, and waits.
//! 3. The supervisor checks the descriptor is a seccomp listener, reads a
//!    known marker back from the now fully restricted child's
//!    `/proc/<pid>/mem`, and only then releases it. The child runs the
//!    checked image with `execveat(1000, "", argv, envp, AT_EMPTY_PATH)`. No
//!    path is resolved again, so replacing the file at the path after the
//!    check changes nothing.
//! 4. For each notification it opens a fresh `/proc/<tid>/mem`, checks the
//!    notification ID after opening and after copying, and copies the path
//!    and `open_how` once into an `fsgate::intercept::OpenRequest`.
//!    `fsgate::Gate::open_intercepted` validates that copy against the RFC's
//!    file-open contract, authorizes it with the strict regular-file open,
//!    and emits one audit event; the supervisor answers with
//!    `SECCOMP_ADDFD_FLAG_SEND` or the errno. It never uses
//!    `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
//!
//! The strict open (fsgate feature `experimental-intercept`) resolves an
//! `O_PATH` handle beneath the grant, refusing every symlink, and reopens
//! that same handle once it is known to be a regular file outside procfs and
//! sysfs. `O_NOFOLLOW`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS`
//! are accepted because that open already enforces them; other resolve
//! flags are refused.
//!
//! The final allowlist is RFC 0004's list: descriptor I/O, memory and
//! runtime, signals, time and identity, and lifecycle syscalls; `fcntl`
//! with the duplicate and flag commands only; `arch_prctl` for the FS and
//! GS bases only; `clone` with thread and fork flags and a termination
//! signal of 0 or `SIGCHLD`; `execveat` on the reserved descriptor with
//! `AT_EMPTY_PATH`; and the open family, which the notification filter
//! sends to the supervisor. Everything else returns `EOPNOTSUPP`, except
//! `clone3`, which returns `ENOSYS` so libc falls back to the checked
//! `clone`. Landlock, not the descriptor number, binds execution to the
//! checked image.
//!
//! Compatibility notes from the static glibc fixture: glibc reads limits
//! with `prlimit64` and `fstat`s with `newfstatat`, neither of which is on
//! the RFC's list, so both return `EOPNOTSUPP` and glibc falls back to its
//! defaults (stdio buffering, thread stack size).
//!
//! Deliberate gaps, each owned by a later RFC 0004 step:
//!
//! - Shutdown, cancellation, and revocation while serving are not handled
//!   yet; the gate moves into the supervisor thread for the worker's life.
//! - `seccompiler` (ADR 0001) cannot express `SECCOMP_RET_USER_NOTIF` or a
//!   per-syscall errno, so both filters are built by hand in `filters.rs`
//!   and checked by a BPF evaluator in its unit tests.
//!
//! Run the tests on Linux x86_64 with a C compiler and static libc
//! (`libc6-dev` on Debian and Ubuntu): `cargo test -p intercept-probe`.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod filters;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod probe;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod sys;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use probe::{Decision, Fault, Outcome, run};
