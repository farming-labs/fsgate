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
//! 1. Opens the worker image `O_PATH` and builds a Landlock ruleset that
//!    handles every ABI v3 filesystem right and allows only `READ_FILE |
//!    EXECUTE` on that image.
//! 2. Forks. Before exec, the child marks every descriptor above stdio
//!    close-on-exec, sets `no_new_privs`, applies the ruleset, installs a
//!    seccomp filter with `NEW_LISTENER` that notifies `open`, `openat`, and
//!    `openat2` (and kills non-x86_64 and x32 calls), sends the listener to
//!    the supervisor, closes its own copy, and waits.
//! 3. The supervisor checks the descriptor is a seccomp listener, reads a
//!    known marker back from the child's `/proc/<pid>/mem`, and only then
//!    releases the child to exec.
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
//! Deliberate gaps, each owned by a later RFC 0004 step:
//!
//! - Exec is by path through `std::process::Command`, not `execveat` on the
//!   held image, and there is no final syscall allowlist yet. Landlock still
//!   denies the worker every direct file access except its own image.
//! - `seccompiler` (ADR 0001) cannot express `SECCOMP_RET_USER_NOTIF` or
//!   `SECCOMP_FILTER_FLAG_NEW_LISTENER` as of 0.5.0, so the 11-instruction
//!   filter is written by hand.
//!
//! Run the tests on Linux x86_64 with a C compiler and static libc
//! (`libc6-dev` on Debian and Ubuntu): `cargo test -p intercept-probe`.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod probe;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod sys;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use probe::{Decision, Fault, Outcome, run};
