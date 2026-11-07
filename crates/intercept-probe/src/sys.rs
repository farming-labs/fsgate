//! Raw Linux interfaces for the probe: seccomp user notifications, the
//! Landlock ruleset syscalls, and the setup that runs in the forked child
//! before exec.
//!
//! # Safety contract
//!
//! This is the only module in the crate that uses `unsafe`. It keeps these
//! rules:
//!
//! - **Ownership.** A descriptor returned by a syscall is wrapped in an
//!   [`OwnedFd`] at once, or, in the child, closed before the child execs.
//!   Nothing here closes a descriptor it does not own.
//! - **Kernel structs.** Structs passed to `ioctl`, `seccomp`, and the
//!   Landlock syscalls are the x86_64 Linux layouts (`libc`'s, or the
//!   `repr(C)` copies below), zero-initialized where the kernel requires it
//!   (`SECCOMP_IOCTL_NOTIF_RECV` rejects a non-zero buffer), and outlive the
//!   call that reads or writes them.
//! - **Post-fork code.** [`install_child_setup`] registers a closure that
//!   runs in a child forked from a multi-threaded process, before exec. It
//!   only makes raw syscalls on stack memory and on data captured before the
//!   fork: no allocation, no locks, no std I/O, and no panicking operations.
//!   Errors are `io::Error`s built from an errno, which do not allocate.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::ptr;

use libc::{c_long, c_ulong};

/// Byte the supervisor writes to release the startup barrier.
pub(crate) const READY_BYTE: u8 = b'1';

/// `struct landlock_ruleset_attr` for ABI v1–v3, which has only this field.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr`, which the kernel declares packed.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
/// Every filesystem right Landlock ABI v3 defines, `EXECUTE` through
/// `TRUNCATE`.
const ACCESS_FS_V3: u64 = (1 << 15) - 1;

/// Control-buffer size for one `SCM_RIGHTS` descriptor.
// SAFETY: CMSG_SPACE only computes a size from its argument.
const CONTROL_SPACE: usize = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
const _: () = assert!(CONTROL_SPACE <= size_of::<[u64; 4]>());

fn check(ret: c_long) -> io::Result<c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// The Landlock ABI version the kernel supports.
pub(crate) fn landlock_abi() -> io::Result<c_long> {
    // SAFETY: with a null attribute, zero size, and the VERSION flag, the
    // kernel reads no memory and returns the ABI version.
    check(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    })
}

/// A ruleset that handles every ABI v3 filesystem right and allows only
/// `READ_FILE | EXECUTE` on `executable`: the worker may run its own image
/// and nothing else.
pub(crate) fn executable_ruleset(executable: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let attr = RulesetAttr {
        handled_access_fs: ACCESS_FS_V3,
    };
    // SAFETY: `attr` is a valid ruleset attribute of the size passed, and it
    // outlives the call.
    let fd = check(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            size_of::<RulesetAttr>(),
            0u32,
        )
    })?;
    // SAFETY: the syscall returned a new descriptor that nothing else owns.
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let rule = PathBeneathAttr {
        allowed_access: ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE,
        parent_fd: executable.as_raw_fd(),
    };
    // SAFETY: `rule` is a valid path-beneath attribute; `ruleset` and
    // `executable` are open descriptors; all three outlive the call.
    check(unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &rule as *const PathBeneathAttr,
            0u32,
        )
    })?;
    Ok(ruleset)
}

/// Fails unless the kernel offers the `SECCOMP_RET_USER_NOTIF` action.
pub(crate) fn user_notif_available() -> io::Result<()> {
    let action: u32 = libc::SECCOMP_RET_USER_NOTIF;
    // SAFETY: SECCOMP_GET_ACTION_AVAIL reads one u32 through a pointer that
    // is valid for the call.
    check(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_ACTION_AVAIL,
            0u32,
            &action as *const u32,
        )
    })
    .map(drop)
}

/// Receives one pending notification.
pub(crate) fn notif_recv(listener: BorrowedFd<'_>) -> io::Result<libc::seccomp_notif> {
    // SAFETY: seccomp_notif is plain integers, so all-zero is a valid value,
    // and the kernel requires a zeroed buffer.
    let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // SAFETY: `notif` is a writable seccomp_notif that outlives the call.
    check(unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_RECV,
            &mut notif as *mut libc::seccomp_notif,
        )
    } as c_long)?;
    Ok(notif)
}

/// Whether notification `id` is still pending: its target has not died
/// and its syscall has not been interrupted.
pub(crate) fn notif_id_valid(listener: BorrowedFd<'_>, id: u64) -> bool {
    // SAFETY: the kernel reads one u64 through a pointer valid for the call.
    unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
            &id as *const u64,
        ) == 0
    }
}

/// Completes notification `id` with `-errno`.
pub(crate) fn notif_send_error(listener: BorrowedFd<'_>, id: u64, errno: i32) -> io::Result<()> {
    let response = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    // SAFETY: `response` is a valid seccomp_notif_resp that outlives the call.
    check(unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_SEND,
            &response as *const libc::seccomp_notif_resp,
        )
    } as c_long)
    .map(drop)
}

/// Installs a copy of `file` in the target and completes notification
/// `id` with the new descriptor number, in one step
/// (`SECCOMP_ADDFD_FLAG_SEND`). Returns the number the target received.
pub(crate) fn notif_addfd_send(
    listener: BorrowedFd<'_>,
    id: u64,
    file: BorrowedFd<'_>,
    cloexec: bool,
) -> io::Result<RawFd> {
    let addfd = libc::seccomp_notif_addfd {
        id,
        flags: libc::SECCOMP_ADDFD_FLAG_SEND as u32,
        srcfd: file.as_raw_fd() as u32,
        newfd: 0,
        newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
    };
    // SAFETY: `addfd` is a valid seccomp_notif_addfd naming an open
    // descriptor, and it outlives the call.
    check(unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ADDFD,
            &addfd as *const libc::seccomp_notif_addfd,
        )
    } as c_long)
    .map(|fd| fd as RawFd)
}

/// What the forked child needs before exec. The descriptors must stay open
/// in the parent until `Command::spawn` returns.
pub(crate) struct ChildSetup {
    /// The worker's Landlock ruleset.
    pub(crate) ruleset: RawFd,
    /// The child's end of the startup socket.
    pub(crate) socket: RawFd,
    /// The notification filter program.
    pub(crate) filter: Vec<libc::sock_filter>,
}

/// Registers the startup sequence to run in the child between fork and
/// exec: close-on-exec for every inherited descriptor above stdio,
/// `no_new_privs`, Landlock, the notification filter, handing the listener
/// to the supervisor, and waiting for the supervisor's release.
pub(crate) fn install_child_setup(command: &mut Command, setup: ChildSetup) {
    let ChildSetup {
        ruleset,
        socket,
        filter,
    } = setup;
    let child = move || child_setup(ruleset, socket, &filter);
    // SAFETY: `child_setup` keeps the post-fork rules in the module contract,
    // and the caller keeps both descriptors open until `spawn` returns.
    unsafe {
        command.pre_exec(child);
    }
}

fn child_setup(ruleset: RawFd, socket: RawFd, filter: &[libc::sock_filter]) -> io::Result<()> {
    // Only stdio survives exec. The setup descriptors stay usable until then.
    // SAFETY: close_range takes integers only.
    check(unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    })?;
    // The kernel reads these as `unsigned long` and rejects stray upper
    // bits, so they are passed at full width through the variadic call.
    // SAFETY: prctl with integer arguments only.
    check(unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as c_ulong,
            0 as c_ulong,
            0 as c_ulong,
            0 as c_ulong,
        )
    } as c_long)?;
    // SAFETY: integers only; `ruleset` was inherited across fork and is open.
    check(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) })?;

    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: `program` points at `filter`, which outlives the call; the
    // kernel copies the program and only reads it.
    let listener = check(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &program as *const libc::sock_fprog,
        )
    })? as RawFd;

    let sent = send_listener(socket, listener);
    // The supervisor holds its own copy now; the worker must not inherit one.
    // SAFETY: `listener` was created above and is owned here.
    unsafe {
        libc::close(listener);
    }
    sent?;

    let mut byte = 0u8;
    // SAFETY: reads at most one byte into a local.
    let read = unsafe { libc::read(socket, (&raw mut byte).cast(), 1) };
    if read != 1 || byte != READY_BYTE {
        return Err(io::Error::from_raw_os_error(libc::ECANCELED));
    }
    Ok(())
}

/// Sends `listener` over `socket` with this process's PID as the payload.
fn send_listener(socket: RawFd, listener: RawFd) -> io::Result<()> {
    // SAFETY: getpid takes no arguments and cannot fail.
    let mut payload = unsafe { libc::getpid() }.to_le_bytes();
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // u64 elements keep the control buffer aligned for `cmsghdr`.
    let mut control = [0u64; 4];
    // SAFETY: msghdr is plain data; all-zero is a valid value.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = CONTROL_SPACE;
    // SAFETY: the control buffer has room for one header carrying one
    // descriptor, so CMSG_FIRSTHDR is non-null and every write below stays
    // inside `control`.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        libc::CMSG_DATA(header)
            .cast::<RawFd>()
            .write_unaligned(listener);
    }
    // SAFETY: `message` and everything it points to are live locals.
    let sent = check(unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) } as c_long)?;
    if sent as usize != payload.len() {
        return Err(io::Error::from_raw_os_error(libc::EPROTO));
    }
    Ok(())
}
