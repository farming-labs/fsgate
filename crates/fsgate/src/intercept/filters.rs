//! The two seccomp filters the worker runs under, as classic BPF.
//!
//! [`notify_filter`] goes first and sends the open family to the
//! supervisor. [`final_allowlist`] is stacked last (RFC 0004, "Syscall
//! boundary and bypass analysis") and decides everything else. With stacked
//! filters the kernel takes the strictest result, so the open family, which
//! the allowlist allows, still reaches the supervisor through the
//! notification filter.
//!
//! `seccompiler` (ADR 0001) can express neither `SECCOMP_RET_USER_NOTIF`
//! nor a per-syscall errno, which the allowlist needs for `clone3`, so both
//! programs are built here. Every jump is short and forward, and the unit
//! tests below run both programs through a small evaluator.

use std::os::fd::RawFd;

use libc::sock_filter;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_JSET_K: u16 = 0x45;
const BPF_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;

/// Offsets into `struct seccomp_data`. Arguments are 64-bit; every check
/// here reads the low word only, because each checked argument is an `int`
/// or, for `clone`, the kernel reads only the low 32 bits of the flags.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const fn arg_low(index: u32) -> u32 {
    16 + 8 * index
}

const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const NOTIFY: u32 = libc::SECCOMP_RET_USER_NOTIF;
const fn errno(errno: i32) -> u32 {
    libc::SECCOMP_RET_ERRNO | (errno as u32 & 0xffff)
}
/// What every syscall not on the allowlist returns.
const REFUSE: u32 = errno(libc::EOPNOTSUPP);

/// The descriptor number the child moves the worker image to before the
/// allowlist is built around it. Below the usual 1024 soft limit; if it is
/// unavailable, startup fails rather than guessing.
pub(crate) const RESERVED_IMAGE_FD: RawFd = 1000;

const ARCH_SET_GS: u32 = 0x1001;
const ARCH_SET_FS: u32 = 0x1002;
const ARCH_GET_FS: u32 = 0x1003;
const ARCH_GET_GS: u32 = 0x1004;

/// `clone` flags a thread or a plain fork needs. Anything else, including
/// every namespace flag, is refused.
const CLONE_ALLOWED: u32 = (libc::CLONE_VM
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD
    | libc::CLONE_SYSVSEM
    | libc::CLONE_SETTLS
    | libc::CLONE_PARENT_SETTID
    | libc::CLONE_CHILD_SETTID
    | libc::CLONE_CHILD_CLEARTID
    | libc::CLONE_VFORK) as u32;
const CSIGNAL: u32 = libc::CSIGNAL as u32;

/// Allowed without argument checks: descriptor I/O, memory and runtime,
/// signals, time and identity, lifecycle, and the open family (which the
/// notification filter sends to the supervisor).
const ALLOWED: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_close,
    libc::SYS_lseek,
    libc::SYS_fstat,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_select,
    libc::SYS_pselect6,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_clock_gettime,
    libc::SYS_gettimeofday,
    libc::SYS_getrandom,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_gettid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_uname,
    libc::SYS_getrlimit,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_openat2,
];

fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Kills anything that is not a native x86_64 syscall, x32 included, and
/// leaves the syscall number in the accumulator.
fn native_x86_64_only(program: &mut Vec<sock_filter>) {
    program.extend([
        stmt(BPF_LD_W_ABS, DATA_ARCH),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, KILL),
        stmt(BPF_LD_W_ABS, DATA_NR),
        jump(BPF_JGE_K, X32_SYSCALL_BIT, 0, 1),
        stmt(BPF_RET_K, KILL),
    ]);
}

/// The notification filter: native x86_64 only, the three open syscalls go
/// to the supervisor, and everything else is left to the allowlist.
pub(crate) fn notify_filter() -> Vec<sock_filter> {
    let mut program = Vec::new();
    native_x86_64_only(&mut program);
    program.extend([
        jump(BPF_JEQ_K, libc::SYS_open as u32, 3, 0),
        jump(BPF_JEQ_K, libc::SYS_openat as u32, 2, 0),
        jump(BPF_JEQ_K, libc::SYS_openat2 as u32, 1, 0),
        stmt(BPF_RET_K, ALLOW),
        stmt(BPF_RET_K, NOTIFY),
    ]);
    program
}

/// Appends a block that, for syscall `nr`, allows the call only when the
/// low word of the argument at `offset` is one of `values`, and refuses it
/// otherwise. Other syscalls skip the block with the number still loaded.
fn one_of(program: &mut Vec<sock_filter>, nr: libc::c_long, offset: u32, values: &[u32]) {
    let count = values.len();
    // LD, one JEQ per value, RET ALLOW, RET REFUSE.
    let block = count + 3;
    program.push(jump(BPF_JEQ_K, nr as u32, 0, block as u8));
    program.push(stmt(BPF_LD_W_ABS, offset));
    for (index, &value) in values.iter().enumerate() {
        let remaining = (count - 1 - index) as u8;
        let last = index + 1 == count;
        program.push(jump(BPF_JEQ_K, value, remaining, u8::from(last)));
    }
    program.push(stmt(BPF_RET_K, ALLOW));
    program.push(stmt(BPF_RET_K, REFUSE));
}

/// The final allowlist, built around the image at `image_fd`.
pub(crate) fn final_allowlist(image_fd: RawFd) -> Vec<sock_filter> {
    let mut program = Vec::new();
    native_x86_64_only(&mut program);
    for &nr in ALLOWED {
        program.push(jump(BPF_JEQ_K, nr as u32, 0, 1));
        program.push(stmt(BPF_RET_K, ALLOW));
    }
    // `ENOSYS`, not `EOPNOTSUPP`: libc falls back to `clone`, checked below.
    program.push(jump(BPF_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
    program.push(stmt(BPF_RET_K, errno(libc::ENOSYS)));

    one_of(
        &mut program,
        libc::SYS_fcntl,
        arg_low(1),
        &[
            libc::F_DUPFD as u32,
            libc::F_DUPFD_CLOEXEC as u32,
            libc::F_GETFD as u32,
            libc::F_SETFD as u32,
            libc::F_GETFL as u32,
        ],
    );
    one_of(
        &mut program,
        libc::SYS_arch_prctl,
        arg_low(0),
        &[ARCH_SET_GS, ARCH_SET_FS, ARCH_GET_FS, ARCH_GET_GS],
    );

    // clone: only allowed flags, and a termination signal of 0 or SIGCHLD.
    program.extend([
        jump(BPF_JEQ_K, libc::SYS_clone as u32, 0, 7),
        stmt(BPF_LD_W_ABS, arg_low(0)),
        jump(BPF_JSET_K, !(CLONE_ALLOWED | CSIGNAL), 4, 0),
        stmt(BPF_AND_K, CSIGNAL),
        jump(BPF_JEQ_K, 0, 1, 0),
        jump(BPF_JEQ_K, libc::SIGCHLD as u32, 0, 1),
        stmt(BPF_RET_K, ALLOW),
        stmt(BPF_RET_K, REFUSE),
    ]);

    // execveat: only the reserved image descriptor with AT_EMPTY_PATH.
    // Landlock, not this number, binds execution to the checked image.
    program.extend([
        jump(BPF_JEQ_K, libc::SYS_execveat as u32, 0, 6),
        stmt(BPF_LD_W_ABS, arg_low(0)),
        jump(BPF_JEQ_K, image_fd as u32, 0, 3),
        stmt(BPF_LD_W_ABS, arg_low(4)),
        jump(BPF_JEQ_K, libc::AT_EMPTY_PATH as u32, 0, 1),
        stmt(BPF_RET_K, ALLOW),
        stmt(BPF_RET_K, REFUSE),
    ]);

    program.push(stmt(BPF_RET_K, REFUSE));
    program
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `program` on one syscall the way the kernel would.
    fn eval(program: &[sock_filter], nr: libc::c_long, arch: u32, args: [u64; 6]) -> u32 {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&(nr as i32).to_le_bytes());
        data.extend_from_slice(&arch.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        for arg in args {
            data.extend_from_slice(&arg.to_le_bytes());
        }
        let mut accumulator = 0u32;
        let mut pc = 0usize;
        loop {
            let instruction = program[pc];
            let k = instruction.k;
            let branch = |taken: bool| {
                usize::from(if taken {
                    instruction.jt
                } else {
                    instruction.jf
                })
            };
            pc += 1;
            match instruction.code {
                BPF_LD_W_ABS => {
                    let at = k as usize;
                    accumulator = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                }
                BPF_JEQ_K => pc += branch(accumulator == k),
                BPF_JGE_K => pc += branch(accumulator >= k),
                BPF_JSET_K => pc += branch(accumulator & k != 0),
                BPF_AND_K => accumulator &= k,
                BPF_RET_K => return k,
                code => panic!("unexpected opcode {code:#x}"),
            }
        }
    }

    const IMAGE: RawFd = RESERVED_IMAGE_FD;

    fn allowlist(nr: libc::c_long, args: [u64; 6]) -> u32 {
        eval(&final_allowlist(IMAGE), nr, AUDIT_ARCH_X86_64, args)
    }

    fn call(nr: libc::c_long) -> u32 {
        allowlist(nr, [0; 6])
    }

    #[test]
    fn non_native_calls_are_killed_by_both_filters() {
        for program in [notify_filter(), final_allowlist(IMAGE)] {
            assert_eq!(eval(&program, libc::SYS_read, 0x4000_0003, [0; 6]), KILL);
            let x32 = libc::SYS_read | X32_SYSCALL_BIT as libc::c_long;
            assert_eq!(eval(&program, x32, AUDIT_ARCH_X86_64, [0; 6]), KILL);
        }
    }

    #[test]
    fn the_notification_filter_sends_only_the_open_family() {
        let program = notify_filter();
        for nr in [libc::SYS_open, libc::SYS_openat, libc::SYS_openat2] {
            assert_eq!(eval(&program, nr, AUDIT_ARCH_X86_64, [0; 6]), NOTIFY);
        }
        for nr in [libc::SYS_read, libc::SYS_execve, libc::SYS_creat] {
            assert_eq!(eval(&program, nr, AUDIT_ARCH_X86_64, [0; 6]), ALLOW);
        }
    }

    #[test]
    fn listed_syscalls_are_allowed() {
        for &nr in ALLOWED {
            assert_eq!(call(nr), ALLOW, "syscall {nr}");
        }
    }

    #[test]
    fn unlisted_syscalls_are_refused_and_clone3_is_enosys() {
        for nr in [
            libc::SYS_execve,
            libc::SYS_creat,
            libc::SYS_newfstatat,
            libc::SYS_io_uring_setup,
            libc::SYS_socket,
            libc::SYS_seccomp,
            libc::SYS_prctl,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_pidfd_getfd,
            libc::SYS_open_by_handle_at,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_ioctl,
        ] {
            assert_eq!(call(nr), REFUSE, "syscall {nr}");
        }
        assert_eq!(call(libc::SYS_clone3), errno(libc::ENOSYS));
    }

    #[test]
    fn fcntl_and_arch_prctl_allow_only_their_listed_commands() {
        for cmd in [
            libc::F_DUPFD,
            libc::F_DUPFD_CLOEXEC,
            libc::F_GETFD,
            libc::F_SETFD,
            libc::F_GETFL,
        ] {
            assert_eq!(
                allowlist(libc::SYS_fcntl, [3, cmd as u64, 0, 0, 0, 0]),
                ALLOW
            );
        }
        for cmd in [libc::F_SETFL, libc::F_SETLK, libc::F_SETOWN] {
            assert_eq!(
                allowlist(libc::SYS_fcntl, [3, cmd as u64, 0, 0, 0, 0]),
                REFUSE
            );
        }
        for code in [ARCH_SET_GS, ARCH_SET_FS, ARCH_GET_FS, ARCH_GET_GS] {
            assert_eq!(
                allowlist(libc::SYS_arch_prctl, [u64::from(code), 0, 0, 0, 0, 0]),
                ALLOW
            );
        }
        // ARCH_GET_CPUID and anything else.
        assert_eq!(
            allowlist(libc::SYS_arch_prctl, [0x1011, 0, 0, 0, 0, 0]),
            REFUSE
        );
    }

    #[test]
    fn clone_allows_threads_and_forks_only() {
        let thread = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u64;
        let fork = (libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID | libc::SIGCHLD) as u64;
        assert_eq!(allowlist(libc::SYS_clone, [thread, 0, 0, 0, 0, 0]), ALLOW);
        assert_eq!(allowlist(libc::SYS_clone, [fork, 0, 0, 0, 0, 0]), ALLOW);
        for flags in [
            libc::CLONE_NEWUSER | libc::SIGCHLD,
            libc::CLONE_NEWNS | libc::SIGCHLD,
            libc::CLONE_PIDFD | libc::SIGCHLD,
            libc::CLONE_PTRACE | libc::SIGCHLD,
            libc::SIGUSR1,
        ] {
            assert_eq!(
                allowlist(libc::SYS_clone, [flags as u64, 0, 0, 0, 0, 0]),
                REFUSE,
                "{flags:#x}"
            );
        }
    }

    #[test]
    fn execveat_runs_only_the_reserved_image_with_an_empty_path() {
        let empty = libc::AT_EMPTY_PATH as u64;
        let image = IMAGE as u64;
        assert_eq!(
            allowlist(libc::SYS_execveat, [image, 0, 0, 0, empty, 0]),
            ALLOW
        );
        assert_eq!(
            allowlist(libc::SYS_execveat, [image + 1, 0, 0, 0, empty, 0]),
            REFUSE
        );
        assert_eq!(
            allowlist(libc::SYS_execveat, [image, 0, 0, 0, 0, 0]),
            REFUSE
        );
        let at_fdcwd = libc::AT_FDCWD as u32 as u64;
        assert_eq!(
            allowlist(libc::SYS_execveat, [at_fdcwd, 0, 0, 0, 0, 0]),
            REFUSE
        );
    }
}
