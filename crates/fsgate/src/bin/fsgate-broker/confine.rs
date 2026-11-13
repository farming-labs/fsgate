//! Confines the worker `fsgate-broker` starts (RFC 0008).
//!
//! The broker starts itself again with [`ENTRY`] as the first argument. That
//! fresh, single-threaded process takes away what the worker must not have
//! and then becomes the worker, so nothing runs in a forked child of the
//! multi-threaded broker. `exec` is the last step and every failure before
//! it exits, so no path leads to an unconfined worker.
//!
//! The broker's grants never become rules here. If they did, the worker
//! could open granted files directly, with no audit event and no way to take
//! the access back.

use std::convert::Infallible;
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fsgate::Rights;
use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, LandlockStatus, PathBeneath, PathFd,
    PathFdError, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

/// The first argument that selects this mode instead of the broker's own
/// command line.
pub(super) const ENTRY: &str = "--confined-exec";

/// Directories an ordinary program needs in order to start. One that does
/// not exist on this system is skipped, which only narrows the ruleset.
/// Nix, and so NixOS, keeps every program, loader, and library in
/// `/nix/store`.
const RUNTIME_DIRS: [&str; 6] = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/nix/store"];

/// Signals that stop the broker. Before it dies of one, the broker ends its
/// confined worker's process group (RFC 0010).
const STOP_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The command that confines the process and then becomes `worker`, and the
/// [`Supervisor`] that ends the worker's process group with it.
///
/// This blocks [`STOP_SIGNALS`] in the calling thread, so call it before
/// starting any thread: each inherits the mask, and only the supervisor's
/// thread takes those signals. A stop signal this process inherited as
/// ignored, as under `nohup`, stays ignored. `std` keeps the mask in the
/// processes it starts, so [`run`] unblocks them again before it becomes
/// the worker.
///
/// `/proc/self/exe` names this binary even if its path has changed since it
/// started. `direct` and `env` were validated when the broker parsed them.
pub(super) fn command(
    connection: RawFd,
    grants: &[(PathBuf, Rights)],
    direct: &[String],
    env: &[String],
    worker: &[String],
) -> Result<(Command, Supervisor), String> {
    check_overlap(grants, direct)?;
    let mut command = Command::new("/proc/self/exe");
    command
        .arg0("fsgate-broker")
        .arg(ENTRY)
        .arg(std::process::id().to_string())
        .arg(connection.to_string());
    for spec in direct {
        command.args(["--direct", spec]);
    }
    for name in env {
        command.args(["--env", name]);
    }
    command.arg("--").args(worker);
    let signals = sys::block_unignored(&STOP_SIGNALS)
        .map_err(|err| format!("blocking the broker's stop signals failed: {err}"))?;
    Ok((command, Supervisor { signals }))
}

/// Ends a confined worker's process group when the worker exits or the
/// broker gets one of [`STOP_SIGNALS`] (RFC 0010). The worker leads its own
/// session (see [`run`]), so its process ID is also its group's.
pub(super) struct Supervisor {
    signals: sys::SignalSet,
}

/// A [`Supervisor`] whose thread is waiting for stop signals.
pub(super) struct Running {
    watch: Arc<Mutex<Watch>>,
}

/// What the supervisor's thread and the broker's main thread share.
struct Watch {
    /// The worker while it can still be killed by ID: from when it starts
    /// until just before it is reaped. Only then is its ID sure to be its.
    worker: Option<Pid>,
    /// The first stop signal the broker got.
    signal: Option<libc::c_int>,
}

fn watching(watch: &Mutex<Watch>) -> MutexGuard<'_, Watch> {
    watch.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Kills the worker and everything left in its group. Until the worker
/// calls `setsid` it is not in a group of its own, so it is killed by ID
/// too. `ESRCH` only means nothing was left to kill.
fn end_group(worker: Pid) {
    let _ = rustix::process::kill_process_group(worker, Signal::KILL);
    let _ = rustix::process::kill_process(worker, Signal::KILL);
}

impl Supervisor {
    /// Starts the thread that waits for stop signals. Call it before the
    /// worker starts, so that no worker runs without it.
    pub(super) fn start(self) -> Result<Running, String> {
        let watch = Arc::new(Mutex::new(Watch {
            worker: None,
            signal: None,
        }));
        let shared = Arc::clone(&watch);
        let signals = self.signals;
        std::thread::Builder::new()
            .spawn(move || {
                // `sigwait` fails only for a set it cannot wait on. Then the
                // signals stay blocked, and the group still ends when the
                // worker exits.
                while let Ok(signal) = sys::wait(&signals) {
                    let mut watch = watching(&shared);
                    watch.signal.get_or_insert(signal);
                    if let Some(worker) = watch.worker {
                        end_group(worker);
                    }
                }
            })
            .map_err(|err| format!("starting the thread that waits for signals failed: {err}"))?;
        Ok(Running { watch })
    }
}

impl Running {
    /// Waits for the worker to exit, kills what is left of its group, and
    /// exits with the worker's code. If the broker got a stop signal, it
    /// dies by that signal instead, as it would have without a worker.
    pub(super) fn finish(self, mut child: Child) -> Result<Infallible, String> {
        let worker = Pid::from_child(&child);
        {
            let mut watch = watching(&self.watch);
            watch.worker = Some(worker);
            // A signal that came before the worker was recorded here.
            if watch.signal.is_some() {
                end_group(worker);
            }
        }
        // `WNOWAIT` leaves the worker a zombie, so until it is reaped below
        // no new process can take its ID or lead a group with it.
        let exited = rustix::io::retry_on_intr(|| {
            rustix::process::waitid(
                WaitId::Pid(worker),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
            )
        });
        let signal = {
            let mut watch = watching(&self.watch);
            end_group(worker);
            watch.worker = None;
            watch.signal
        };
        let status = child
            .wait()
            .map_err(|err| format!("waiting for the worker failed: {err}"))?;
        exited.map_err(|err| format!("waiting for the worker failed: {err}"))?;
        if let Some(signal) = signal {
            let err = sys::die_by(signal);
            return Err(format!("dying by signal {signal} failed: {err}"));
        }
        std::process::exit(status.code().unwrap_or(1))
    }
}

/// Refuses a grant the worker could read without the broker: one that
/// overlaps a runtime directory or a `--direct` path, in either direction,
/// and gives a right the worker has there. Those reads would not be
/// audited, and revoking the grant would not stop them. Paths are compared
/// after resolving symlinks, as the rules see them. The image and the
/// single files in [`restrict`] hold no data, so they are left out.
fn check_overlap(grants: &[(PathBuf, Rights)], direct: &[String]) -> Result<(), String> {
    let mut readable = Vec::new();
    for dir in RUNTIME_DIRS {
        if let Ok(path) = fs::canonicalize(dir) {
            readable.push((format!("the runtime directory `{dir}`"), path, "rl"));
        }
    }
    for spec in direct {
        let (path, letters) = super::parse_direct(spec)?;
        let path = fs::canonicalize(&path).map_err(|err| format!("`--direct {spec}`: {err}"))?;
        readable.push((format!("`--direct {spec}`"), path, letters));
    }
    for (grant, rights) in grants {
        let resolved = fs::canonicalize(grant)
            .map_err(|err| format!("granting `{}` failed: {err}", grant.display()))?;
        for (what, path, letters) in &readable {
            let bypassed = (rights.contains(Rights::READ) && letters.contains('r'))
                || (rights.contains(Rights::LIST) && letters.contains('l'));
            if bypassed && (resolved.starts_with(path) || path.starts_with(&resolved)) {
                return Err(format!(
                    "`--grant {}` overlaps {what}, which a confined worker reads without \
                     the broker, so those reads would not be audited and revoking the \
                     grant would not stop them; grant a directory that neither contains \
                     nor sits beneath it",
                    grant.display()
                ));
            }
        }
    }
    Ok(())
}

struct Request {
    broker: u32,
    connection: RawFd,
    direct: Vec<String>,
    env: Vec<String>,
    worker: Vec<String>,
}

/// Runs the confining process. Returns only if the worker did not start.
pub(super) fn main(args: impl Iterator<Item = String>) -> ExitCode {
    let result = parse(args).and_then(run);
    let Err(message) = result;
    eprintln!("fsgate-broker: {message}");
    ExitCode::from(1)
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Request, String> {
    let malformed = || format!("`{ENTRY}` is internal to `fsgate-broker`; do not call it directly");
    let broker = args
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(malformed)?;
    let connection = args
        .next()
        .and_then(|value| value.parse().ok())
        .filter(|fd: &RawFd| *fd >= 0)
        .ok_or_else(malformed)?;

    let mut direct = Vec::new();
    let mut env = Vec::new();
    loop {
        match args.next().as_deref() {
            Some("--direct") => direct.push(args.next().ok_or_else(malformed)?),
            Some("--env") => env.push(args.next().ok_or_else(malformed)?),
            Some("--") => break,
            _ => return Err(malformed()),
        }
    }
    let worker: Vec<String> = args.collect();
    if worker.is_empty() {
        return Err(malformed());
    }
    Ok(Request {
        broker,
        connection,
        direct,
        env,
        worker,
    })
}

fn run(request: Request) -> Result<Infallible, String> {
    // The broker blocked these for its supervisor, and neither `std` nor
    // `exec` clears a mask, so the worker would start with them blocked.
    sys::unblock(&STOP_SIGNALS)
        .map_err(|err| format!("unblocking the worker's stop signals failed: {err}"))?;

    // `TIOCSTI` lets a process type into its controlling terminal, so a
    // worker could queue commands for the user's shell. A new session has
    // no controlling terminal.
    rustix::process::setsid().map_err(|err| format!("starting a new session failed: {err}"))?;

    // After `setsid`, Ctrl-C reaches only the broker. Without this, a killed
    // broker would leave its worker running.
    rustix::process::set_parent_process_death_signal(Some(Signal::KILL))
        .map_err(|err| format!("tying the worker to its broker failed: {err}"))?;
    // The broker may have died before that call took effect.
    if std::os::unix::process::parent_id() != request.broker {
        return Err("the broker exited before its worker started".into());
    }

    let image = resolve(&request.worker[0])?;
    let landlock = restrict(&image, &request.direct)?;
    if !refuses_unix_connects(landlock) {
        unix_socket_filter::install()?;
    }

    // Landlock does not restrict descriptors opened before it applies. This
    // comes after `restrict` so that on a kernel too old for both, the error
    // is the one that names `--unconfined`.
    close_others_at_exec(request.connection)
        .map_err(|err| format!("closing inherited descriptors failed: {err}"))?;

    let mut worker = Command::new(&image);
    worker.arg0(&request.worker[0]).args(&request.worker[1..]);
    worker.env_clear();
    for name in &request.env {
        if let Some(value) = std::env::var_os(name) {
            worker.env(name, value);
        }
    }
    worker.env("FSGATE_BROKER_FD", request.connection.to_string());
    let err = worker.exec();
    Err(format!("starting `{}` failed: {err}", request.worker[0]))
}

/// Marks every descriptor except standard input, output, and error and the
/// broker connection to close when the worker starts.
fn close_others_at_exec(connection: RawFd) -> io::Result<()> {
    let keep = connection.unsigned_abs();
    if keep > 3 {
        sys::close_at_exec(3, keep - 1)?;
    }
    sys::close_at_exec((keep + 1).max(3), u32::MAX)
}

/// Where `name` is, the way `execvp` would find it, so a rule can name the
/// worker's own image.
fn resolve(name: &str) -> Result<PathBuf, String> {
    if name.contains('/') {
        return Ok(PathBuf::from(name));
    }
    let path = std::env::var_os("PATH")
        .ok_or_else(|| format!("`PATH` is not set, so `{name}` cannot be found; give its path"))?;
    std::env::split_paths(&path)
        // An empty entry means the current directory. Without the `.` the
        // result has no `/`, and `exec` would search for it again.
        .map(|dir| {
            if dir.as_os_str().is_empty() {
                Path::new(".").join(name)
            } else {
                dir.join(name)
            }
        })
        .find(|candidate| is_executable(candidate))
        .ok_or_else(|| format!("`{name}` was not found on `PATH`; give its path"))
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Whether the Landlock ruleset [`restrict`] applied refuses connects to
/// pathname Unix sockets, which needs ABI 9 (Linux 7.1). It also scopes
/// abstract ones there.
fn refuses_unix_connects(landlock: LandlockStatus) -> bool {
    matches!(landlock, LandlockStatus::Available { effective_abi, .. } if effective_abi >= ABI::V9)
}

/// Restricts this process, and so the worker it becomes, to the paths a
/// program needs to start and the `--direct` paths. Data comes from the
/// broker. Returns the Landlock status the kernel reported.
fn restrict(image: &Path, direct: &[String]) -> Result<LandlockStatus, String> {
    let runtime = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
    let mut ruleset = ruleset()?;
    for dir in RUNTIME_DIRS {
        ruleset = allow_if_present(ruleset, Path::new(dir), runtime)?;
    }
    ruleset = allow_if_present(
        ruleset,
        Path::new("/etc/ld.so.cache"),
        AccessFs::ReadFile.into(),
    )?;
    ruleset = allow_if_present(
        ruleset,
        Path::new("/dev/null"),
        AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate,
    )?;
    ruleset = allow_if_present(
        ruleset,
        Path::new("/dev/urandom"),
        AccessFs::ReadFile.into(),
    )?;
    ruleset = allow(ruleset, image, AccessFs::ReadFile | AccessFs::Execute)?;
    for spec in direct {
        let (path, letters) = super::parse_direct(spec)?;
        let mut access = BitFlags::<AccessFs>::EMPTY;
        for letter in letters.chars() {
            access |= match letter {
                'r' => AccessFs::ReadFile,
                'l' => AccessFs::ReadDir,
                _ => AccessFs::Execute,
            };
        }
        ruleset = allow(ruleset, &path, access)?;
    }

    let status = ruleset.restrict_self().map_err(unavailable)?;
    // The hard requirement in `ruleset` makes this unreachable. It is checked
    // anyway, so an unexpected crate or kernel answer cannot start a worker.
    if status.ruleset == RulesetStatus::NotEnforced || !status.no_new_privs {
        return Err(unavailable("the kernel did not apply the ruleset"));
    }
    Ok(status.landlock)
}

/// A ruleset that handles every filesystem right `lock()` handles, and asks
/// for the RFC 0006 restrictions where the kernel has them.
fn ruleset() -> Result<RulesetCreated, String> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3))
        .map_err(unavailable)?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::IoctlDev)
        .map_err(unavailable)?
        // No rule below names this one. The worker already holds its
        // connection, so it never needs a connect.
        .handle_access(AccessFs::ResolveUnix)
        .map_err(unavailable)?
        .scope(Scope::AbstractUnixSocket)
        .map_err(unavailable)?
        .scope(Scope::Signal)
        .map_err(unavailable)?
        .create()
        .map_err(unavailable)
}

fn unavailable(err: impl std::fmt::Display) -> String {
    format!(
        "this kernel cannot confine the worker, which needs Landlock ABI v3 ({err}); \
         pass `--unconfined` to run it without confinement"
    )
}

fn allow(
    ruleset: RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, String> {
    let fd = PathFd::new(path).map_err(|err| {
        format!(
            "`{}` cannot be opened for the worker: {err}",
            path.display()
        )
    })?;
    add_rule(ruleset, path, fd, access)
}

fn allow_if_present(
    ruleset: RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, String> {
    match PathFd::new(path) {
        Ok(fd) => add_rule(ruleset, path, fd, access),
        Err(PathFdError::OpenCall { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Ok(ruleset)
        }
        Err(err) => Err(format!(
            "`{}` cannot be opened for the worker: {err}",
            path.display()
        )),
    }
}

fn add_rule(
    ruleset: RulesetCreated,
    path: &Path,
    fd: PathFd,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, String> {
    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map_err(|err| format!("allowing `{}` failed: {err}", path.display()))
}

/// The seccomp filter that keeps a confined worker off Unix sockets where
/// Landlock cannot (RFC 0009). It answers:
///
/// - `socket(AF_UNIX, ...)` with `EACCES`. With no new Unix socket there is
///   nothing to connect, by path or by abstract name.
/// - `socketpair(AF_UNIX, SOCK_DGRAM, ...)` with `EACCES`. A datagram socket
///   can send to any address and connect to another, even as half of a
///   pair. Stream and seqpacket pairs stay connected to each other, so they
///   are allowed.
/// - `io_uring_setup`, `io_uring_enter`, and `io_uring_register` with
///   `ENOSYS`, as a kernel without `io_uring` does. Its operations create
///   and connect sockets without the calls above.
/// - A call from another architecture, or an x32 call, by killing the
///   process. Those use call numbers this filter does not know.
/// - Anything else by allowing it.
///
/// Every program the worker starts inherits the filter across `exec`, and
/// nothing can remove it.
mod unix_socket_filter {
    /// Installs the filter on this thread, which becomes the worker. Landlock
    /// has already set `no_new_privs`, which the kernel requires.
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(
            target_arch = "aarch64",
            target_pointer_width = "64",
            target_endian = "little"
        ),
    ))]
    pub(super) fn install() -> Result<(), String> {
        super::sys::install_seccomp_filter(&native::PROGRAM).map_err(|err| {
            format!(
                "installing the filter that keeps the worker off Unix sockets failed ({err}); \
                 pass `--unconfined` to run it without confinement"
            )
        })
    }

    #[cfg(not(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(
            target_arch = "aarch64",
            target_pointer_width = "64",
            target_endian = "little"
        ),
    )))]
    pub(super) fn install() -> Result<(), String> {
        Err(format!(
            "this kernel's Landlock cannot keep the worker off Unix sockets, which needs \
             Landlock ABI v9 (Linux 7.1), and fsgate has no filter that does it on {}; \
             pass `--unconfined` to run it without confinement",
            std::env::consts::ARCH
        ))
    }

    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(
            target_arch = "aarch64",
            target_pointer_width = "64",
            target_endian = "little"
        ),
    ))]
    mod native {
        use libc::{
            AF_UNIX, BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET,
            BPF_W, EACCES, ENOSYS, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
            SOCK_DGRAM, SYS_io_uring_enter, SYS_io_uring_register, SYS_io_uring_setup, SYS_socket,
            SYS_socketpair, sock_filter,
        };

        /// `AUDIT_ARCH_X86_64`, which `libc` does not define.
        #[cfg(target_arch = "x86_64")]
        const AUDIT_ARCH: u32 = 0xc000_003e;
        /// `AUDIT_ARCH_AARCH64`, which `libc` does not define.
        #[cfg(target_arch = "aarch64")]
        const AUDIT_ARCH: u32 = 0xc000_00b7;

        // Offsets into `struct seccomp_data`. Both architectures are little
        // endian, so an argument's low 32 bits come first. `socket` and
        // `socketpair` take `int` arguments, and the kernel reads only those
        // bits too.
        const NR: u32 = 0;
        const ARCH: u32 = 4;
        const ARG0: u32 = 16;
        const ARG1: u32 = 24;

        /// Set in the number of an x32 call. No native call number on
        /// either architecture has it.
        const X32_SYSCALL_BIT: u32 = 0x4000_0000;
        /// The bits of `socketpair`'s type argument that name the type,
        /// without `SOCK_CLOEXEC` and `SOCK_NONBLOCK`.
        const SOCK_TYPE_MASK: u32 = 0xf;

        // Where the steps that several jumps lead to start.
        const SOCKETPAIR: usize = 9;
        const SOCKET: usize = 12;
        const ALLOW: usize = 14;
        const REFUSE: usize = 15;
        const MISSING: usize = 16;
        const KILL: usize = 17;

        /// Each jump names its own index first, then where it goes on when
        /// its comparison holds and when it does not.
        pub(super) const PROGRAM: [sock_filter; 18] = [
            load(ARCH),
            jeq(1, AUDIT_ARCH, 2, KILL),
            load(NR),
            jge(3, X32_SYSCALL_BIT, KILL, 4),
            jeq(4, number(SYS_socket), SOCKET, 5),
            jeq(5, number(SYS_socketpair), SOCKETPAIR, 6),
            jeq(6, number(SYS_io_uring_setup), MISSING, 7),
            jeq(7, number(SYS_io_uring_enter), MISSING, 8),
            jeq(8, number(SYS_io_uring_register), MISSING, ALLOW),
            // SOCKETPAIR: only a datagram pair goes on to the domain.
            load(ARG1),
            statement(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK),
            jeq(11, SOCK_DGRAM as u32, SOCKET, ALLOW),
            // SOCKET
            load(ARG0),
            jeq(13, AF_UNIX as u32, REFUSE, ALLOW),
            answer(SECCOMP_RET_ALLOW),
            answer(SECCOMP_RET_ERRNO | EACCES as u32),
            answer(SECCOMP_RET_ERRNO | ENOSYS as u32),
            answer(SECCOMP_RET_KILL_PROCESS),
        ];

        // Each label names the step the jumps expect, or this does not build.
        const _: () = {
            assert!(PROGRAM[SOCKETPAIR].k == ARG1);
            assert!(PROGRAM[SOCKET].k == ARG0);
            assert!(PROGRAM[ALLOW].k == SECCOMP_RET_ALLOW);
            assert!(PROGRAM[REFUSE].k == SECCOMP_RET_ERRNO | EACCES as u32);
            assert!(PROGRAM[MISSING].k == SECCOMP_RET_ERRNO | ENOSYS as u32);
            assert!(PROGRAM[KILL].k == SECCOMP_RET_KILL_PROCESS);
        };

        /// A call number as the filter sees it. Every number used here is
        /// small and positive.
        const fn number(call: libc::c_long) -> u32 {
            assert!(call > 0 && call < X32_SYSCALL_BIT as libc::c_long);
            call as u32
        }

        const fn statement(code: u32, k: u32) -> sock_filter {
            sock_filter {
                code: code as u16,
                jt: 0,
                jf: 0,
                k,
            }
        }

        const fn load(offset: u32) -> sock_filter {
            statement(BPF_LD | BPF_W | BPF_ABS, offset)
        }

        const fn answer(action: u32) -> sock_filter {
            statement(BPF_RET | BPF_K, action)
        }

        const fn jeq(at: usize, k: u32, yes: usize, no: usize) -> sock_filter {
            jump(at, BPF_JEQ, k, yes, no)
        }

        const fn jge(at: usize, k: u32, yes: usize, no: usize) -> sock_filter {
            jump(at, BPF_JGE, k, yes, no)
        }

        /// The jump at index `at` that compares the loaded value with `k`
        /// and goes on at index `yes` or `no`. A filter only jumps forward.
        const fn jump(at: usize, test: u32, k: u32, yes: usize, no: usize) -> sock_filter {
            assert!(yes > at && yes - at <= 256 && no > at && no - at <= 256);
            sock_filter {
                code: (BPF_JMP | test | BPF_K) as u16,
                jt: (yes - at - 1) as u8,
                jf: (no - at - 1) as u8,
                k,
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use libc::{AF_INET, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_RAW, SOCK_RDM};
            use libc::{SOCK_SEQPACKET, SOCK_STREAM};

            const REFUSED: u32 = SECCOMP_RET_ERRNO | EACCES as u32;

            /// What the filter answers for a call, found by running it on
            /// `struct seccomp_data` as the kernel does. Only the
            /// instructions the filter is built from are known here.
            fn answer_for(arch: u32, nr: u32, args: [u64; 2]) -> u32 {
                let mut data = [0u8; 64];
                data[..4].copy_from_slice(&nr.to_le_bytes());
                data[4..8].copy_from_slice(&arch.to_le_bytes());
                data[16..24].copy_from_slice(&args[0].to_le_bytes());
                data[24..32].copy_from_slice(&args[1].to_le_bytes());
                let (mut loaded, mut at) = (0u32, 0);
                loop {
                    let step = PROGRAM[at];
                    at += 1;
                    match u32::from(step.code) {
                        code if code == BPF_LD | BPF_W | BPF_ABS => {
                            let offset = step.k as usize;
                            let word = data[offset..offset + 4].try_into().unwrap();
                            loaded = u32::from_le_bytes(word);
                        }
                        code if code == BPF_ALU | BPF_AND | BPF_K => loaded &= step.k,
                        code if code == BPF_JMP | BPF_JEQ | BPF_K
                            || code == BPF_JMP | BPF_JGE | BPF_K =>
                        {
                            let holds = if code & 0xf0 == BPF_JEQ {
                                loaded == step.k
                            } else {
                                loaded >= step.k
                            };
                            at += usize::from(if holds { step.jt } else { step.jf });
                        }
                        code if code == BPF_RET | BPF_K => return step.k,
                        code => panic!(
                            "step {} has code {code:#x}, which this does not run",
                            at - 1
                        ),
                    }
                }
            }

            fn call(nr: libc::c_long, domain: libc::c_int, kind: libc::c_int) -> u32 {
                answer_for(AUDIT_ARCH, number(nr), [domain as u64, kind as u64])
            }

            #[test]
            fn refuses_every_unix_socket_but_a_stream_or_seqpacket_pair() {
                let flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
                for kind in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET, SOCK_RAW, SOCK_RDM] {
                    assert_eq!(
                        call(SYS_socket, AF_UNIX, kind | flags),
                        REFUSED,
                        "socket {kind}"
                    );
                }
                for (kind, answer) in [
                    (SOCK_STREAM, SECCOMP_RET_ALLOW),
                    (SOCK_SEQPACKET, SECCOMP_RET_ALLOW),
                    (SOCK_DGRAM, REFUSED),
                    // The kernel makes a Unix `SOCK_RAW` socket a datagram one.
                    (SOCK_RAW, REFUSED),
                    (SOCK_RDM, REFUSED),
                ] {
                    assert_eq!(
                        call(SYS_socketpair, AF_UNIX, kind | flags),
                        answer,
                        "pair {kind}"
                    );
                }
                // The kernel reads these arguments as `int`, as the filter does.
                let high = 1u64 << 32;
                let pair = |domain: u64, kind: u64| {
                    answer_for(AUDIT_ARCH, number(SYS_socketpair), [domain, kind])
                };
                assert_eq!(pair(high | AF_UNIX as u64, SOCK_DGRAM as u64), REFUSED);
                assert_eq!(pair(AF_UNIX as u64, high | SOCK_RAW as u64), REFUSED);
            }

            #[test]
            fn allows_other_calls_and_kills_foreign_ones() {
                assert_eq!(call(SYS_socket, AF_INET, SOCK_STREAM), SECCOMP_RET_ALLOW);
                assert_eq!(call(SYS_socket, AF_INET, SOCK_RAW), SECCOMP_RET_ALLOW);
                assert_eq!(call(libc::SYS_openat, 0, 0), SECCOMP_RET_ALLOW);
                for nr in [
                    SYS_io_uring_setup,
                    SYS_io_uring_enter,
                    SYS_io_uring_register,
                ] {
                    assert_eq!(call(nr, 0, 0), SECCOMP_RET_ERRNO | ENOSYS as u32, "{nr}");
                }
                let socket = number(SYS_socket);
                assert_eq!(
                    answer_for(AUDIT_ARCH, X32_SYSCALL_BIT | socket, [0, 0]),
                    SECCOMP_RET_KILL_PROCESS
                );
                // `AUDIT_ARCH_I386`, a 32-bit call on either architecture.
                assert_eq!(
                    answer_for(0x4000_0003, socket, [0, 0]),
                    SECCOMP_RET_KILL_PROCESS
                );
            }
        }
    }
}

/// The `unsafe` calls confinement and its supervisor need, kept apart from
/// their logic. Neither `std` nor `rustix` wraps them safely.
///
/// # Safety contract
///
/// - `close_range(2)` takes plain integers and reads no memory of this
///   process. With `CLOSE_RANGE_CLOEXEC` it closes nothing now; it only
///   marks descriptors to close at `exec`. So it cannot invalidate a
///   descriptor that Rust code holds, whatever the range.
/// - `seccomp(2)` with `SECCOMP_SET_MODE_FILTER` reads a `sock_fprog` and
///   the instructions it points to, both of which outlive the call, and
///   copies them into the kernel. It never writes through that pointer, so
///   one made from a shared slice is sound. The filter then refuses or
///   kills later system calls; it changes no memory that Rust code holds.
/// - `sigemptyset`, `sigaddset`, `sigaction`, `pthread_sigmask`, and
///   `sigwait` read and write only the `sigset_t`, `sigaction`, and `c_int`
///   values passed to them, each a local or a field of [`SignalSet`] that
///   outlives the call. `sigaction` with a null new action only reads the
///   current one. A mask belongs to the calling thread. None of these
///   touch memory or descriptors that Rust code holds.
/// - [`die_by`] restores the default action for a signal that `std` does
///   not handle and raises it, so the process ends without returning to
///   Rust code that could observe the change.
#[allow(unsafe_code)]
mod sys {
    use std::io;
    use std::mem::MaybeUninit;
    use std::ptr;

    /// A set of signals, built by [`block_unignored`].
    #[derive(Clone, Copy)]
    pub(super) struct SignalSet(libc::sigset_t);

    fn empty() -> libc::sigset_t {
        let mut set = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `sigemptyset` initializes the set it is given, which is
        // this local. See the module contract.
        unsafe {
            libc::sigemptyset(set.as_mut_ptr());
            set.assume_init()
        }
    }

    fn add(set: &mut libc::sigset_t, signal: libc::c_int) -> io::Result<()> {
        // SAFETY: `set` is a valid, initialized set. See the module contract.
        if unsafe { libc::sigaddset(set, signal) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn mask(how: libc::c_int, set: &libc::sigset_t) -> io::Result<()> {
        // SAFETY: `set` is a valid set, and a null old set is allowed. See
        // the module contract.
        match unsafe { libc::pthread_sigmask(how, set, ptr::null_mut()) } {
            0 => Ok(()),
            errno => Err(io::Error::from_raw_os_error(errno)),
        }
    }

    /// Blocks each of `signals` that this process does not ignore, in the
    /// calling thread, and returns the set it blocked.
    pub(super) fn block_unignored(signals: &[libc::c_int]) -> io::Result<SignalSet> {
        let mut set = empty();
        for &signal in signals {
            let mut current = MaybeUninit::<libc::sigaction>::uninit();
            // SAFETY: a null new action only reads the current one into
            // this local. See the module contract.
            if unsafe { libc::sigaction(signal, ptr::null(), current.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `sigaction` succeeded, so it wrote the action.
            let current = unsafe { current.assume_init() };
            if current.sa_sigaction != libc::SIG_IGN {
                add(&mut set, signal)?;
            }
        }
        mask(libc::SIG_BLOCK, &set)?;
        Ok(SignalSet(set))
    }

    /// Unblocks each of `signals` in the calling thread.
    pub(super) fn unblock(signals: &[libc::c_int]) -> io::Result<()> {
        let mut set = empty();
        for &signal in signals {
            add(&mut set, signal)?;
        }
        mask(libc::SIG_UNBLOCK, &set)
    }

    /// Waits for one of `set`, which every thread must have blocked.
    pub(super) fn wait(set: &SignalSet) -> io::Result<libc::c_int> {
        let mut signal = 0;
        // SAFETY: both pointers are to values that outlive the call. See the
        // module contract.
        match unsafe { libc::sigwait(&set.0, &mut signal) } {
            0 => Ok(signal),
            errno => Err(io::Error::from_raw_os_error(errno)),
        }
    }

    /// Ends the process by `signal`, with its default action. Returns only
    /// if that failed.
    pub(super) fn die_by(signal: libc::c_int) -> io::Error {
        // SAFETY: an all-zero `sigaction` is the default action with an
        // empty mask and no flags. See the module contract.
        let default: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: `default` outlives the call, and a null old action is
        // allowed. See the module contract.
        if unsafe { libc::sigaction(signal, &default, ptr::null_mut()) } != 0 {
            return io::Error::last_os_error();
        }
        let mut set = empty();
        if let Err(err) = add(&mut set, signal).and_then(|()| mask(libc::SIG_UNBLOCK, &set)) {
            return err;
        }
        // SAFETY: `raise` takes an integer. See the module contract.
        unsafe { libc::raise(signal) };
        io::Error::other("the signal did not end the process")
    }

    /// Installs `program` as a seccomp filter on the calling thread, which
    /// must already have `no_new_privs`.
    #[cfg_attr(
        not(any(
            all(target_arch = "x86_64", target_pointer_width = "64"),
            all(
                target_arch = "aarch64",
                target_pointer_width = "64",
                target_endian = "little"
            ),
        )),
        allow(dead_code)
    )]
    pub(super) fn install_seccomp_filter(program: &[libc::sock_filter]) -> io::Result<()> {
        let len = u16::try_from(program.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let program = libc::sock_fprog {
            len,
            filter: program.as_ptr().cast_mut(),
        };
        let flags: libc::c_ulong = 0;
        // SAFETY: `program` and the instructions it points to outlive the
        // call, and the kernel only reads them. See the module contract.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
                flags,
                ptr::from_ref(&program),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn close_at_exec(first: u32, last: u32) -> io::Result<()> {
        // SAFETY: the arguments are integers. See the module contract.
        let result = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                libc::c_ulong::from(first),
                libc::c_ulong::from(last),
                libc::c_ulong::from(libc::CLOSE_RANGE_CLOEXEC),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runtime path this system lacks is skipped, which only narrows the
    /// ruleset. Any other failure to open one stops the worker, so a path
    /// the broker cannot see is never silently left out of the rules.
    #[test]
    fn only_a_missing_runtime_path_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let access = AccessFs::ReadFile.into();

        let missing = dir.path().join("missing");
        assert!(allow_if_present(ruleset().unwrap(), &missing, access).is_ok());
        assert!(allow_if_present(ruleset().unwrap(), dir.path(), access).is_ok());

        let shut = dir.path().join("shut");
        fs::create_dir(&shut).unwrap();
        fs::set_permissions(&shut, fs::Permissions::from_mode(0o000)).unwrap();
        let Err(err) = allow_if_present(ruleset().unwrap(), &shut.join("beneath"), access) else {
            panic!("a path that cannot be searched was skipped");
        };
        assert!(err.contains("cannot be opened for the worker"), "{err}");
    }
}
