//! Launcher and supervisor. Everything here is safe code; the raw
//! interfaces live in [`crate::sys`].

use std::fs::File;
use std::io::{self, IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};

use fsgate::{Gate, GateError};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};

use crate::sys;

/// Known bytes the supervisor reads back from the restricted child before
/// releasing it. The child is a fork of this process, so the static sits at
/// the same address there.
static READY_MARKER: [u8; 16] = *b"fsgate-probe-rdy";

/// How long the supervisor waits for a request or the worker's exit before
/// giving up and closing the listener, which fails any pending open.
const IDLE_TIMEOUT: Timespec = Timespec {
    tv_sec: 30,
    tv_nsec: 0,
};

/// Paths are at most 4096 bytes including the terminator (RFC 0004).
const PATH_MAX: usize = 4096;
/// Base page size on x86_64; path copies never cross a page in one read.
const PAGE_SIZE: u64 = 4096;
/// `sizeof(struct open_how)`; the only `openat2` layout accepted.
const OPEN_HOW_SIZE: u64 = 24;
/// The kernel's `O_LARGEFILE` on x86_64. libc defines it as 0 for
/// userspace, but some runtimes pass the kernel bit explicitly.
const KERNEL_O_LARGEFILE: u64 = 0o100000;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;

/// Fault injection for the startup and supervisor-loss tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Normal operation.
    None,
    /// The supervisor closes its listener before releasing the startup
    /// barrier, as if it died right after startup.
    CloseListener,
    /// The supervisor never releases the startup barrier.
    AbortStartup,
}

/// One notified open request and the supervisor's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The syscall number: `SYS_open`, `SYS_openat`, or `SYS_openat2`.
    pub syscall: i64,
    /// The copied path, when one was read and decoded as UTF-8.
    pub path: Option<String>,
    /// `None` when a descriptor was delivered; otherwise the errno returned.
    pub errno: Option<i32>,
}

/// What one probe run observed.
#[derive(Debug)]
pub struct Outcome {
    /// The worker's exit status.
    pub status: ExitStatus,
    /// Everything the worker wrote to standard output.
    pub stdout: Vec<u8>,
    /// Everything the worker wrote to standard error.
    pub stderr: Vec<u8>,
    /// Every request the supervisor answered, in order.
    pub decisions: Vec<Decision>,
}

/// Runs `executable` with `args` as a contained worker whose open-family
/// syscalls are answered from `gate`.
///
/// The worker starts with only stdio open, under `no_new_privs`, a Landlock
/// ruleset that allows it nothing but executing its own image, and a seccomp
/// filter that sends `open`, `openat`, and `openat2` to the supervisor. A
/// failure before exec, including the supervisor refusing to release the
/// startup barrier, returns the child's error and the worker never runs.
pub fn run(executable: &Path, args: &[&str], gate: Gate, fault: Fault) -> io::Result<Outcome> {
    preflight()?;
    let image = rustix::fs::open(executable, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?;
    if FileType::from_raw_mode(rustix::fs::fstat(&image)?.st_mode) != FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "`{}` is not a regular file; pass the worker executable itself",
                executable.display()
            ),
        ));
    }
    let ruleset = sys::executable_ruleset(image.as_fd())?;
    let (supervisor_end, child_end) = UnixStream::pair()?;
    // The supervisor holds its end until the child has sent the listener or
    // died, so this number stays valid through the fork.
    let peer = supervisor_end.as_raw_fd();
    let supervisor = thread::spawn(move || supervise(supervisor_end, gate, fault));

    let mut command = Command::new(executable);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sys::install_child_setup(
        &mut command,
        sys::ChildSetup {
            ruleset: ruleset.as_raw_fd(),
            socket: child_end.as_raw_fd(),
            peer,
            filter: notify_filter(),
        },
    );
    let spawned = command.spawn();
    // The parent's copy would hide a dead child from the supervisor.
    drop(child_end);
    drop(ruleset);
    drop(image);

    let output = match spawned {
        Ok(child) => child.wait_with_output(),
        // A supervisor failure explains a failed startup better than the
        // child's errno; otherwise the child's error (a refused barrier, a
        // failed exec) is the answer.
        Err(err) => return Err(join(supervisor).err().unwrap_or(err)),
    };
    let decisions = join(supervisor)?;
    let output = output?;
    Ok(Outcome {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
        decisions,
    })
}

fn preflight() -> io::Result<()> {
    let abi = sys::landlock_abi().map_err(|err| {
        unsupported(format!(
            "landlock is unavailable ({err}); the probe needs Landlock ABI 3 (Linux 6.2+) enabled"
        ))
    })?;
    if abi < 3 {
        return Err(unsupported(format!(
            "landlock ABI {abi} is too old; the probe needs ABI 3 (Linux 6.2+)"
        )));
    }
    sys::user_notif_available().map_err(|err| {
        unsupported(format!(
            "seccomp user notifications are unavailable ({err}); the probe needs Linux 5.14+ with seccomp enabled"
        ))
    })
}

fn unsupported(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn join(supervisor: JoinHandle<io::Result<Vec<Decision>>>) -> io::Result<Vec<Decision>> {
    supervisor
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("supervisor thread panicked")))
}

/// The notification filter: kill anything that is not native x86_64 (x32
/// included), notify the supervisor of the three open syscalls, and allow
/// everything else. Landlock, not this filter, denies direct file access.
pub(crate) fn notify_filter() -> Vec<libc::sock_filter> {
    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(k: u32, jt: u8, jf: u8, code: u16) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    vec![
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH),
        jump(AUDIT_ARCH_X86_64, 1, 0, BPF_JEQ_K),
        stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR),
        jump(X32_SYSCALL_BIT, 0, 1, BPF_JGE_K),
        stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        jump(libc::SYS_open as u32, 3, 0, BPF_JEQ_K),
        jump(libc::SYS_openat as u32, 2, 0, BPF_JEQ_K),
        jump(libc::SYS_openat2 as u32, 1, 0, BPF_JEQ_K),
        stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW),
        stmt(BPF_RET_K, libc::SECCOMP_RET_USER_NOTIF),
    ]
}

fn supervise(socket: UnixStream, gate: Gate, fault: Fault) -> io::Result<Vec<Decision>> {
    let (listener, pid) = receive_listener(&socket)?;
    verify_listener(&listener)?;
    verify_child_memory(pid)?;
    match fault {
        // Dropping the socket without the ready byte fails the barrier.
        Fault::AbortStartup => return Ok(Vec::new()),
        Fault::CloseListener => {
            drop(listener);
            release(&socket)?;
            return Ok(Vec::new());
        }
        Fault::None => {}
    }
    release(&socket)?;
    drop(socket);
    serve(&listener, &gate)
}

fn startup_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, message.to_owned())
}

/// Receives the child's listener and PID.
fn receive_listener(socket: &UnixStream) -> io::Result<(OwnedFd, i32)> {
    let mut payload = [0u8; 4];
    let mut space = vec![MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = rustix::net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut payload)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut fds = Vec::new();
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(received_fds) = message {
            fds.extend(received_fds);
        }
    }
    match (received.bytes, fds.pop(), fds.is_empty()) {
        (4, Some(listener), true) => Ok((listener, i32::from_le_bytes(payload))),
        _ => Err(startup_error(
            "the child exited or sent a malformed message before handing over its seccomp listener",
        )),
    }
}

fn verify_listener(listener: &OwnedFd) -> io::Result<()> {
    let target = std::fs::read_link(format!("/proc/self/fd/{}", listener.as_raw_fd()))?;
    if target != Path::new("anon_inode:seccomp notify") {
        return Err(startup_error(
            "the child handed over a descriptor that is not a seccomp listener",
        ));
    }
    Ok(())
}

/// Reads [`READY_MARKER`] back from the restricted child, proving that the
/// supervisor can copy worker memory before any worker code runs.
fn verify_child_memory(pid: i32) -> io::Result<()> {
    let memory = File::open(format!("/proc/{pid}/mem")).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "cannot open /proc/{pid}/mem ({err}); the supervisor must be allowed to read its child's memory"
            ),
        )
    })?;
    let mut copy = [0u8; READY_MARKER.len()];
    memory.read_exact_at(&mut copy, READY_MARKER.as_ptr() as u64)?;
    if copy != READY_MARKER {
        return Err(startup_error(
            "the child's memory did not match the expected marker",
        ));
    }
    Ok(())
}

fn release(socket: &UnixStream) -> io::Result<()> {
    (&*socket).write_all(&[sys::READY_BYTE])
}

fn serve(listener: &OwnedFd, gate: &Gate) -> io::Result<Vec<Decision>> {
    let mut decisions = Vec::new();
    loop {
        let mut fds = [PollFd::new(listener, PollFlags::IN)];
        if rustix::event::poll(&mut fds, Some(&IDLE_TIMEOUT))? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the supervisor saw no request and no worker exit for 30 s",
            ));
        }
        let revents = fds[0].revents();
        if revents.contains(PollFlags::IN) {
            match sys::notif_recv(listener.as_fd()) {
                Ok(notif) => decisions.extend(answer(listener, gate, &notif)),
                // The target died or its syscall was interrupted first.
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
                Err(err) => return Err(err),
            }
        } else if revents.intersects(PollFlags::HUP | PollFlags::ERR) {
            // No task uses the filter any more: the worker has exited.
            return Ok(decisions);
        }
    }
}

/// A copied and validated request, or why it cannot proceed.
enum Request {
    /// The notification is no longer pending; nobody is waiting for a reply.
    Cancelled,
    /// Refused before authorization.
    Refused { path: Option<String>, errno: i32 },
    /// A supported read-only open of an absolute path.
    Open { path: String, cloexec: bool },
}

fn answer(listener: &OwnedFd, gate: &Gate, notif: &libc::seccomp_notif) -> Option<Decision> {
    let syscall = i64::from(notif.data.nr);
    let (path, errno) = match copy_request(listener, notif) {
        Request::Cancelled => return None,
        Request::Refused { path, errno } => (path, Some(errno)),
        Request::Open { path, cloexec } => {
            let errno = match authorize(gate, &path) {
                Ok(file) => {
                    match sys::notif_addfd_send(listener.as_fd(), notif.id, file.as_fd(), cloexec) {
                        Ok(_) => None,
                        // Cancelled between authorization and delivery.
                        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return None,
                        Err(err) => Some(err.raw_os_error().unwrap_or(libc::EIO)),
                    }
                }
                Err(errno) => Some(errno),
            };
            (Some(path), errno)
        }
    };
    if let Some(errno) = errno {
        // Fails with ENOENT if the request was cancelled meanwhile; then
        // there is nobody to answer.
        let _ = sys::notif_send_error(listener.as_fd(), notif.id, errno);
    }
    Some(Decision {
        syscall,
        path,
        errno,
    })
}

/// Copies the request's arguments out of the worker once, then validates
/// only that copy (RFC 0004, "Memory, delivery, and audit").
fn copy_request(listener: &OwnedFd, notif: &libc::seccomp_notif) -> Request {
    let args = notif.data.args;
    let refused = |path: Option<String>, errno: i32| Request::Refused { path, errno };
    let (path_addr, flags, how_addr) = match i64::from(notif.data.nr) {
        // `int flags`: the kernel ignores the upper half of the register.
        libc::SYS_open => (args[0], u64::from(args[1] as u32), None),
        libc::SYS_openat => (args[1], u64::from(args[2] as u32), None),
        libc::SYS_openat2 if args[3] != OPEN_HOW_SIZE => return refused(None, libc::EOPNOTSUPP),
        libc::SYS_openat2 => (args[1], 0, Some(args[2])),
        _ => return refused(None, libc::ENOSYS),
    };

    // A fresh memory handle per notification, checked against the
    // notification after opening it and again after copying.
    let memory = match File::open(format!("/proc/{}/mem", notif.pid)) {
        Ok(memory) => memory,
        Err(_) if !sys::notif_id_valid(listener.as_fd(), notif.id) => return Request::Cancelled,
        Err(_) => return refused(None, libc::EACCES),
    };
    if !sys::notif_id_valid(listener.as_fd(), notif.id) {
        return Request::Cancelled;
    }
    let path = read_path(&memory, path_addr);
    let how = how_addr.map(|addr| read_open_how(&memory, addr));
    if !sys::notif_id_valid(listener.as_fd(), notif.id) {
        return Request::Cancelled;
    }
    drop(memory);

    let path = match path.map(String::from_utf8) {
        Ok(Ok(path)) => path,
        Ok(Err(_)) => return refused(None, libc::EILSEQ),
        Err(errno) => return refused(None, errno),
    };
    if let Err(errno) = validate_path(&path) {
        return refused(Some(path), errno);
    }
    let flags = match how {
        None => flags,
        Some(Err(errno)) => return refused(Some(path), errno),
        Some(Ok(how)) if how.mode != 0 => return refused(Some(path), libc::EINVAL),
        // Resolve flags need the strict resolver (step 2); refuse rather
        // than drop their meaning.
        Some(Ok(how)) if how.resolve != 0 => return refused(Some(path), libc::EOPNOTSUPP),
        Some(Ok(how)) => how.flags,
    };
    if let Err(errno) = validate_flags(flags) {
        return refused(Some(path), errno);
    }
    Request::Open {
        path,
        cloexec: flags & libc::O_CLOEXEC as u64 != 0,
    }
}

/// Copies a NUL-terminated path, one page at a time, stopping at
/// [`PATH_MAX`] bytes.
fn read_path(memory: &File, mut addr: u64) -> Result<Vec<u8>, i32> {
    let mut path = Vec::new();
    let mut page = [0u8; PAGE_SIZE as usize];
    while path.len() < PATH_MAX {
        let to_page_end = (PAGE_SIZE - addr % PAGE_SIZE) as usize;
        let want = to_page_end.min(PATH_MAX - path.len());
        let read = match memory.read_at(&mut page[..want], addr) {
            Ok(0) | Err(_) => return Err(libc::EFAULT),
            Ok(read) => read,
        };
        if let Some(end) = page[..read].iter().position(|&byte| byte == 0) {
            path.extend_from_slice(&page[..end]);
            return Ok(path);
        }
        path.extend_from_slice(&page[..read]);
        addr = addr.checked_add(read as u64).ok_or(libc::EFAULT)?;
    }
    Err(libc::ENAMETOOLONG)
}

/// `struct open_how`, copied once into owned memory.
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn read_open_how(memory: &File, addr: u64) -> Result<OpenHow, i32> {
    let mut raw = [0u8; OPEN_HOW_SIZE as usize];
    memory
        .read_exact_at(&mut raw, addr)
        .map_err(|_| libc::EFAULT)?;
    let field = |index: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        u64::from_ne_bytes(bytes)
    };
    Ok(OpenHow {
        flags: field(0),
        mode: field(1),
        resolve: field(2),
    })
}

/// The path rules from RFC 0004's file-open contract, applied before the
/// gate's lexical normalizer ever sees the path.
pub(crate) fn validate_path(path: &str) -> Result<(), i32> {
    if path.is_empty() {
        return Err(libc::ENOENT);
    }
    if !path.starts_with('/') || path.ends_with('/') || path.contains("//") {
        return Err(libc::EOPNOTSUPP);
    }
    if path[1..]
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return Err(libc::EOPNOTSUPP);
    }
    Ok(())
}

/// Read-only opens only, with `O_CLOEXEC` and `O_LARGEFILE` the only extra
/// bits. `O_NOFOLLOW` is refused until the strict resolver exists, since
/// [`Gate::open`] follows symlinks inside a grant.
pub(crate) fn validate_flags(flags: u64) -> Result<(), i32> {
    let access = flags & libc::O_ACCMODE as u64;
    let allowed = libc::O_CLOEXEC as u64 | KERNEL_O_LARGEFILE;
    if access != libc::O_RDONLY as u64 || flags & !(libc::O_ACCMODE as u64 | allowed) != 0 {
        return Err(libc::EOPNOTSUPP);
    }
    Ok(())
}

/// Authorizes through the existing gate. Only regular files are delivered.
fn authorize(gate: &Gate, path: &str) -> Result<File, i32> {
    match gate.open(path) {
        Ok(file) => {
            let metadata = file
                .metadata()
                .map_err(|err| err.raw_os_error().unwrap_or(libc::EIO))?;
            if metadata.is_dir() {
                Err(libc::EISDIR)
            } else if !metadata.is_file() {
                Err(libc::EOPNOTSUPP)
            } else {
                Ok(file)
            }
        }
        Err(GateError::Io { source, .. }) => Err(source.raw_os_error().unwrap_or(libc::EIO)),
        // NoGrant, RightsExceeded, and any future refusal: the gate has
        // already audited the decision.
        Err(_) => Err(libc::EACCES),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_syscalls_jump_to_the_notify_return() {
        let filter = notify_filter();
        let notify = filter.len() - 1;
        assert_eq!(filter[notify].k, libc::SECCOMP_RET_USER_NOTIF);
        for (index, instruction) in filter.iter().enumerate().take(9).skip(6) {
            let target = index + 1 + usize::from(instruction.jt);
            assert_eq!(target, notify, "instruction {index}");
        }
        assert_eq!(filter[notify - 1].k, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn paths_outside_the_contract_are_refused() {
        assert_eq!(validate_path("/srv/data/a.txt"), Ok(()));
        assert_eq!(validate_path(""), Err(libc::ENOENT));
        for path in [
            "a.txt",
            "/srv/data/",
            "/",
            "/srv//data",
            "/srv/./data",
            "/srv/../etc",
            "/srv/..",
        ] {
            assert_eq!(validate_path(path), Err(libc::EOPNOTSUPP), "{path}");
        }
    }

    #[test]
    fn only_read_only_flags_are_accepted() {
        let rdonly = libc::O_RDONLY as u64;
        assert_eq!(validate_flags(rdonly), Ok(()));
        assert_eq!(validate_flags(rdonly | libc::O_CLOEXEC as u64), Ok(()));
        assert_eq!(validate_flags(rdonly | KERNEL_O_LARGEFILE), Ok(()));
        for flags in [
            libc::O_WRONLY,
            libc::O_RDWR,
            libc::O_CREAT,
            libc::O_TRUNC,
            libc::O_PATH,
            libc::O_DIRECTORY,
            libc::O_NOFOLLOW,
            libc::O_TMPFILE,
        ] {
            assert_eq!(
                validate_flags(flags as u64),
                Err(libc::EOPNOTSUPP),
                "{flags:#o}"
            );
        }
    }
}
