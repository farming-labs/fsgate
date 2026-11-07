//! The experimental launcher and its supervisor. Everything here is safe
//! code; the raw interfaces live in the private `sys` module, the BPF
//! programs in `filters`.

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{self, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};

use super::{CopyFault, OPEN_HOW_SIZE, OpenCall, OpenHow, OpenRequest, PATH_MAX, filters, sys};
use crate::Gate;

/// Known bytes the supervisor reads back from the restricted child before
/// releasing it. The child is a fork of this process, so the static sits at
/// the same address there.
static READY_MARKER: [u8; 16] = *b"fsgate-launch-ok";

/// How long the supervisor waits for a request or the worker's exit before
/// giving up and closing the listener, which fails any pending open.
const IDLE_TIMEOUT: Timespec = Timespec {
    tv_sec: 30,
    tv_nsec: 0,
};

/// Base page size on x86_64; path copies never cross a page in one read.
const PAGE_SIZE: u64 = 4096;

/// Fault injection for the startup, supervisor-loss, and image tests.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Fault {
    /// Normal operation.
    None,
    /// The supervisor closes its listener before releasing the startup
    /// barrier, as if it died right after startup.
    #[cfg_attr(not(test), allow(dead_code))]
    CloseListener,
    /// The supervisor never releases the startup barrier.
    #[cfg_attr(not(test), allow(dead_code))]
    AbortStartup,
    /// After the image is checked and before the child execs, the
    /// supervisor renames `with` over the executable path.
    #[cfg_attr(not(test), allow(dead_code))]
    ReplaceImage { with: PathBuf },
}

/// Launches a worker under the RFC 0004 interception profile and answers
/// its file opens from a [`Gate`].
///
/// **Experimental.** Linux x86_64 only, behind the `experimental-intercept`
/// feature, and not covered by semver. The design has not been
/// independently reviewed.
///
/// The worker image must be a regular, native x86_64 ELF executable with no
/// interpreter (statically linked), not set-ID, and without file
/// capabilities. It starts with only stdio open (standard input empty,
/// standard output and error captured), an empty environment, under
/// `no_new_privs`, a Landlock ruleset that allows it nothing but executing
/// its own image, and two seccomp filters: one that sends `open`, `openat`,
/// and `openat2` to the supervisor, and the RFC's final syscall allowlist.
/// Each notified open is decided by [`Gate::open_intercepted`], which emits
/// one audit event per request through the gate's sink.
///
/// ```no_run
/// use fsgate::{Gate, Rights};
/// use fsgate::intercept::Launch;
///
/// # fn main() -> std::io::Result<()> {
/// let mut gate = Gate::new();
/// gate.grant("/srv/data", Rights::READ).map_err(std::io::Error::other)?;
///
/// let outcome = Launch::new("/opt/tools/report")
///     .arg("/srv/data/input.csv")
///     .run(gate)?;
/// assert!(outcome.status.success());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Launch {
    executable: PathBuf,
    args: Vec<OsString>,
}

impl Launch {
    /// A launch of `executable`, with no arguments yet.
    pub fn new(executable: impl Into<PathBuf>) -> Launch {
        Launch {
            executable: executable.into(),
            args: Vec::new(),
        }
    }

    /// Appends one argument. `argv[0]` is the executable path.
    pub fn arg(&mut self, arg: impl Into<OsString>) -> &mut Launch {
        self.args.push(arg.into());
        self
    }

    /// Appends several arguments.
    pub fn args<I, S>(&mut self, args: I) -> &mut Launch
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Checks kernel support and the image rule without launching
    /// anything: Landlock ABI 3, seccomp user notifications, and the
    /// executable itself. Fails with `Unsupported` for a missing kernel
    /// feature and `InvalidInput` for an image the profile refuses.
    pub fn check(&self) -> io::Result<()> {
        preflight()?;
        let image = open_image(&self.executable)?;
        check_image(&image, &self.executable)
    }

    /// Runs the worker to completion and returns its exit status and
    /// output.
    ///
    /// Fails before the worker runs if [`check`](Launch::check) would, or if
    /// any startup step fails; the worker never runs unconfined. After it
    /// starts, the supervisor answers requests until the worker exits, or
    /// gives up after 30 seconds without a request or an exit, failing any
    /// pending open.
    pub fn run(&self, gate: Gate) -> io::Result<Outcome> {
        run(&self.executable, &self.args, gate, Fault::None)
    }
}

/// What a finished worker left behind.
#[derive(Debug)]
#[non_exhaustive]
pub struct Outcome {
    /// The worker's exit status.
    pub status: ExitStatus,
    /// Everything the worker wrote to standard output.
    pub stdout: Vec<u8>,
    /// Everything the worker wrote to standard error.
    pub stderr: Vec<u8>,
}

/// Opens the image once, without blocking on a FIFO at the path; the image
/// check then refuses anything but a regular file.
fn open_image(executable: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::open(
        executable,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )?))
}

/// Runs `executable` with `args` as a contained worker whose open-family
/// syscalls are answered from `gate`. A failure before exec, including the
/// supervisor refusing to release the startup barrier, returns the child's
/// error and the worker never runs.
fn run(executable: &Path, args: &[OsString], gate: Gate, fault: Fault) -> io::Result<Outcome> {
    preflight()?;
    let image = open_image(executable)?;
    check_image(&image, executable)?;
    let ruleset = sys::executable_ruleset(image.as_fd())?;
    let argv = std::iter::once(executable.as_os_str())
        .chain(args.iter().map(OsString::as_os_str))
        .map(|arg| {
            CString::new(arg.as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an argument contains a NUL byte; pass arguments without NUL",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let target = executable.to_path_buf();
    let (supervisor_end, child_end) = UnixStream::pair()?;
    // The supervisor holds its end until the child has sent the listener or
    // died, so this number stays valid through the fork.
    let peer = supervisor_end.as_raw_fd();
    let supervisor = thread::spawn(move || supervise(supervisor_end, gate, fault, &target));

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
            filter: filters::notify_filter(),
            allowlist: filters::final_allowlist(filters::RESERVED_IMAGE_FD),
            image: image.as_raw_fd(),
            argv,
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
    join(supervisor)?;
    let output = output?;
    Ok(Outcome {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn preflight() -> io::Result<()> {
    let abi = sys::landlock_abi().map_err(|err| {
        unsupported(format!(
            "landlock is unavailable ({err}); interception needs Landlock ABI 3 (Linux 6.2+) enabled"
        ))
    })?;
    if abi < 3 {
        return Err(unsupported(format!(
            "landlock ABI {abi} is too old; interception needs ABI 3 (Linux 6.2+)"
        )));
    }
    sys::user_notif_available().map_err(|err| {
        unsupported(format!(
            "seccomp user notifications are unavailable ({err}); interception needs Linux 5.14+ with seccomp enabled"
        ))
    })
}

/// The RFC 0004 image rule, checked on the held image itself: a regular,
/// native x86_64 ELF executable with no interpreter, not set-ID, and with
/// no file capabilities. The child later executes this same descriptor.
fn check_image(image: &File, executable: &Path) -> io::Result<()> {
    let refuse = |problem: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{}` {problem}", executable.display()),
        )
    };
    let stat = rustix::fs::fstat(image)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(refuse(
            "is not a regular file; pass the worker executable itself",
        ));
    }
    if stat.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0 {
        return Err(refuse(
            "is set-user-ID or set-group-ID; the worker image must not change privileges on exec",
        ));
    }
    match rustix::fs::fgetxattr_query(image, "security.capability") {
        Ok(_) => {
            return Err(refuse(
                "has file capabilities; remove them with `setcap -r` or pick another image",
            ));
        }
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::OPNOTSUPP) => {}
        Err(err) => return Err(err.into()),
    }

    let not_elf = || {
        refuse("is not an ELF executable (scripts are not supported); pass a static native binary")
    };
    let mut header = [0u8; 64];
    image.read_exact_at(&mut header, 0).map_err(|_| not_elf())?;
    let u16_at = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    if header[..4] != *b"\x7fELF" {
        return Err(not_elf());
    }
    // ELFCLASS64, ELFDATA2LSB, EM_X86_64, and ET_EXEC or ET_DYN (static PIE).
    if header[4] != 2 || header[5] != 1 || u16_at(18) != 62 {
        return Err(refuse(
            "is not a 64-bit x86_64 ELF; the interception profile supports native x86_64 only",
        ));
    }
    if !matches!(u16_at(16), 2 | 3) {
        return Err(not_elf());
    }
    let mut phoff = [0u8; 8];
    phoff.copy_from_slice(&header[32..40]);
    let (phoff, entry_size, entries) = (u64::from_le_bytes(phoff), u16_at(54), u16_at(56));
    // Elf64_Phdr is 56 bytes; 0xffff (PN_XNUM) and absurd counts are refused.
    if entry_size != 56 || entries == 0 || entries > 1024 {
        return Err(refuse("has an unsupported program header table"));
    }
    let mut table = vec![0u8; 56 * usize::from(entries)];
    image
        .read_exact_at(&mut table, phoff)
        .map_err(|_| refuse("has a truncated program header table"))?;
    const PT_INTERP: [u8; 4] = 3u32.to_le_bytes();
    if table.chunks_exact(56).any(|entry| entry[..4] == PT_INTERP) {
        return Err(refuse(
            "needs an ELF interpreter (it is dynamically linked); build it static, for example with `cc -static`",
        ));
    }
    Ok(())
}

fn unsupported(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn join(supervisor: JoinHandle<io::Result<()>>) -> io::Result<()> {
    supervisor
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("supervisor thread panicked")))
}

fn supervise(socket: UnixStream, gate: Gate, fault: Fault, executable: &Path) -> io::Result<()> {
    let (listener, pid) = receive_listener(&socket)?;
    await_restricted(&socket)?;
    verify_listener(&listener)?;
    verify_child_memory(pid)?;
    match fault {
        Fault::ReplaceImage { with } => std::fs::rename(with, executable)?,
        // Dropping the socket without the ready byte fails the barrier.
        Fault::AbortStartup => return Ok(()),
        Fault::CloseListener => {
            drop(listener);
            release(&socket)?;
            return Ok(());
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

/// Waits for the child to report that both filters are installed, so the
/// memory check below reads a fully restricted child.
fn await_restricted(socket: &UnixStream) -> io::Result<()> {
    let mut byte = [0u8; 1];
    match (&*socket).read(&mut byte) {
        Ok(1) if byte[0] == sys::RESTRICTED_BYTE => Ok(()),
        _ => Err(startup_error(
            "the child exited before installing its syscall allowlist",
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
    (&*socket).write_all(&[sys::RELEASE_BYTE])
}

fn serve(listener: &OwnedFd, gate: &Gate) -> io::Result<()> {
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
                Ok(notif) => answer(listener, gate, &notif),
                // The target died or its syscall was interrupted first.
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
                Err(err) => return Err(err),
            }
        } else if revents.intersects(PollFlags::HUP | PollFlags::ERR) {
            // No task uses the filter any more: the worker has exited.
            return Ok(());
        }
    }
}

/// What the supervisor copied for one notification.
enum Copied {
    /// The notification is no longer pending; nobody is waiting for a reply.
    Cancelled,
    /// A syscall the filter should never have notified.
    NotAnOpen,
    /// An open request, its arguments copied once.
    Request(OpenRequest),
}

/// Answers one notification: the gate decides and audits; the supervisor
/// delivers the file or the errno.
fn answer(listener: &OwnedFd, gate: &Gate, notif: &libc::seccomp_notif) {
    let request = match copy_request(listener, notif) {
        Copied::Cancelled => return,
        Copied::NotAnOpen => {
            let _ = sys::notif_send_error(listener.as_fd(), notif.id, libc::ENOSYS);
            return;
        }
        Copied::Request(request) => request,
    };
    let errno = match gate.open_intercepted(&request) {
        Ok(file) => match sys::notif_addfd_send(
            listener.as_fd(),
            notif.id,
            file.as_fd(),
            request.wants_cloexec(),
        ) {
            Ok(_) => return,
            // Cancelled between authorization and delivery.
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return,
            Err(err) => err.raw_os_error().unwrap_or(libc::EIO),
        },
        Err(err) => err.raw_os_error().unwrap_or(libc::EIO),
    };
    // Fails with ENOENT if the request was cancelled meanwhile; then there
    // is nobody to answer.
    let _ = sys::notif_send_error(listener.as_fd(), notif.id, errno);
}

/// Copies the request's arguments out of the worker once (RFC 0004,
/// "Memory, delivery, and audit"). Validation happens in fsgate, on this
/// copy only.
fn copy_request(listener: &OwnedFd, notif: &libc::seccomp_notif) -> Copied {
    let args = notif.data.args;
    // `int flags`: the kernel ignores the upper half of the register.
    let (path_addr, call, how_addr) = match i64::from(notif.data.nr) {
        libc::SYS_open => (
            args[0],
            OpenCall::Open {
                flags: args[1] as u32,
            },
            None,
        ),
        libc::SYS_openat => (
            args[1],
            OpenCall::Openat {
                flags: args[2] as u32,
            },
            None,
        ),
        libc::SYS_openat2 => {
            let size = args[3];
            let how = Err(CopyFault::Unreadable);
            let how_addr = (size == OPEN_HOW_SIZE).then_some(args[2]);
            (args[1], OpenCall::Openat2 { size, how }, how_addr)
        }
        _ => return Copied::NotAnOpen,
    };
    let request = |call, path| {
        Copied::Request(OpenRequest {
            notification: notif.id,
            call,
            path,
        })
    };

    // A fresh memory handle per notification, checked against the
    // notification after opening it and again after copying.
    let Ok(memory) = File::open(format!("/proc/{}/mem", notif.pid)) else {
        if !sys::notif_id_valid(listener.as_fd(), notif.id) {
            return Copied::Cancelled;
        }
        return request(call, Err(CopyFault::Inaccessible));
    };
    if !sys::notif_id_valid(listener.as_fd(), notif.id) {
        return Copied::Cancelled;
    }
    let path = read_path(&memory, path_addr);
    let call = match (call, how_addr) {
        (OpenCall::Openat2 { size, .. }, Some(addr)) => OpenCall::Openat2 {
            size,
            how: read_open_how(&memory, addr),
        },
        (call, _) => call,
    };
    if !sys::notif_id_valid(listener.as_fd(), notif.id) {
        return Copied::Cancelled;
    }
    request(call, path)
}

/// Copies a NUL-terminated path, one page at a time, stopping at
/// [`PATH_MAX`] bytes.
fn read_path(memory: &File, mut addr: u64) -> Result<Vec<u8>, CopyFault> {
    let mut path = Vec::new();
    let mut page = [0u8; PAGE_SIZE as usize];
    while path.len() < PATH_MAX {
        let to_page_end = (PAGE_SIZE - addr % PAGE_SIZE) as usize;
        let want = to_page_end.min(PATH_MAX - path.len());
        let read = match memory.read_at(&mut page[..want], addr) {
            Ok(0) | Err(_) => return Err(CopyFault::Unreadable),
            Ok(read) => read,
        };
        if let Some(end) = page[..read].iter().position(|&byte| byte == 0) {
            path.extend_from_slice(&page[..end]);
            return Ok(path);
        }
        path.extend_from_slice(&page[..read]);
        addr = addr.checked_add(read as u64).ok_or(CopyFault::Unreadable)?;
    }
    Err(CopyFault::Unterminated)
}

/// Copies `struct open_how` once into owned memory.
fn read_open_how(memory: &File, addr: u64) -> Result<OpenHow, CopyFault> {
    let mut raw = [0u8; OPEN_HOW_SIZE as usize];
    memory
        .read_exact_at(&mut raw, addr)
        .map_err(|_| CopyFault::Unreadable)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use crate::Rights;

    /// A temporary directory with a granted `a.txt` and the worker fixture,
    /// built with `cc -static` (`tests/fixtures/worker.c`).
    struct Fixture {
        root: tempfile::TempDir,
        worker: PathBuf,
        granted: PathBuf,
    }

    impl Fixture {
        fn new() -> Fixture {
            let root = tempfile::tempdir().unwrap();
            let granted = root.path().join("granted");
            fs::create_dir(&granted).unwrap();
            fs::write(granted.join("a.txt"), b"inside").unwrap();
            let worker = root.path().join("worker");
            let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/worker.c");
            let status = Command::new("cc")
                .args(["-static", "-pthread", "-O2", "-Wall", "-Werror", "-o"])
                .arg(&worker)
                .arg(&source)
                .status()
                .expect("run cc; the launcher tests need a C compiler and static libc (libc6-dev)");
            assert!(
                status.success(),
                "cc -static failed for {}",
                source.display()
            );
            Fixture {
                root,
                worker,
                granted,
            }
        }

        fn gate(&self) -> Gate {
            let mut gate = Gate::new();
            gate.grant(&self.granted, Rights::READ).unwrap();
            gate
        }

        fn read_args(&self) -> Vec<OsString> {
            vec!["read".into(), self.granted.join("a.txt").into()]
        }
    }

    #[test]
    fn an_aborted_startup_never_executes_the_worker() {
        let fixture = Fixture::new();

        let err = run(
            &fixture.worker,
            &fixture.read_args(),
            fixture.gate(),
            Fault::AbortStartup,
        )
        .expect_err("startup must fail before exec");

        assert_eq!(err.raw_os_error(), Some(libc::ECANCELED), "{err}");
    }

    #[test]
    fn a_closed_listener_fails_later_opens_with_enosys() {
        let fixture = Fixture::new();

        let outcome = run(
            &fixture.worker,
            &fixture.read_args(),
            fixture.gate(),
            Fault::CloseListener,
        )
        .expect("worker run");

        // No supervisor, no open: the kernel fails the notified call.
        assert_eq!(
            outcome.stdout,
            format!("errno={}\n", libc::ENOSYS).as_bytes()
        );
    }

    #[test]
    fn the_checked_image_runs_even_after_its_path_is_replaced() {
        let fixture = Fixture::new();
        let script = fixture.root.path().join("swapped");
        fs::write(&script, "#!/bin/sh\necho swapped\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let outcome = run(
            &fixture.worker,
            &fixture.read_args(),
            fixture.gate(),
            Fault::ReplaceImage { with: script },
        )
        .expect("worker run");

        // The child executed the held descriptor, not what the path names now.
        assert_eq!(outcome.stdout, b"inside");
        assert_eq!(
            fs::read(&fixture.worker).unwrap(),
            b"#!/bin/sh\necho swapped\n"
        );
    }
}
