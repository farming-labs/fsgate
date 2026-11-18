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
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
use rustix::process::{Pid, PidfdFlags};

use super::runtime::Runtime;
use super::{CopyFault, OPEN_HOW_SIZE, OpenCall, OpenHow, OpenRequest, PATH_MAX, filters, sys};
use crate::{Gate, GateError, Grant, Rights};

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
    /// Replaces the declared interpreter after its rule has been prepared.
    #[cfg_attr(not(test), allow(dead_code))]
    ReplaceLoader { path: PathBuf, with: PathBuf },
    /// After deciding the first request, and before delivering it, the
    /// supervisor interrupts the worker with `SIGUSR1` and waits until the
    /// request is cancelled.
    #[cfg_attr(not(test), allow(dead_code))]
    InterruptFirstRequest,
    /// Cancels the first metadata request immediately before its result copy.
    #[cfg_attr(not(test), allow(dead_code))]
    InterruptFirstMetadata,
}

/// Launches a worker under the RFC 0004 interception profile and answers
/// its file opens from a [`Gate`].
///
/// **Experimental.** Linux x86_64 only, behind the `experimental-intercept`
/// feature, and not covered by semver. The design has not been
/// independently reviewed.
///
/// The worker image must be a regular, native x86_64 ELF executable with no
/// interpreter unless explicitly covered by [`runtime`](Launch::runtime),
/// not set-ID, and without file capabilities. It starts with only stdio open (standard input empty,
/// standard output and error captured), an empty environment, under
/// `no_new_privs`, a Landlock ruleset that allows it nothing but executing
/// its own image and its held loader, and two seccomp filters: one that sends
/// `open`, `openat`, and `openat2` to the supervisor, and the RFC's final syscall
/// allowlist. Data opens are decided by [`Gate::open_intercepted`], which emits
/// one audit event per request through the gate's sink. Runtime opens use
/// distinct audit operations. With runtime grants, the worker cannot create
/// threads or descendants; grant-checked `newfstatat` is mediated too.
///
/// The trusted parent must keep `SIGCHLD` at its default disposition without
/// `SA_NOCLDWAIT` and must not independently reap this owned worker. Startup
/// checks that disposition; runtime-profile cleanup joins the supervisor
/// before reaping, so a metadata write cannot target a recycled PID.
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
    runtime: Vec<PathBuf>,
}

impl Launch {
    /// A launch of `executable`, with no arguments yet.
    pub fn new(executable: impl Into<PathBuf>) -> Launch {
        Launch {
            executable: executable.into(),
            args: Vec::new(),
            runtime: Vec::new(),
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

    /// Grants read access to this runtime file or directory. No runtime paths
    /// are added automatically. Runtime and data grants must not overlap.
    ///
    /// A nonempty runtime list selects the single-process, single-thread
    /// profile. Directory symlinks must stay beneath the held directory;
    /// exact file grants pin the object selected during startup.
    pub fn runtime(&mut self, path: impl Into<PathBuf>) -> &mut Launch {
        self.runtime.push(path.into());
        self
    }

    /// Checks kernel support and the image rule without launching
    /// anything: Landlock ABI 3, seccomp user notifications, and the
    /// executable itself. Fails with `Unsupported` for a missing kernel
    /// feature and `InvalidInput` for an image the profile refuses.
    pub fn check(&self) -> io::Result<()> {
        self.check_grants(None)
    }

    /// Checks startup, including runtime/data overlap, without starting a worker.
    pub fn check_with(&self, gate: &Gate) -> io::Result<()> {
        self.check_grants(Some(gate))
    }

    /// Reads the native ELF interpreter path without executing the image.
    /// Returns `None` for a static image. This does not grant the interpreter.
    pub fn interpreter(&self) -> io::Result<Option<PathBuf>> {
        Ok(check_image(&open_image(&self.executable)?, &self.executable)?.interpreter)
    }

    fn check_grants(&self, data: Option<&Gate>) -> io::Result<()> {
        preflight()?;
        let image = open_image(&self.executable)?;
        let runtime = Runtime::prepare(&self.runtime)?;
        if let Some(data) = data {
            runtime.check_overlap(data)?;
        }
        prepare_loader(&image, &self.executable, &runtime)?;
        if !self.runtime.is_empty() {
            sys::check_child_waitability()?;
        }
        Ok(())
    }

    /// Starts the worker and returns a handle to it while its supervisor
    /// answers requests from `gate`.
    ///
    /// Fails before the worker runs if [`check`](Launch::check) would, or if
    /// any startup step fails; the worker never runs unconfined. The
    /// supervisor answers until the worker exits, or gives up after 30
    /// seconds without a request or an exit, failing any pending open.
    pub fn spawn(&self, gate: Gate) -> io::Result<Running> {
        spawn(
            &self.executable,
            &self.args,
            &self.runtime,
            gate,
            Fault::None,
        )
    }

    /// Runs the worker to completion, with standard input closed, and
    /// returns its exit status and output: [`spawn`](Launch::spawn), then
    /// [`Running::wait`].
    pub fn run(&self, gate: Gate) -> io::Result<Outcome> {
        self.spawn(gate)?.wait()
    }
}

/// A worker started by [`Launch::spawn`], with its supervisor answering
/// requests from the gate.
///
/// [`revoke`](Running::revoke) and [`narrow`](Running::narrow) change the
/// gate while the worker runs. They are serialized with the supervisor: each
/// returns only after any request already being decided has been answered,
/// and every request after that is decided against the changed grants.
/// Neither takes back a descriptor already delivered; the worker keeps
/// reading it.
///
/// Standard output and error are drained in the background and returned by
/// [`wait`](Running::wait). Dropping a `Running` without waiting kills and
/// reaps the worker. Runtime-profile cleanup joins its supervisor first.
pub struct Running {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<JoinHandle<io::Result<Vec<u8>>>>,
    stderr: Option<JoinHandle<io::Result<Vec<u8>>>>,
    supervisor: Option<JoinHandle<io::Result<()>>>,
    gate: Arc<Mutex<Authority>>,
    runtime_profile: bool,
}

impl Running {
    /// The worker's process ID.
    pub fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Takes the writing end of the worker's standard input, a dedicated
    /// pipe. Dropping it, or calling [`wait`](Running::wait), closes it.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    /// Revokes `grant` for every later request (see [`Gate::revoke`]).
    pub fn revoke(&self, grant: Grant) -> Result<(), GateError> {
        lock(&self.gate).data.revoke(grant)
    }

    /// Narrows `grant` for every later request (see [`Gate::narrow`]).
    pub fn narrow(&self, grant: Grant, rights: Rights) -> Result<(), GateError> {
        lock(&self.gate).data.narrow(grant, rights)
    }

    /// Removes an explicit runtime grant for later opens. Already delivered
    /// files, mapped libraries, and the loader execution rule remain usable.
    pub fn revoke_runtime(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut authority = lock(&self.gate);
        let Authority { data, runtime } = &mut *authority;
        runtime.revoke(path.as_ref(), data)
    }

    /// Kills the worker with `SIGKILL`. Call [`wait`](Running::wait)
    /// afterwards to reap it and collect its output.
    pub fn kill(&mut self) -> io::Result<()> {
        match &mut self.child {
            Some(child) => child.kill(),
            None => Ok(()),
        }
    }

    /// Closes standard input, waits for the worker to exit, and returns its
    /// status and output. Fails if the supervisor failed while serving, for
    /// example after 30 seconds without a request or an exit.
    pub fn wait(mut self) -> io::Result<Outcome> {
        drop(self.stdin.take());
        // Retain the owned PID until the last metadata write has finished.
        if self.runtime_profile {
            if let Some(supervisor) = self.supervisor.take() {
                join(supervisor)?;
            }
        }
        let status = match self.child.take() {
            Some(mut child) => child.wait(),
            None => Err(io::Error::other("the worker was already reaped")),
        };
        let stdout = join_output(self.stdout.take());
        let stderr = join_output(self.stderr.take());
        // The supervisor stops once the reaped worker leaves the filter.
        if let Some(supervisor) = self.supervisor.take() {
            join(supervisor)?;
        }
        Ok(Outcome {
            status: status?,
            stdout: stdout?,
            stderr: stderr?,
        })
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            if self.runtime_profile {
                if let Some(supervisor) = self.supervisor.take() {
                    let _ = join(supervisor);
                }
            }
            let _ = child.wait();
        }
    }
}

struct Authority {
    data: Gate,
    runtime: Runtime,
}

/// A grant mutation completes before its audit callback. If that callback
/// panics, revocation must still work through the poisoned lock.
fn lock(gate: &Mutex<Authority>) -> MutexGuard<'_, Authority> {
    gate.lock().unwrap_or_else(PoisonError::into_inner)
}

fn drain(mut pipe: impl Read + Send + 'static) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut output = Vec::new();
        pipe.read_to_end(&mut output)?;
        Ok(output)
    })
}

fn join_output(reader: Option<JoinHandle<io::Result<Vec<u8>>>>) -> io::Result<Vec<u8>> {
    match reader {
        Some(reader) => reader
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("an output reader panicked"))),
        None => Ok(Vec::new()),
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

/// Starts `executable` with `args` as a contained worker whose open-family
/// syscalls are answered from `gate`. A failure before exec, including the
/// supervisor refusing to release the startup barrier, returns the child's
/// error and the worker never runs.
fn spawn(
    executable: &Path,
    args: &[OsString],
    runtime_paths: &[PathBuf],
    gate: Gate,
    fault: Fault,
) -> io::Result<Running> {
    preflight()?;
    let image = open_image(executable)?;
    let runtime_profile = !runtime_paths.is_empty();
    if runtime_profile {
        sys::check_child_waitability()?;
    }
    let runtime = Runtime::prepare(runtime_paths)?;
    runtime.check_overlap(&gate)?;
    let loader = prepare_loader(&image, executable, &runtime)?;
    let ruleset = sys::executable_ruleset(image.as_fd(), loader.as_ref().map(AsFd::as_fd))?;
    runtime.audit_grants(&gate);
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
    let gate = Arc::new(Mutex::new(Authority {
        data: gate,
        runtime,
    }));
    let shared = Arc::clone(&gate);
    let (supervisor_end, child_end) = UnixStream::pair()?;
    // The supervisor holds its end until the child has sent the listener or
    // died, so this number stays valid through the fork.
    let peer = supervisor_end.as_raw_fd();
    let supervisor =
        thread::spawn(move || supervise(supervisor_end, &shared, fault, &target, runtime_profile));

    let mut command = Command::new(executable);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sys::install_child_setup(
        &mut command,
        sys::ChildSetup {
            ruleset: ruleset.as_raw_fd(),
            socket: child_end.as_raw_fd(),
            peer,
            filter: filters::notify_filter(runtime_profile),
            allowlist: filters::final_allowlist(filters::RESERVED_IMAGE_FD, runtime_profile),
            image: image.as_raw_fd(),
            argv,
        },
    );
    let spawned = command.spawn();
    // The parent's copy would hide a dead child from the supervisor.
    drop(child_end);
    drop(ruleset);
    drop(image);

    let mut child = match spawned {
        Ok(child) => child,
        // A supervisor failure explains a failed startup better than the
        // child's errno; otherwise the child's error (a refused barrier, a
        // failed exec) is the answer.
        Err(err) => return Err(join(supervisor).err().unwrap_or(err)),
    };
    Ok(Running {
        stdin: child.stdin.take(),
        stdout: child.stdout.take().map(drain),
        stderr: child.stderr.take().map(drain),
        child: Some(child),
        supervisor: Some(supervisor),
        gate,
        runtime_profile,
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
/// native x86_64 ELF executable, not set-ID, and with
/// no file capabilities. The child later executes this same descriptor.
fn check_image(image: &File, executable: &Path) -> io::Result<crate::intercept_image::Image> {
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

    crate::intercept_image::inspect(image).map_err(|error| {
        io::Error::new(error.kind(), format!("`{}` {error}", executable.display()))
    })
}

fn prepare_loader(image: &File, executable: &Path, runtime: &Runtime) -> io::Result<Option<File>> {
    let inspected = check_image(image, executable)?;
    let Some(path) = inspected.interpreter else {
        return Ok(None);
    };
    let loader = runtime.open_loader(&path)?;
    if check_image(&loader, &path)?.interpreter.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ELF interpreter has its own interpreter; grant a native standalone loader",
        ));
    }
    Ok(Some(loader))
}

fn unsupported(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn join(supervisor: JoinHandle<io::Result<()>>) -> io::Result<()> {
    supervisor
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("supervisor thread panicked")))
}

fn supervise(
    socket: UnixStream,
    gate: &Mutex<Authority>,
    fault: Fault,
    executable: &Path,
    runtime_profile: bool,
) -> io::Result<()> {
    let interrupt_first = fault == Fault::InterruptFirstRequest;
    let interrupt_metadata = fault == Fault::InterruptFirstMetadata;
    let (listener, pid) = receive_listener(&socket)?;
    await_restricted(&socket)?;
    verify_listener(&listener)?;
    verify_child_memory(pid)?;
    let runtime_exit = if runtime_profile {
        let worker = Pid::from_raw(pid).ok_or_else(|| startup_error("invalid worker PID"))?;
        Some(rustix::process::pidfd_open(worker, PidfdFlags::empty())?)
    } else {
        None
    };
    match fault {
        Fault::ReplaceImage { with } => std::fs::rename(with, executable)?,
        Fault::ReplaceLoader { path, with } => std::fs::rename(with, path)?,
        // Dropping the socket without the ready byte fails the barrier.
        Fault::AbortStartup => return Ok(()),
        Fault::CloseListener => {
            drop(listener);
            release(&socket)?;
            return Ok(());
        }
        Fault::None | Fault::InterruptFirstRequest | Fault::InterruptFirstMetadata => {}
    }
    release(&socket)?;
    drop(socket);
    serve(
        &listener,
        gate,
        interrupt_first,
        runtime_profile.then_some(pid),
        interrupt_metadata,
        runtime_exit.as_ref(),
    )
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

fn serve(
    listener: &OwnedFd,
    gate: &Mutex<Authority>,
    mut interrupt_next: bool,
    runtime_pid: Option<i32>,
    mut interrupt_metadata: bool,
    runtime_exit: Option<&OwnedFd>,
) -> io::Result<()> {
    let mut fds = vec![PollFd::new(listener, PollFlags::IN)];
    if let Some(exited) = runtime_exit {
        fds.push(PollFd::new(exited, PollFlags::IN));
    }
    loop {
        if rustix::event::poll(&mut fds, Some(&IDLE_TIMEOUT))? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the supervisor saw no request and no worker exit for 30 s",
            ));
        }
        if let Some(exited) = fds.get(1) {
            let events = exited.revents();
            if events.intersects(PollFlags::ERR | PollFlags::NVAL) {
                return Err(io::Error::other(
                    "cannot poll the runtime worker exit descriptor",
                ));
            }
            if events.intersects(PollFlags::IN | PollFlags::HUP) {
                // The runtime profile cannot leave descendants holding the filter.
                return Ok(());
            }
        }
        let revents = fds[0].revents();
        if revents.contains(PollFlags::IN) {
            match sys::notif_recv(listener.as_fd()) {
                Ok(notif) => answer(
                    listener,
                    gate,
                    &notif,
                    if i64::from(notif.data.nr) == libc::SYS_newfstatat {
                        std::mem::take(&mut interrupt_metadata)
                    } else {
                        std::mem::take(&mut interrupt_next)
                    },
                    runtime_pid,
                ),
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
/// delivers the file or the errno. The gate stays locked from the decision
/// through the delivery, so a concurrent revoke waits for this request and
/// applies to every later one.
fn answer(
    listener: &OwnedFd,
    gate: &Mutex<Authority>,
    notif: &libc::seccomp_notif,
    interrupt: bool,
    runtime_pid: Option<i32>,
) {
    if let Some(pid) = runtime_pid {
        if notif.pid != pid as u32 {
            let _ = sys::notif_send_error(listener.as_fd(), notif.id, libc::EACCES);
            return;
        }
        if i64::from(notif.data.nr) == libc::SYS_newfstatat {
            answer_metadata(listener, gate, notif, pid, interrupt);
            return;
        }
    }
    let request = match copy_request(listener, notif) {
        Copied::Cancelled => return,
        Copied::NotAnOpen => {
            let _ = sys::notif_send_error(listener.as_fd(), notif.id, libc::ENOSYS);
            return;
        }
        Copied::Request(request) => request,
    };
    let gate = lock(gate);
    let opened = gate
        .runtime
        .open(&request, &gate.data)
        .unwrap_or_else(|| gate.data.open_intercepted(&request));
    let errno = match opened {
        Ok(file) => {
            if interrupt {
                interrupt_request(listener, notif);
            }
            match sys::notif_addfd_send(
                listener.as_fd(),
                notif.id,
                file.as_fd(),
                request.wants_cloexec(),
            ) {
                Ok(_) => return,
                // Cancelled between authorization and delivery: `file` is
                // dropped here and nothing was installed in the worker.
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return,
                Err(err) => err.raw_os_error().unwrap_or(libc::EIO),
            }
        }
        Err(err) => err.raw_os_error().unwrap_or(libc::EIO),
    };
    // Fails with ENOENT if the request was cancelled meanwhile; then there
    // is nobody to answer.
    let _ = sys::notif_send_error(listener.as_fd(), notif.id, errno);
}

/// Only the owned worker can reach this handler. Its PID stays unreaped
/// until the supervisor exits, including on cancellation and drop.
fn answer_metadata(
    listener: &OwnedFd,
    authority: &Mutex<Authority>,
    notif: &libc::seccomp_notif,
    pid: i32,
    interrupt: bool,
) {
    let authority = lock(authority);
    let origin = crate::Origin {
        op: crate::AuditOp::Metadata,
        notified: Some(crate::Notified {
            syscall: "newfstatat",
            notification: notif.id,
        }),
    };
    let mut reason = crate::AuditReason::Ok;
    let mut audited = false;
    let mut requested = None;
    let result = (|| -> io::Result<()> {
        if !sys::notif_id_valid(listener.as_fd(), notif.id) {
            return Ok(());
        }
        let args = notif.data.args;
        let flags = args[3] as u32;
        if flags & !(libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT) as u32
            != 0
        {
            reason = crate::AuditReason::UnsupportedInput;
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        let memory = File::open(format!("/proc/{pid}/mem")).inspect_err(|_| {
            reason = crate::AuditReason::InvalidMemory;
        })?;
        let path = read_path(&memory, args[1]).map_err(|fault| {
            reason = crate::AuditReason::InvalidMemory;
            io::Error::from(fault.errno())
        })?;
        let copy = |file: &File| {
            if interrupt {
                interrupt_request(listener, notif);
            }
            if !sys::notif_id_valid(listener.as_fd(), notif.id) {
                return Ok(());
            }
            sys::write_metadata(pid, file.as_fd(), args[2])
        };
        if path.is_empty() {
            let fd = args[0] as i32;
            if fd < 0 || flags & libc::AT_EMPTY_PATH as u32 == 0 {
                reason = crate::AuditReason::UnsupportedInput;
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            let file = rustix::fs::open(
                format!("/proc/{pid}/fd/{fd}"),
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                if error == rustix::io::Errno::NOENT {
                    io::Error::from_raw_os_error(libc::EBADF)
                } else {
                    error.into()
                }
            })?;
            return copy(&File::from(file));
        }
        let nofollow = flags & libc::AT_SYMLINK_NOFOLLOW as u32 != 0;
        let request = OpenRequest {
            notification: notif.id,
            call: OpenCall::Open {
                flags: if nofollow { OFlags::NOFOLLOW.bits() } else { 0 },
            },
            path: Ok(path),
        };
        let path = super::validate(&request).map_err(|refusal| {
            reason = refusal.reason;
            requested = refusal.path.map(PathBuf::from);
            io::Error::from(refusal.errno)
        })?;
        let path = Path::new(&path);
        if let Some(file) = authority.runtime.open_path(path, nofollow, false) {
            let result = file.and_then(|file| copy(&file));
            authority.data.emit(
                crate::Origin {
                    op: crate::AuditOp::RuntimeMetadata,
                    ..origin
                },
                Some(path),
                None,
                crate::AuditDecision::Allow,
                crate::AuditReason::Ok,
                result.as_ref().err().and_then(io::Error::raw_os_error),
            );
            audited = true;
            return result;
        }
        audited = true;
        authority
            .data
            .gated(origin, path, Rights::READ, |entry, rel| {
                let file = super::open_regular_beneath(&entry.dir, rel)?;
                copy(&file)
            })
            .map_err(super::runtime::gate_error)
    })();
    if sys::notif_id_valid(listener.as_fd(), notif.id) {
        if !audited {
            let allowed = reason == crate::AuditReason::Ok;
            authority.data.emit(
                origin,
                requested.as_deref(),
                None,
                if allowed {
                    crate::AuditDecision::Allow
                } else {
                    crate::AuditDecision::Deny
                },
                reason,
                if allowed {
                    result.as_ref().err().and_then(io::Error::raw_os_error)
                } else {
                    None
                },
            );
        }
        let errno = result
            .err()
            .map_or(0, |error| error.raw_os_error().unwrap_or(libc::EIO));
        let _ = sys::notif_send_error(listener.as_fd(), notif.id, errno);
    }
}

/// The `InterruptFirstRequest` fault: signals the worker and waits, without
/// sleeping, until its blocked syscall is cancelled.
#[cfg(test)]
fn interrupt_request(listener: &OwnedFd, notif: &libc::seccomp_notif) {
    let _ = sys::signal(notif.pid as i32, libc::SIGUSR1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while sys::notif_id_valid(listener.as_fd(), notif.id) && std::time::Instant::now() < deadline {
        thread::yield_now();
    }
}

#[cfg(not(test))]
fn interrupt_request(_: &OwnedFd, _: &libc::seccomp_notif) {}

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

    /// `spawn` with a fault, standard input closed, then `wait`.
    fn run(executable: &Path, args: &[OsString], gate: Gate, fault: Fault) -> io::Result<Outcome> {
        let mut running = spawn(executable, args, &[], gate, fault)?;
        drop(running.take_stdin());
        running.wait()
    }

    #[test]
    fn an_unreaped_worker_exit_ends_supervision_without_listener_hangup() {
        use rustix::process::{WaitId, WaitIdOptions, waitid};

        let mut child = Command::new("/bin/true").spawn().unwrap();
        let pid = Pid::from_child(&child);
        let exited = rustix::process::pidfd_open(pid, PidfdFlags::empty()).unwrap();
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .unwrap();
        // Linux 6.6 keeps the seccomp listener open until the child is reaped.
        let (listener, _keep_open) = UnixStream::pair().unwrap();
        let listener: OwnedFd = listener.into();
        let authority = Mutex::new(Authority {
            data: Gate::new(),
            runtime: Runtime::prepare(&[]).unwrap(),
        });
        let result = serve(
            &listener,
            &authority,
            false,
            Some(child.id() as i32),
            false,
            Some(&exited),
        );
        let retained = waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
        );
        let status = child.wait().unwrap();
        result.expect("the worker's exit must end supervision before it is reaped");
        assert!(
            retained.unwrap().is_some(),
            "the child must remain waitable"
        );
        assert!(status.success());
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

    #[test]
    fn a_replaced_interpreter_is_refused_by_its_held_landlock_rule() {
        let fixture = Fixture::new();
        let interpreter = crate::intercept_image::inspect(&File::open("/bin/true").unwrap())
            .unwrap()
            .interpreter
            .unwrap();
        let loader = fixture.root.path().join("loader");
        fs::copy(&interpreter, &loader).unwrap();
        let dynamic = fixture.root.path().join("dynamic");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/worker.c");
        assert!(
            Command::new("cc")
                .args(["-pthread", "-O2", "-o"])
                .arg(&dynamic)
                .arg(format!("-Wl,--dynamic-linker={}", loader.display()))
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        let replacement = fixture.root.path().join("replacement");
        fs::copy(&fixture.worker, &replacement).unwrap();
        let error = match spawn(
            &dynamic,
            &fixture.read_args(),
            std::slice::from_ref(&loader),
            fixture.gate(),
            Fault::ReplaceLoader {
                path: loader.clone(),
                with: replacement,
            },
        ) {
            Ok(_) => panic!("the replaced interpreter must not execute"),
            Err(error) => error,
        };
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        assert_eq!(fs::read(fixture.granted.join("a.txt")).unwrap(), b"inside");
    }

    #[test]
    fn cancelled_metadata_does_not_copy_a_result() {
        let fixture = Fixture::new();
        let worker = fixture.root.path().join("metadata-worker");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dynamic-worker.c");
        assert!(
            Command::new("cc")
                .args(["-static", "-O2", "-Wall", "-Werror", "-o"])
                .arg(&worker)
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        let runtime = fixture.root.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        let args = [
            OsString::from("metadata-cancel"),
            fixture.granted.join("a.txt").into(),
        ];
        let outcome = spawn(
            &worker,
            &args,
            &[runtime],
            fixture.gate(),
            Fault::InterruptFirstMetadata,
        )
        .unwrap()
        .wait()
        .unwrap();
        assert!(
            outcome.status.success(),
            "{:?}: {:?}",
            outcome.status,
            outcome.stderr
        );
        assert_eq!(outcome.stdout, b"ok\n");
    }

    #[test]
    fn an_interrupted_request_delivers_no_descriptor() {
        let fixture = Fixture::new();
        let args = vec![
            "interrupted-open".into(),
            fixture.granted.join("a.txt").into(),
        ];

        let outcome = run(
            &fixture.worker,
            &args,
            fixture.gate(),
            Fault::InterruptFirstRequest,
        )
        .expect("worker run");

        // The open was decided, then cancelled by the signal: the worker sees
        // EINTR and holds no descriptor beyond stdio. The supervisor's copy
        // of the file was dropped when delivery failed.
        assert_eq!(
            outcome.stdout,
            format!("errno={}\ndone\n", libc::EINTR).as_bytes()
        );
    }
}
