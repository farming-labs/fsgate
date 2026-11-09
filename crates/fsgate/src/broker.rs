//! Broker transport: a trusted parent process holds a [`Gate`] and serves
//! filesystem requests over a Unix socket, passing file descriptors back
//! with `SCM_RIGHTS`.
//!
//! The worker process holds no grants of its own; a [`BrokerGate`] sends
//! each request to the broker, where the same [`Gate`] resolution and
//! rights checks run as for in-process use — the worker is never trusted
//! with the decision. When the broker dies, every subsequent operation
//! fails with [`GateError::Broker`]: fail closed, no fallback.
//!
//! Wire format (RFC 0003): each message is a 4-byte little-endian length
//! followed by that many bytes of JSON. A response that carries a file
//! descriptor attaches it as `SCM_RIGHTS` ancillary data on the same
//! message. Paths must be valid UTF-8 on this transport.

use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Write};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{Gate, GateError, Rights};

/// Upper bound for one wire message; a frame claiming more is a protocol
/// violation and fails the connection closed.
const MAX_FRAME_BYTES: usize = 1 << 20;

/// Room for as many descriptors as one message can carry: 253 on Linux
/// (`SCM_MAX_FD`), 254 on macOS. A receive buffer with less truncates
/// them, and macOS still installs the ones that do not fit without
/// reporting them, so nothing could ever close them.
const MAX_FDS_PER_MESSAGE: usize = 254;

/// Whether a frame may arrive with descriptors. Responses may; requests
/// carry none (RFC 0003).
#[derive(Clone, Copy, PartialEq)]
enum Descriptors {
    Accept,
    Refuse,
}

/// Received descriptors must not survive `exec`, like every file std
/// opens. Linux marks them close-on-exec atomically inside `recvmsg`;
/// other platforms mark them right after it (see [`read_frame`]).
#[cfg(any(target_os = "linux", target_os = "android"))]
const RECV_FLAGS: rustix::net::RecvFlags = rustix::net::RecvFlags::CMSG_CLOEXEC;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const RECV_FLAGS: rustix::net::RecvFlags = rustix::net::RecvFlags::empty();

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Open { path: String },
    Create { path: String },
    Metadata { path: String },
    ReadDir { path: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Response {
    /// Success; the file descriptor rides along as ancillary data.
    Fd,
    Stat {
        stat: FileStat,
    },
    Entries {
        entries: Vec<String>,
    },
    Error {
        error: WireError,
    },
}

#[derive(Serialize, Deserialize)]
struct WireError {
    kind: String,
    message: String,
    path: Option<PathBuf>,
    grant_path: Option<PathBuf>,
    missing: Option<u8>,
    op: Option<String>,
    errno: Option<i32>,
}

/// File metadata as reported over the broker transport.
///
/// Deliberately a plain data type rather than [`crate::Metadata`]: only
/// facts that serialize cleanly cross the boundary.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FileStat {
    /// Whether the path is a directory.
    pub is_dir: bool,
    /// Whether the path is a regular file.
    pub is_file: bool,
    /// Size in bytes.
    pub len: u64,
}

/// How [`Broker::serve_with`] admits connections ([RFC 0007]).
///
/// The default admits peers running as the broker's effective user, and
/// at most 64 connections at once.
///
/// [RFC 0007]: https://github.com/farming-labs/fsgate/blob/main/docs/rfcs/0007-broker-peers.md
#[derive(Clone, Debug)]
pub struct ServeOptions {
    peers: Peers,
    max_connections: NonZeroUsize,
}

#[derive(Clone, Debug)]
enum Peers {
    BrokerUser,
    Uids(Vec<u32>),
    Any,
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions {
            peers: Peers::BrokerUser,
            max_connections: NonZeroUsize::new(64).expect("64 is not zero"),
        }
    }
}

impl ServeOptions {
    /// Admits exactly these peer uids, replacing the default of the
    /// broker's own user. For a worker that runs as another user.
    #[must_use]
    pub fn allow_peer_uids(mut self, uids: impl IntoIterator<Item = u32>) -> ServeOptions {
        self.peers = Peers::Uids(uids.into_iter().collect());
        self
    }

    /// Admits every peer that can reach the socket, without checking who
    /// it is. Needed to serve at all on a platform where fsgate cannot
    /// read a peer's identity.
    #[must_use]
    pub fn any_peer(mut self) -> ServeOptions {
        self.peers = Peers::Any;
        self
    }

    /// Sets how many connections are served at once. Past this, each new
    /// connection is closed at once, and its worker fails closed with
    /// [`GateError::Broker`].
    #[must_use]
    pub fn max_connections(mut self, limit: NonZeroUsize) -> ServeOptions {
        self.max_connections = limit;
        self
    }

    /// The uids to admit, or `None` to admit every peer.
    fn allowed_uids(&self) -> io::Result<Option<Vec<u32>>> {
        match &self.peers {
            Peers::Any => Ok(None),
            _ if !CAN_READ_PEER_UID => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fsgate cannot read a peer's identity on this platform; \
                 pass `ServeOptions::any_peer` to serve without the check",
            )),
            Peers::BrokerUser => Ok(Some(vec![rustix::process::geteuid().as_raw()])),
            Peers::Uids(uids) => Ok(Some(uids.clone())),
        }
    }
}

const CAN_READ_PEER_UID: bool = cfg!(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos"
));

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    Ok(rustix::net::sockopt::socket_peercred(stream)?.uid.as_raw())
}

#[cfg(target_os = "macos")]
use crate::broker_sys::peer_uid;

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn peer_uid(_stream: &UnixStream) -> io::Result<u32> {
    Err(io::ErrorKind::Unsupported.into())
}

/// Whether to serve this connection. A peer whose identity cannot be read
/// is refused.
fn is_admitted(stream: &UnixStream, allowed: Option<&[u32]>) -> bool {
    match allowed {
        None => true,
        Some(allowed) => peer_uid(stream).is_ok_and(|uid| allowed.contains(&uid)),
    }
}

/// How long `serve` waits before retrying after running out of a resource.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Whether `accept` failed for lack of something that can come back, as
/// opposed to the listener itself failing.
fn is_temporary(err: &io::Error) -> bool {
    use rustix::io::Errno;

    matches!(
        Errno::from_io_error(err),
        Some(Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOMEM | Errno::CONNABORTED)
    )
}

/// One served connection, counted until it ends, even by a panic.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serves a [`Gate`] to broker clients. The gate's own resolution and
/// rights checks authorize every request; the broker adds no policy.
pub struct Broker {
    gate: Gate,
}

impl Broker {
    /// Wraps a configured gate for serving.
    pub fn new(gate: Gate) -> Broker {
        Broker { gate }
    }

    /// Accepts connections forever with [`ServeOptions::default`]: peers
    /// of the broker's own user, and at most 64 at once. Returns only when
    /// the listener fails.
    pub fn serve(&self, listener: &UnixListener) -> io::Result<()> {
        self.serve_with(listener, ServeOptions::default())
    }

    /// Accepts connections forever, serving each admitted one on its own
    /// thread. A connection that is not admitted is closed with no answer.
    /// While the process is out of descriptors, new connections wait in
    /// the listen backlog. Returns only when the listener fails, or at once
    /// with [`io::ErrorKind::Unsupported`] if `options` needs a peer's
    /// identity and this platform cannot provide it.
    pub fn serve_with(&self, listener: &UnixListener, options: ServeOptions) -> io::Result<()> {
        let allowed = options.allowed_uids()?;
        let active = AtomicUsize::new(0);
        let active = &active;
        std::thread::scope(|scope| {
            loop {
                let (stream, _) = match listener.accept() {
                    Ok(conn) => conn,
                    // Connections being served can free what ran out, and
                    // the new one waits in the listen backlog. Retrying at
                    // once would spin.
                    Err(err) if is_temporary(&err) => {
                        std::thread::sleep(ACCEPT_RETRY);
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                // Checked first, so a refused peer cannot use up the limit.
                if !is_admitted(&stream, allowed.as_deref()) {
                    continue;
                }
                if active.load(Ordering::Acquire) >= options.max_connections.get() {
                    continue;
                }
                // Only this thread adds, so the count cannot pass the limit.
                active.fetch_add(1, Ordering::AcqRel);
                scope.spawn(move || {
                    let _slot = Slot(active);
                    // A failed connection only ends that connection.
                    let _ = self.serve_conn(stream);
                });
            }
        })
    }

    /// Serves one connection until the peer hangs up.
    pub fn serve_conn(&self, mut stream: UnixStream) -> io::Result<()> {
        loop {
            let frame = match read_frame(&mut stream, Descriptors::Refuse) {
                Ok((frame, _)) => frame,
                // Peer closed between requests: a normal end.
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err),
            };
            let request: Request = match serde_json::from_slice(&frame) {
                Ok(request) => request,
                // A malformed request fails the whole connection closed
                // rather than guessing at intent.
                Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            };
            let (response, fd) = self.handle(request);
            let body = serde_json::to_vec(&response)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            write_frame(&mut stream, &body, fd.as_ref().map(File::as_fd))?;
        }
    }

    fn handle(&self, request: Request) -> (Response, Option<File>) {
        match request {
            Request::Open { path } => match self.gate.open(&path) {
                Ok(file) => (Response::Fd, Some(file)),
                Err(err) => (error_response(err), None),
            },
            Request::Create { path } => match self.gate.create(&path) {
                Ok(file) => (Response::Fd, Some(file)),
                Err(err) => (error_response(err), None),
            },
            Request::Metadata { path } => match self.gate.metadata(&path) {
                Ok(meta) => (
                    Response::Stat {
                        stat: FileStat {
                            is_dir: meta.is_dir(),
                            is_file: meta.is_file(),
                            len: meta.len(),
                        },
                    },
                    None,
                ),
                Err(err) => (error_response(err), None),
            },
            Request::ReadDir { path } => match self.gate.read_dir(&path) {
                Ok(entries) => match collect_entry_names(entries) {
                    Ok(entries) => (Response::Entries { entries }, None),
                    Err(err) => (error_response(err), None),
                },
                Err(err) => (error_response(err), None),
            },
        }
    }
}

fn collect_entry_names(entries: crate::ReadDir) -> Result<Vec<String>, GateError> {
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| GateError::Broker {
            message: format!("reading a directory entry failed: {source}"),
        })?;
        match entry.file_name().into_string() {
            Ok(name) => names.push(name),
            Err(name) => {
                return Err(GateError::Broker {
                    message: format!(
                        "directory entry {name:?} is not valid UTF-8; \
                         the broker protocol requires UTF-8 names"
                    ),
                });
            }
        }
    }
    Ok(names)
}

fn error_response(err: GateError) -> Response {
    let mut wire = WireError {
        kind: String::new(),
        message: err.to_string(),
        path: None,
        grant_path: None,
        missing: None,
        op: None,
        errno: None,
    };
    match err {
        GateError::NotAbsolute { path } => {
            wire.kind = "not_absolute".into();
            wire.path = Some(path);
        }
        GateError::NoGrant { path } => {
            wire.kind = "no_grant".into();
            wire.path = Some(path);
        }
        GateError::RightsExceeded {
            path,
            grant_path,
            missing,
            op,
        } => {
            wire.kind = "rights_exceeded".into();
            wire.path = Some(path);
            wire.grant_path = Some(grant_path);
            wire.missing = Some(missing.bits());
            wire.op = Some(op);
        }
        GateError::Io { path, source } => {
            wire.kind = "io".into();
            wire.path = Some(path);
            wire.errno = source.raw_os_error();
        }
        GateError::UnknownGrant
        | GateError::WouldWiden { .. }
        | GateError::Locked
        | GateError::LockUnsupported { .. }
        | GateError::LockFailed { .. }
        | GateError::Broker { .. } => {
            wire.kind = "broker".into();
        }
    }
    Response::Error { error: wire }
}

/// A [`Gate`]-shaped client whose authority lives in the broker process.
///
/// Compared with [`Gate`]: `metadata` returns the serializable
/// [`FileStat`] and `read_dir` returns entry names, because those results
/// cross a process boundary. `open` and `create` return real
/// [`File`]s — the descriptor itself travels over the socket.
pub struct BrokerGate {
    stream: UnixStream,
}

impl BrokerGate {
    /// Connects to a broker's Unix socket (conventionally published to
    /// workers in the `FSGATE_BROKER_SOCKET` environment variable).
    ///
    /// A worker that also calls [`Gate::lock`] connects first: on Linux 7.1
    /// and later the lock refuses new connects
    /// ([`Restrictions::RESOLVE_UNIX`](crate::Restrictions::RESOLVE_UNIX)),
    /// and a connection made before it keeps working.
    pub fn connect(socket: impl AsRef<Path>) -> Result<BrokerGate, GateError> {
        let stream = UnixStream::connect(socket.as_ref()).map_err(|source| {
            let remedy = if source.kind() == io::ErrorKind::PermissionDenied {
                "connect before calling `lock`, which refuses new connects on Linux 7.1 \
                 and later, or check the socket's permissions"
            } else {
                "is the broker running?"
            };
            GateError::Broker {
                message: format!(
                    "connecting to broker socket `{}` failed: {source}; {remedy}",
                    socket.as_ref().display()
                ),
            }
        })?;
        Ok(BrokerGate { stream })
    }

    /// Wraps an already-connected stream (e.g. an inherited socketpair).
    pub fn from_stream(stream: UnixStream) -> BrokerGate {
        BrokerGate { stream }
    }

    /// Opens an existing file for reading via the broker.
    pub fn open(&mut self, path: impl AsRef<Path>) -> Result<File, GateError> {
        let path = utf8_path(path.as_ref())?;
        let (response, mut fds) = self.request(&Request::Open { path })?;
        expect_fd(response, &mut fds)
    }

    /// Creates (or truncates) a file for writing via the broker.
    pub fn create(&mut self, path: impl AsRef<Path>) -> Result<File, GateError> {
        let path = utf8_path(path.as_ref())?;
        let (response, mut fds) = self.request(&Request::Create { path })?;
        expect_fd(response, &mut fds)
    }

    /// Reads metadata via the broker.
    pub fn metadata(&mut self, path: impl AsRef<Path>) -> Result<FileStat, GateError> {
        let path = utf8_path(path.as_ref())?;
        match self.request(&Request::Metadata { path })? {
            (Response::Stat { stat }, _) => Ok(stat),
            (response, _) => Err(unexpected(response)),
        }
    }

    /// Lists directory entry names via the broker.
    pub fn read_dir(&mut self, path: impl AsRef<Path>) -> Result<Vec<String>, GateError> {
        let path = utf8_path(path.as_ref())?;
        match self.request(&Request::ReadDir { path })? {
            (Response::Entries { entries }, _) => Ok(entries),
            (response, _) => Err(unexpected(response)),
        }
    }

    fn request(&mut self, request: &Request) -> Result<(Response, Vec<OwnedFd>), GateError> {
        let body = serde_json::to_vec(request).map_err(|err| GateError::Broker {
            message: format!("encoding the request failed: {err}"),
        })?;
        write_frame(&mut self.stream, &body, None).map_err(transport_lost)?;
        let (frame, fds) =
            read_frame(&mut self.stream, Descriptors::Accept).map_err(transport_lost)?;
        let response: Response =
            serde_json::from_slice(&frame).map_err(|err| GateError::Broker {
                message: format!("broker sent a malformed response: {err}"),
            })?;
        if let Response::Error { error } = response {
            return Err(remote_error(error));
        }
        Ok((response, fds))
    }
}

fn utf8_path(path: &Path) -> Result<String, GateError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| GateError::Broker {
            message: format!(
                "path {path:?} is not valid UTF-8; \
                 the broker protocol requires UTF-8 paths"
            ),
        })
}

fn expect_fd(response: Response, fds: &mut Vec<OwnedFd>) -> Result<File, GateError> {
    match response {
        Response::Fd => match (fds.len(), fds.pop()) {
            (1, Some(fd)) => Ok(File::from(fd)),
            _ => Err(GateError::Broker {
                message: "broker response did not carry exactly one file descriptor".into(),
            }),
        },
        other => Err(unexpected(other)),
    }
}

fn unexpected(_response: Response) -> GateError {
    GateError::Broker {
        message: "broker sent a response of the wrong type for the request".into(),
    }
}

fn transport_lost(source: io::Error) -> GateError {
    GateError::Broker {
        message: format!(
            "broker connection lost ({source}); all filesystem operations fail closed"
        ),
    }
}

fn remote_error(error: WireError) -> GateError {
    match error.kind.as_str() {
        "not_absolute" => GateError::NotAbsolute {
            path: error.path.unwrap_or_default(),
        },
        "no_grant" => GateError::NoGrant {
            path: error.path.unwrap_or_default(),
        },
        "rights_exceeded" => GateError::RightsExceeded {
            path: error.path.unwrap_or_default(),
            grant_path: error.grant_path.unwrap_or_default(),
            missing: Rights::from_bits_truncate(error.missing.unwrap_or(0)),
            op: error.op.unwrap_or_default(),
        },
        "io" => GateError::Io {
            path: error.path.unwrap_or_default(),
            source: match error.errno {
                Some(errno) => io::Error::from_raw_os_error(errno),
                None => io::Error::other(error.message.clone()),
            },
        },
        _ => GateError::Broker {
            message: error.message,
        },
    }
}

/// Writes one frame, attaching `fd` as ancillary data when present. The
/// ancillary payload rides on the first byte of the frame.
fn write_frame(stream: &mut UnixStream, body: &[u8], fd: Option<BorrowedFd>) -> io::Result<()> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds the protocol size limit",
        ));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);

    let mut sent = 0;
    if let Some(fd) = fd {
        let fds = [fd];
        let mut space =
            vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
        ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&fds));
        sent = rustix::net::sendmsg(
            &*stream,
            &[IoSlice::new(&frame)],
            &mut ancillary,
            rustix::net::SendFlags::empty(),
        )?;
    }
    stream.write_all(&frame[sent..])
}

/// Reads one frame, collecting any file descriptors delivered alongside
/// it, each marked close-on-exec. Returns `UnexpectedEof` when the peer
/// is gone.
///
/// Without `MSG_CMSG_CLOEXEC` (macOS and other non-Linux systems), a
/// thread that forks and execs between `recvmsg` and `fcntl` can still
/// inherit a descriptor; nothing outside the kernel can close that window.
fn read_frame(
    stream: &mut UnixStream,
    descriptors: Descriptors,
) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut fds = Vec::new();
    let mut acc: Vec<u8> = Vec::new();
    let mut expected: Option<usize> = None;

    loop {
        if let Some(total) = expected {
            if acc.len() > 4 + total {
                // A lockstep peer sends nothing past a frame before its
                // response. Extra bytes mean the prefix understates the body
                // or the peer pipelined; acting on either would guess.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer sent bytes beyond the declared frame length",
                ));
            }
            if acc.len() == 4 + total {
                let frame = acc.split_off(4);
                debug_assert!(acc.len() == 4);
                return Ok((frame, fds));
            }
        } else if acc.len() >= 4 {
            let len = u32::from_le_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
            if len > MAX_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame exceeds the protocol size limit",
                ));
            }
            expected = Some(len);
            continue;
        }

        let mut buf = [0u8; 65536];
        let mut space = vec![
            std::mem::MaybeUninit::<u8>::uninit();
            rustix::cmsg_space!(ScmRights(MAX_FDS_PER_MESSAGE))
        ];
        let mut ancillary = rustix::net::RecvAncillaryBuffer::new(&mut space);
        let received = rustix::net::recvmsg(
            &*stream,
            &mut [IoSliceMut::new(&mut buf)],
            &mut ancillary,
            RECV_FLAGS,
        )?;
        for message in ancillary.drain() {
            if let rustix::net::RecvAncillaryMessage::ScmRights(received_fds) = message {
                for fd in received_fds {
                    // On failure, `?` drops (closes) this descriptor and
                    // every other one received so far.
                    #[cfg(not(any(target_os = "linux", target_os = "android")))]
                    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
                    fds.push(fd);
                }
            }
        }
        if received.flags.contains(rustix::net::ReturnFlags::CTRUNC) {
            // The buffer holds every descriptor Linux and macOS let one
            // message carry, so this is another platform or a full
            // descriptor table. Descriptors that did not fit may be open
            // here unreported; only the reported ones can be closed.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer attached more descriptors than could be received",
            ));
        }
        if descriptors == Descriptors::Refuse && !fds.is_empty() {
            // Refused at the first one, before the rest of the frame, so a
            // peer cannot pile them up by splitting a request across
            // messages. Returning closes what was received.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer attached a file descriptor to a request; requests carry none",
            ));
        }
        if received.bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "broker peer closed the connection",
            ));
        }
        acc.extend_from_slice(&buf[..received.bytes]);
    }
}
