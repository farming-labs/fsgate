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
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Gate, GateError, Rights};

/// Upper bound for one wire message; a frame claiming more is a protocol
/// violation and fails the connection closed.
const MAX_FRAME_BYTES: usize = 1 << 20;

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

    /// Accepts connections forever, serving each on its own thread.
    /// Returns only when the listener fails.
    pub fn serve(&self, listener: &UnixListener) -> io::Result<()> {
        std::thread::scope(|scope| {
            loop {
                let (stream, _) = match listener.accept() {
                    Ok(conn) => conn,
                    Err(err) => return Err(err),
                };
                scope.spawn(move || {
                    // A failed connection only ends that connection.
                    let _ = self.serve_conn(stream);
                });
            }
        })
    }

    /// Serves one connection until the peer hangs up.
    pub fn serve_conn(&self, mut stream: UnixStream) -> io::Result<()> {
        loop {
            let frame = match read_frame(&mut stream) {
                Ok((frame, _fds)) => frame,
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
    pub fn connect(socket: impl AsRef<Path>) -> Result<BrokerGate, GateError> {
        let stream = UnixStream::connect(socket.as_ref()).map_err(|source| GateError::Broker {
            message: format!(
                "connecting to broker socket `{}` failed: {source}; \
                 is the broker running?",
                socket.as_ref().display()
            ),
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
        let (frame, fds) = read_frame(&mut self.stream).map_err(transport_lost)?;
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
/// it. Returns `UnexpectedEof` when the peer is gone.
fn read_frame(stream: &mut UnixStream) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut fds = Vec::new();
    let mut acc: Vec<u8> = Vec::new();
    let mut expected: Option<usize> = None;

    loop {
        if let Some(total) = expected {
            if acc.len() >= 4 + total {
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
        let mut space =
            vec![std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut ancillary = rustix::net::RecvAncillaryBuffer::new(&mut space);
        let received = rustix::net::recvmsg(
            &*stream,
            &mut [IoSliceMut::new(&mut buf)],
            &mut ancillary,
            rustix::net::RecvFlags::empty(),
        )?;
        for message in ancillary.drain() {
            if let rustix::net::RecvAncillaryMessage::ScmRights(received_fds) = message {
                fds.extend(received_fds);
            }
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
