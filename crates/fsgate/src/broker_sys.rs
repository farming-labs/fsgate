//! The `unsafe` the broker needs, kept apart from its logic.
//!
//! # Safety contract
//!
//! Each block here is limited to what a safe caller cannot get wrong.
//! System calls take descriptors from a live borrow and out-pointers from
//! locals that outlive the call, and nothing here keeps a pointer past
//! the call. A raw descriptor number is adopted only once it is shown to
//! be open, and at most once. Nothing else in the broker uses `unsafe`.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;

use rustix::io::FdFlags;
use rustix::net::{AddressFamily, SocketType};

/// Takes ownership of the descriptor numbered `raw` if it is a Unix stream
/// socket, and marks it close-on-exec. A descriptor this refuses stays
/// open, because it may belong to someone else.
///
/// The caller must not call this twice for one number: the first call
/// owns it.
pub(crate) fn adopt_unix_stream(raw: RawFd) -> io::Result<UnixStream> {
    // `/dev/fd/N` exists only while N is open, so the `unsafe` below never
    // sees a closed number.
    let file_type = std::fs::metadata(format!("/dev/fd/{raw}"))?.file_type();
    if !file_type.is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the descriptor is not a socket",
        ));
    }
    // SAFETY: `raw` is open, checked just above, and is not -1. Taking
    // ownership is sound because the caller adopts a number once, and the
    // parent named this number for this process to own. See the module
    // contract.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    match prepare(&fd) {
        Ok(()) => Ok(UnixStream::from(fd)),
        Err(err) => {
            // Give the number back rather than close it.
            let _ = fd.into_raw_fd();
            Err(err)
        }
    }
}

fn prepare(fd: &OwnedFd) -> io::Result<()> {
    let is_stream = rustix::net::sockopt::socket_type(fd)? == SocketType::STREAM;
    let family = rustix::net::getsockname(fd)?.address_family();
    if !is_stream || family != AddressFamily::UNIX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the descriptor is not a Unix stream socket",
        ));
    }
    rustix::io::fcntl_setfd(fd, FdFlags::CLOEXEC)?;
    Ok(())
}

/// The peer's effective uid, as the kernel recorded it at connect.
/// `rustix` does not wrap `getpeereid`.
#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &std::os::unix::net::UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the descriptor is open for the borrow of `stream`, and both
    // pointers are to locals that outlive this call. See the module
    // contract.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}
