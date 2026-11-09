//! The `unsafe` the broker needs, kept apart from its logic.
//!
//! # Safety contract
//!
//! System calls here take descriptors from a live borrow and out-pointers
//! from locals that outlive the call, and nothing keeps a pointer past the
//! call.
//!
//! Adopting a raw descriptor number rests on the environment:
//! `FSGATE_BROKER_FD` is the parent's statement that this process owns that
//! number. [`adopt_unix_stream`] narrows what it will believe. The number
//! must be open, a Unix stream socket, and not close-on-exec, which an
//! inherited descriptor cannot be and everything `std` opens is. A process
//! that leaves an unrelated Unix stream socket inheritable at that number,
//! and names it in the variable, gives that socket up. Nothing else in the
//! broker uses `unsafe`.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;

use rustix::io::FdFlags;
use rustix::net::{AddressFamily, SocketType};

/// Takes ownership of the inherited descriptor numbered `raw` if it is a
/// Unix stream socket, and marks it close-on-exec. A descriptor this
/// refuses stays open, because it may belong to someone else.
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
    // SAFETY: `raw` is open, checked just above, and is not -1. `prepare`
    // releases it unless it is an inherited Unix stream socket, which is
    // what the parent named for this process to own. See the module
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
    // This tells an inherited connection from a stale number that now
    // names something this process opened, or adopted already.
    if rustix::io::fcntl_getfd(fd)?.contains(FdFlags::CLOEXEC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the descriptor is close-on-exec, so it was not inherited",
        ));
    }
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

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    /// A worker's child inherits the variable but not the descriptor, so
    /// the number can name a socket of its own. Adopting that would close
    /// it twice.
    #[test]
    fn a_socket_this_process_opened_is_not_adopted() {
        let (ours, _peer) = UnixStream::pair().unwrap();

        let err = adopt_unix_stream(ours.as_raw_fd()).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert!(rustix::io::fcntl_getfd(&ours).is_ok(), "it was closed");
    }
}
