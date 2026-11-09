//! The `unsafe` the broker needs, kept apart from its logic.
//!
//! # Safety contract
//!
//! Each block here calls one operating system function with arguments
//! that a safe caller cannot make invalid: descriptors come from a live
//! borrow, and out-pointers from locals that outlive the call. Nothing
//! here keeps a pointer past the call, and nothing else in the broker
//! uses `unsafe`.

#![allow(unsafe_code)]

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
