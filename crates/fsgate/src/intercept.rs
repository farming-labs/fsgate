//! The strict regular-file open of the RFC 0004 interception profile.
//!
//! [`open_regular_beneath`] never opens anything for I/O until it knows the
//! object is a regular file outside procfs and sysfs, and what it opens is
//! the object it checked: it resolves an `O_PATH` handle beneath the grant
//! with every symlink and magic link refused, inspects that handle, and
//! reopens the same handle through the process's pinned `/proc/self/fd`.
//! A rename, a symlink, or a FIFO swapped in after the check is never
//! followed or opened.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use cap_std::fs::Dir;
use rustix::fs::{FileType, FsWord, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags};
use rustix::io::Errno;
use rustix::path::DecInt;

/// `SYSFS_MAGIC` from `linux/magic.h`.
const SYSFS_MAGIC: FsWord = 0x6265_6572;

/// Opens the regular file at `rel` beneath `dir`, read-only.
///
/// Fails with `ELOOP` for any symlink on the way, `EISDIR` for a directory,
/// and `EOPNOTSUPP` for FIFOs, devices, sockets, and procfs or sysfs files,
/// none of which is opened for I/O.
pub(crate) fn open_regular_beneath(dir: &Dir, rel: &Path) -> io::Result<File> {
    let handle = resolve_beneath(dir, rel)?;
    reopen_regular(&handle)
}

/// Resolves `rel` beneath `dir` to an `O_PATH` handle. The kernel refuses
/// escapes, symlinks, and magic links during the walk.
fn resolve_beneath(dir: &Dir, rel: &Path) -> io::Result<OwnedFd> {
    Ok(rustix::fs::openat2(
        dir,
        rel,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?)
}

/// Checks that `handle` names a regular file outside procfs and sysfs, then
/// opens that same object read-only and confirms the result is the file
/// that was checked.
fn reopen_regular(handle: &OwnedFd) -> io::Result<File> {
    let checked = rustix::fs::fstat(handle)?;
    match FileType::from_raw_mode(checked.st_mode) {
        FileType::RegularFile => {}
        FileType::Directory => return Err(Errno::ISDIR.into()),
        _ => return Err(Errno::OPNOTSUPP.into()),
    }
    let filesystem = rustix::fs::fstatfs(handle)?.f_type as FsWord;
    if filesystem == PROC_SUPER_MAGIC || filesystem == SYSFS_MAGIC {
        return Err(Errno::OPNOTSUPP.into());
    }
    // The name is this process's own descriptor number, never a path the
    // caller supplied, and the directory is the verified `/proc/self/fd`.
    let opened = rustix::fs::openat(
        rustix_linux_procfs::proc_self_fd()?,
        DecInt::from_fd(handle),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )?;
    let reopened = rustix::fs::fstat(&opened)?;
    if (reopened.st_dev, reopened.st_ino) != (checked.st_dev, checked.st_ino) {
        return Err(Errno::STALE.into());
    }
    Ok(File::from(opened))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;

    use cap_std::ambient_authority;

    fn granted() -> (tempfile::TempDir, Dir) {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), b"original").unwrap();
        let dir = Dir::open_ambient_dir(root.path(), ambient_authority()).unwrap();
        (root, dir)
    }

    fn read(mut file: File) -> String {
        let mut out = String::new();
        file.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn a_fifo_renamed_over_the_checked_path_is_never_opened() {
        let (root, dir) = granted();
        let handle = resolve_beneath(&dir, Path::new("a.txt")).unwrap();

        // Swap a FIFO in under the same name between the check and the open.
        let fifo = root.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        std::fs::rename(&fifo, root.path().join("a.txt")).unwrap();

        // The reopen reaches the original file and does not block on the FIFO.
        assert_eq!(read(reopen_regular(&handle).unwrap()), "original");
    }

    #[test]
    fn a_symlink_renamed_over_the_checked_path_is_never_followed() {
        let (root, dir) = granted();
        std::fs::write(root.path().join("other.txt"), b"other").unwrap();
        let handle = resolve_beneath(&dir, Path::new("a.txt")).unwrap();

        std::os::unix::fs::symlink("other.txt", root.path().join("link")).unwrap();
        std::fs::rename(root.path().join("link"), root.path().join("a.txt")).unwrap();

        assert_eq!(read(reopen_regular(&handle).unwrap()), "original");
    }
}
