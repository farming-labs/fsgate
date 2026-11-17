//! Pre-lock inspection of visible io_uring resources (RFC 0014).
//!
//! This is a precondition on trusted setup, not a kernel restriction.
//! Hidden rings and concurrent changes remain outside its guarantee.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{CWD, Dir, Mode, OFlags, PROC_SUPER_MAGIC, fstatfs, openat, readlinkat};

use crate::GateError;

fn inspection(path: &Path, source: impl Into<io::Error>) -> GateError {
    GateError::IoUringInspection {
        path: path.to_owned(),
        source: source.into(),
    }
}

fn open_proc(
    parent: impl AsFd,
    name: &Path,
    path: &Path,
    directory: bool,
) -> Result<OwnedFd, GateError> {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    // Only /proc/self is a link. Every subsequent component is opened
    // relative to a held directory and must not be another link.
    if path != Path::new("/proc/self") {
        flags |= OFlags::NOFOLLOW;
    }
    let fd = openat(parent, name, flags, Mode::empty()).map_err(|err| inspection(path, err))?;
    let stat = fstatfs(&fd).map_err(|err| inspection(path, err))?;
    if stat.f_type != PROC_SUPER_MAGIC {
        return Err(inspection(
            path,
            io::Error::new(io::ErrorKind::InvalidData, "expected a procfs entry"),
        ));
    }
    Ok(fd)
}

fn entries(fd: impl AsFd, path: &Path) -> Result<Dir, GateError> {
    Dir::read_from(fd).map_err(|err| inspection(path, err))
}

/// Check every visible thread, including unshared descriptor tables.
pub(crate) fn check() -> Result<(), GateError> {
    let root_path = Path::new("/proc/self");
    let root = open_proc(CWD, root_path, root_path, true)?;
    let tasks_path = root_path.join("task");
    let tasks = open_proc(&root, Path::new("task"), &tasks_path, true)?;
    for entry in entries(&tasks, &tasks_path)? {
        let entry = entry.map_err(|err| inspection(&tasks_path, err))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = Path::new(std::ffi::OsStr::from_bytes(name));
        let task_path = tasks_path.join(name);
        let task = open_proc(&tasks, name, &task_path, true)?;
        let comm_path = task_path.join("comm");
        let comm = open_proc(&task, Path::new("comm"), &comm_path, false)?;
        let mut name = Vec::new();
        File::from(comm)
            .read_to_end(&mut name)
            .map_err(|err| inspection(&comm_path, err))?;
        if name.starts_with(b"iou-sqp-") {
            return Err(GateError::IoUringPresent { path: comm_path });
        }
        let fds_path = task_path.join("fd");
        let fds = open_proc(&task, Path::new("fd"), &fds_path, true)?;
        for entry in entries(&fds, &fds_path)? {
            let entry = entry.map_err(|err| inspection(&fds_path, err))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name = Path::new(std::ffi::OsStr::from_bytes(name));
            let path: PathBuf = fds_path.join(name);
            let target =
                readlinkat(&fds, name, Vec::new()).map_err(|err| inspection(&path, err))?;
            if target.to_bytes() == b"anon_inode:[io_uring]" {
                return Err(GateError::IoUringPresent { path });
            }
        }
    }
    Ok(())
}
