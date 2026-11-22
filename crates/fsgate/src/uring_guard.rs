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

/// `PF_IO_WORKER` (`include/linux/sched.h`): the task is an io_uring
/// thread, either an `SQPOLL` thread or an io-wq worker.
const PF_IO_WORKER: u64 = 0x10;

/// Whether a task's `stat` describes an io_uring thread that may hold a
/// ring: any `PF_IO_WORKER` task except an io-wq worker that has named
/// itself `iou-wrk-<pid>`. The kernel sets the flag before the task is
/// visible, but a new `SQPOLL` thread keeps its creator's name until it
/// first runs and names itself `iou-sqp-<pid>`, so the name alone misses
/// it. An io-wq worker runs work with each request's own credentials, and
/// one can stay idle after its rings are closed.
fn holds_a_ring(stat: &[u8]) -> Option<bool> {
    // The name, in parentheses, may itself contain spaces and `)`.
    let open = stat.iter().position(|&byte| byte == b'(')?;
    let close = stat.iter().rposition(|&byte| byte == b')')?;
    let name = stat.get(open + 1..close)?;
    let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    // Fields 3 to 8 come first: state, ppid, pgrp, session, tty_nr, tpgid.
    let flags: u64 = rest.split_ascii_whitespace().nth(6)?.parse().ok()?;
    Some(flags & PF_IO_WORKER != 0 && !name.starts_with(b"iou-wrk-"))
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
        let stat_path = task_path.join("stat");
        let stat = open_proc(&task, Path::new("stat"), &stat_path, false)?;
        let mut contents = Vec::new();
        File::from(stat)
            .read_to_end(&mut contents)
            .map_err(|err| inspection(&stat_path, err))?;
        match holds_a_ring(&contents) {
            Some(false) => {}
            Some(true) => return Err(GateError::IoUringPresent { path: stat_path }),
            None => {
                return Err(inspection(
                    &stat_path,
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected task `stat` format"),
                ));
            }
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

#[cfg(test)]
mod tests {
    use super::holds_a_ring;

    #[test]
    fn reads_the_flags_after_the_name() {
        // 0x400040: `PF_RANDOMIZE | PF_FORKNOEXEC`, not an io worker.
        let plain = b"42 (my (odd) name) S 1 42 42 0 -1 4194368 100 0 0 0";
        assert_eq!(holds_a_ring(plain), Some(false));
        // 0x10 set, still named like its creator.
        let unnamed = b"43 (test-thread) S 1 42 42 0 -1 4194384 0 0 0 0";
        assert_eq!(holds_a_ring(unnamed), Some(true));
        let sqpoll = b"44 (iou-sqp-42) S 1 42 42 0 -1 2097232 0 0 0 0";
        assert_eq!(holds_a_ring(sqpoll), Some(true));
        let worker = b"45 (iou-wrk-42) S 1 42 42 0 -1 2097232 0 0 0 0";
        assert_eq!(holds_a_ring(worker), Some(false));
        assert_eq!(holds_a_ring(b"46 (cut"), None);
        assert_eq!(holds_a_ring(b"47 (short) S 1 2"), None);
    }
}
