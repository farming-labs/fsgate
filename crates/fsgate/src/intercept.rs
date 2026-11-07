//! Experimental building blocks for RFC 0004 filesystem interception.
//!
//! **Experimental.** Linux only, behind the `experimental-intercept`
//! feature, and not covered by semver.
//!
//! A supervisor that receives seccomp notifications for a worker's
//! `open`, `openat`, and `openat2` copies each request's arguments once
//! out of the worker, describes them as an [`OpenRequest`], and passes it
//! to [`Gate::open_intercepted`](crate::Gate::open_intercepted). That
//! validates the copy against the profile's file-open contract, authorizes
//! it with [`Gate::open_regular_strict`](crate::Gate::open_regular_strict),
//! and emits exactly one audit event, including for requests refused
//! before any grant is matched.
//!
//! The strict open never opens anything for I/O until it knows the object
//! is a regular file outside procfs and sysfs, and what it opens is the
//! object it checked: it resolves an `O_PATH` handle beneath the grant with
//! every symlink and magic link refused, inspects that handle, and reopens
//! the same handle through the process's pinned `/proc/self/fd`. A rename,
//! a symlink, or a FIFO swapped in after the check is never followed or
//! opened.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use cap_std::fs::Dir;
use rustix::fs::{FileType, FsWord, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags};
use rustix::io::Errno;
use rustix::path::DecInt;

use crate::AuditReason;

/// `SYSFS_MAGIC` from `linux/magic.h`.
const SYSFS_MAGIC: FsWord = 0x6265_6572;

/// Longest accepted path in bytes, terminator included.
pub const PATH_MAX: usize = 4096;

/// `sizeof(struct open_how)`: the only `openat2` layout accepted.
pub const OPEN_HOW_SIZE: u64 = 24;

/// Why an argument could not be copied out of the worker's memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CopyFault {
    /// The worker's memory could not be opened at all, for example because
    /// the worker is no longer traceable. Answered with `EACCES`.
    Inaccessible,
    /// The address could not be read. Answered with `EFAULT`.
    Unreadable,
    /// No terminator within [`PATH_MAX`] bytes. Answered with
    /// `ENAMETOOLONG`.
    Unterminated,
}

impl CopyFault {
    fn errno(self) -> Errno {
        match self {
            CopyFault::Inaccessible => Errno::ACCESS,
            CopyFault::Unreadable => Errno::FAULT,
            CopyFault::Unterminated => Errno::NAMETOOLONG,
        }
    }
}

/// `struct open_how` from `linux/openat2.h`, copied out of the worker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenHow {
    /// The open flags.
    pub flags: u64,
    /// The creation mode; must be zero.
    pub mode: u64,
    /// The `RESOLVE_*` flags.
    pub resolve: u64,
}

/// The notified syscall and its open flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenCall {
    /// `open(path, flags, mode)`, with the `int flags` argument.
    Open {
        /// The open flags.
        flags: u32,
    },
    /// `openat(dirfd, path, flags, mode)`. The directory argument is
    /// ignored: only absolute paths are accepted.
    Openat {
        /// The open flags.
        flags: u32,
    },
    /// `openat2(dirfd, path, how, size)`.
    Openat2 {
        /// The `size` argument. Anything but [`OPEN_HOW_SIZE`] is refused
        /// without looking at `how`.
        size: u64,
        /// The copied `open_how`, or why it could not be copied.
        how: Result<OpenHow, CopyFault>,
    },
}

impl OpenCall {
    /// The syscall's name, as recorded in the audit event.
    pub const fn name(&self) -> &'static str {
        match self {
            OpenCall::Open { .. } => "open",
            OpenCall::Openat { .. } => "openat",
            OpenCall::Openat2 { .. } => "openat2",
        }
    }
}

/// One notified open request, with its arguments copied once out of the
/// worker. Validation and authorization use only this copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    /// The seccomp notification ID, recorded in the audit event.
    pub notification: u64,
    /// The syscall and its flags.
    pub call: OpenCall,
    /// The path bytes without the terminator, or why they could not be
    /// copied.
    pub path: Result<Vec<u8>, CopyFault>,
}

impl OpenRequest {
    /// Whether the caller asked for `O_CLOEXEC`, which the delivered
    /// descriptor must keep.
    pub fn wants_cloexec(&self) -> bool {
        let flags = match self.call {
            OpenCall::Open { flags } | OpenCall::Openat { flags } => u64::from(flags),
            OpenCall::Openat2 { how: Ok(how), .. } => how.flags,
            OpenCall::Openat2 { how: Err(_), .. } => 0,
        };
        flags & u64::from(OFlags::CLOEXEC.bits()) != 0
    }
}

/// A request refused before authorization.
pub(crate) struct Refusal {
    /// The requested path, when a valid one was copied.
    pub(crate) path: Option<String>,
    pub(crate) reason: AuditReason,
    pub(crate) errno: Errno,
}

/// Applies the RFC 0004 file-open contract to the copied request and
/// returns the path to authorize. Nothing here touches the filesystem.
pub(crate) fn validate(request: &OpenRequest) -> Result<String, Refusal> {
    let refuse = |path: Option<&str>, reason, errno| Refusal {
        path: path.map(str::to_owned),
        reason,
        errno,
    };
    let path = match &request.path {
        Ok(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| refuse(None, AuditReason::UnsupportedInput, Errno::ILSEQ))?,
        Err(fault) => return Err(refuse(None, AuditReason::InvalidMemory, fault.errno())),
    };
    validate_path(path)
        .map_err(|errno| refuse(Some(path), AuditReason::UnsupportedInput, errno))?;
    let flags = match request.call {
        OpenCall::Open { flags } | OpenCall::Openat { flags } => u64::from(flags),
        OpenCall::Openat2 { size, how } => {
            if size != OPEN_HOW_SIZE {
                return Err(refuse(
                    Some(path),
                    AuditReason::UnsupportedInput,
                    Errno::OPNOTSUPP,
                ));
            }
            let how =
                how.map_err(|fault| refuse(Some(path), AuditReason::InvalidMemory, fault.errno()))?;
            if how.mode != 0 {
                return Err(refuse(
                    Some(path),
                    AuditReason::UnsupportedInput,
                    Errno::INVAL,
                ));
            }
            // The strict open already refuses every symlink and magic link;
            // anything else is refused rather than silently dropped.
            let enforced = (ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS).bits();
            if how.resolve & !enforced != 0 {
                return Err(refuse(
                    Some(path),
                    AuditReason::UnsupportedInput,
                    Errno::OPNOTSUPP,
                ));
            }
            how.flags
        }
    };
    validate_flags(flags)
        .map_err(|errno| refuse(Some(path), AuditReason::UnsupportedInput, errno))?;
    Ok(path.to_owned())
}

/// Absolute paths only, without `.` or `..` components, repeated
/// separators, or a trailing separator; an empty path is `ENOENT`.
fn validate_path(path: &str) -> Result<(), Errno> {
    if path.is_empty() {
        return Err(Errno::NOENT);
    }
    if !path.starts_with('/') || path.ends_with('/') || path.contains("//") {
        return Err(Errno::OPNOTSUPP);
    }
    if path[1..]
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return Err(Errno::OPNOTSUPP);
    }
    Ok(())
}

/// Read-only opens only, with `O_CLOEXEC`, `O_NOFOLLOW`, and `O_LARGEFILE`
/// the only extra bits. `O_NOFOLLOW` is honored because the strict open
/// refuses every symlink.
fn validate_flags(flags: u64) -> Result<(), Errno> {
    let bits = |flags: OFlags| u64::from(flags.bits());
    let allowed = bits(OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::LARGEFILE);
    let access = flags & bits(OFlags::ACCMODE);
    if access != bits(OFlags::RDONLY) || flags & !(bits(OFlags::ACCMODE) | allowed) != 0 {
        return Err(Errno::OPNOTSUPP);
    }
    Ok(())
}

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

    fn openat(path: &str, flags: OFlags) -> OpenRequest {
        OpenRequest {
            notification: 1,
            call: OpenCall::Openat {
                flags: flags.bits(),
            },
            path: Ok(path.as_bytes().to_vec()),
        }
    }

    fn openat2(how: Result<OpenHow, CopyFault>, size: u64) -> OpenRequest {
        OpenRequest {
            notification: 1,
            call: OpenCall::Openat2 { size, how },
            path: Ok(b"/srv/a.txt".to_vec()),
        }
    }

    fn refusal(request: &OpenRequest) -> (Option<String>, AuditReason, Errno) {
        let refusal = validate(request).map(drop).unwrap_err();
        (refusal.path, refusal.reason, refusal.errno)
    }

    #[test]
    fn read_only_absolute_requests_pass_validation() {
        assert_eq!(
            validate(&openat("/srv/a.txt", OFlags::RDONLY))
                .ok()
                .as_deref(),
            Some("/srv/a.txt")
        );
        for flags in [OFlags::CLOEXEC, OFlags::NOFOLLOW, OFlags::LARGEFILE] {
            assert!(validate(&openat("/srv/a.txt", flags)).is_ok(), "{flags:?}");
        }
    }

    #[test]
    fn copy_faults_are_invalid_memory_with_no_path() {
        for (fault, errno) in [
            (CopyFault::Inaccessible, Errno::ACCESS),
            (CopyFault::Unreadable, Errno::FAULT),
            (CopyFault::Unterminated, Errno::NAMETOOLONG),
        ] {
            let mut request = openat("/srv/a.txt", OFlags::RDONLY);
            request.path = Err(fault);
            assert_eq!(refusal(&request), (None, AuditReason::InvalidMemory, errno));
        }
    }

    #[test]
    fn paths_outside_the_contract_are_unsupported_input() {
        let mut request = openat("", OFlags::RDONLY);
        request.path = Ok(vec![b'/', 0xff]);
        assert_eq!(
            refusal(&request),
            (None, AuditReason::UnsupportedInput, Errno::ILSEQ)
        );
        assert_eq!(
            refusal(&openat("", OFlags::RDONLY)),
            (
                Some(String::new()),
                AuditReason::UnsupportedInput,
                Errno::NOENT
            )
        );
        for path in [
            "a.txt",
            "/srv/",
            "/",
            "/srv//a",
            "/srv/./a",
            "/srv/../etc",
            "/srv/..",
        ] {
            assert_eq!(
                refusal(&openat(path, OFlags::RDONLY)),
                (
                    Some(path.to_owned()),
                    AuditReason::UnsupportedInput,
                    Errno::OPNOTSUPP
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn writes_and_other_flags_are_unsupported_input() {
        for flags in [
            OFlags::WRONLY,
            OFlags::RDWR,
            OFlags::CREATE,
            OFlags::TRUNC,
            OFlags::PATH,
            OFlags::DIRECTORY,
            OFlags::TMPFILE,
        ] {
            let (_, reason, errno) = refusal(&openat("/srv/a.txt", flags));
            assert_eq!(
                (reason, errno),
                (AuditReason::UnsupportedInput, Errno::OPNOTSUPP),
                "{flags:?}"
            );
        }
    }

    #[test]
    fn openat2_needs_the_known_layout_zero_mode_and_enforced_resolve_flags() {
        let enforced = (ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS).bits();
        let how = |mode, resolve| {
            Ok(OpenHow {
                flags: 0,
                mode,
                resolve,
            })
        };
        assert!(validate(&openat2(how(0, enforced), OPEN_HOW_SIZE)).is_ok());
        assert_eq!(
            refusal(&openat2(how(0, 0), 32)),
            (
                Some("/srv/a.txt".to_owned()),
                AuditReason::UnsupportedInput,
                Errno::OPNOTSUPP
            )
        );
        assert_eq!(
            refusal(&openat2(Err(CopyFault::Unreadable), OPEN_HOW_SIZE)),
            (
                Some("/srv/a.txt".to_owned()),
                AuditReason::InvalidMemory,
                Errno::FAULT
            )
        );
        assert_eq!(
            refusal(&openat2(how(0o644, 0), OPEN_HOW_SIZE)).2,
            Errno::INVAL
        );
        assert_eq!(
            refusal(&openat2(
                how(0, ResolveFlags::BENEATH.bits()),
                OPEN_HOW_SIZE
            ))
            .2,
            Errno::OPNOTSUPP
        );
    }

    #[test]
    fn cloexec_comes_from_the_callers_flags() {
        assert!(!openat("/srv/a.txt", OFlags::RDONLY).wants_cloexec());
        assert!(openat("/srv/a.txt", OFlags::CLOEXEC).wants_cloexec());
        let how = OpenHow {
            flags: u64::from(OFlags::CLOEXEC.bits()),
            ..OpenHow::default()
        };
        assert!(openat2(Ok(how), OPEN_HOW_SIZE).wants_cloexec());
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
