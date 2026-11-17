//! Explicit runtime authority, separate from data grants (RFC 0015).

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};
use rustix::path::DecInt;

use super::{OpenCall, OpenRequest, reopen_regular, validate};
use crate::{
    AuditDecision, AuditOp, AuditReason, DirId, Gate, GateError, Grant, Notified, Origin, Rights,
};

pub(super) struct Runtime {
    directories: Gate,
    entries: Vec<Entry>,
}

struct Entry {
    path: PathBuf,
    ancestry: Vec<DirId>,
    target: Target,
}

enum Target {
    Directory(Grant),
    File(OwnedFd),
}

impl Runtime {
    pub(super) fn prepare(paths: &[PathBuf]) -> io::Result<Self> {
        let mut runtime = Self {
            directories: Gate::new(),
            entries: Vec::new(),
        };
        for path in paths {
            let path = crate::normalize(path).map_err(gate_error)?;
            if runtime.entries.iter().any(|entry| entry.path == path) {
                return Err(invalid(format!(
                    "duplicate runtime grant `{}`; declare each path once",
                    path.display()
                )));
            }
            let handle = rustix::fs::open(&path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?;
            let stat = rustix::fs::fstat(&handle)?;
            let (target, ancestry) = match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    let grant = runtime
                        .directories
                        .grant(&path, Rights::READ)
                        .map_err(gate_error)?;
                    let entry = runtime.directories.grants[grant.index]
                        .as_ref()
                        .expect("new grant");
                    if crate::dir_id(&rustix::fs::fstat(&entry.dir)?) != crate::dir_id(&stat) {
                        return Err(invalid(
                            "runtime directory changed during setup; keep grants stable",
                        ));
                    }
                    (Target::Directory(grant), entry.ancestry.clone())
                }
                FileType::RegularFile => {
                    drop(reopen_regular(&handle)?);
                    let ancestry = file_ancestry(&handle)?;
                    (Target::File(handle), ancestry)
                }
                _ => {
                    return Err(invalid(
                        "runtime grant is not a regular file or directory; select runtime files or their directory",
                    ));
                }
            };
            runtime.entries.push(Entry {
                path,
                ancestry,
                target,
            });
        }
        Ok(runtime)
    }

    pub(super) fn check_overlap(&self, data: &Gate) -> io::Result<()> {
        for runtime in &self.entries {
            for entry in data.grants.iter().flatten() {
                let related = runtime.ancestry.contains(&entry.ancestry[0])
                    || (matches!(runtime.target, Target::Directory(_))
                        && entry.ancestry.contains(&runtime.ancestry[0]));
                if related
                    || runtime.path.starts_with(&entry.path)
                    || entry.path.starts_with(&runtime.path)
                {
                    return Err(invalid(format!(
                        "runtime grant `{}` overlaps data grant `{}`; use separate runtime and data paths",
                        runtime.path.display(),
                        entry.path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    pub(super) fn audit_grants(&self, data: &Gate) {
        for entry in &self.entries {
            data.emit_rights(
                AuditOp::RuntimeGrant,
                Some(&entry.path),
                None,
                Rights::READ,
                AuditDecision::Allow,
                AuditReason::Ok,
            );
        }
    }

    pub(super) fn open(&self, request: &OpenRequest, data: &Gate) -> Option<io::Result<File>> {
        let validated = validate(request).ok()?;
        let path = Path::new(&validated);
        let (flags, resolve) = match request.call {
            OpenCall::Open { flags } | OpenCall::Openat { flags } => (u64::from(flags), 0),
            OpenCall::Openat2 { how: Ok(how), .. } => (how.flags, how.resolve),
            OpenCall::Openat2 { how: Err(_), .. } => return None,
        };
        let result = self.open_path(
            path,
            flags & u64::from(OFlags::NOFOLLOW.bits()) != 0,
            resolve & ResolveFlags::NO_SYMLINKS.bits() != 0,
        )?;
        data.emit(
            Origin {
                op: AuditOp::RuntimeOpen,
                notified: Some(Notified {
                    syscall: request.call.name(),
                    notification: request.notification,
                }),
            },
            Some(path),
            None,
            AuditDecision::Allow,
            AuditReason::Ok,
            result.as_ref().err().and_then(io::Error::raw_os_error),
        );
        Some(result)
    }

    pub(super) fn open_loader(&self, path: &Path) -> io::Result<File> {
        self.open_path(path, false, false).ok_or_else(|| invalid(format!("needs an ELF interpreter `{}` with an explicit runtime grant; add this path with `Launch::runtime` or `--runtime`", path.display())))?
    }

    pub(super) fn open_path(
        &self,
        path: &Path,
        nofollow: bool,
        no_symlinks: bool,
    ) -> Option<io::Result<File>> {
        let entry = self
            .entries
            .iter()
            .filter(|entry| match entry.target {
                Target::File(_) => path == entry.path,
                Target::Directory(_) => path.starts_with(&entry.path),
            })
            .max_by_key(|entry| entry.path.components().count())?;
        Some(match &entry.target {
            Target::File(handle) => reopen_regular(handle),
            Target::Directory(_) => self
                .directories
                .gated(AuditOp::RuntimeOpen, path, Rights::READ, |dir, rel| {
                    let mut flags = OFlags::PATH | OFlags::CLOEXEC;
                    if nofollow {
                        flags |= OFlags::NOFOLLOW;
                    }
                    let mut resolve = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS;
                    if no_symlinks {
                        resolve |= ResolveFlags::NO_SYMLINKS;
                    }
                    let handle = rustix::fs::openat2(&dir.dir, rel, flags, Mode::empty(), resolve)?;
                    if FileType::from_raw_mode(rustix::fs::fstat(&handle)?.st_mode)
                        == FileType::Symlink
                    {
                        return Err(io::Error::from_raw_os_error(libc::ELOOP));
                    }
                    reopen_regular(&handle)
                })
                .map_err(gate_error),
        })
    }

    pub(super) fn revoke(&mut self, path: &Path, data: &Gate) -> io::Result<()> {
        let path = crate::normalize(path).map_err(gate_error)?;
        let index = self
            .entries
            .iter()
            .position(|entry| entry.path == path)
            .ok_or_else(|| {
                invalid(format!(
                    "no runtime grant for `{}`; name an active declared runtime path",
                    path.display()
                ))
            })?;
        if let Target::Directory(grant) = self.entries[index].target {
            self.directories.revoke(grant).map_err(gate_error)?;
        }
        self.entries.remove(index);
        data.emit(
            AuditOp::RuntimeRevoke,
            Some(&path),
            None,
            AuditDecision::Allow,
            AuditReason::Ok,
            None,
        );
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(super) fn gate_error(error: GateError) -> io::Error {
    match error {
        GateError::Io { source, .. } => source,
        GateError::NoGrant { .. } | GateError::RightsExceeded { .. } => {
            io::Error::from_raw_os_error(libc::EACCES)
        }
        error => invalid(error.to_string()),
    }
}

fn file_ancestry(handle: &OwnedFd) -> io::Result<Vec<DirId>> {
    let target = rustix::fs::readlinkat(
        rustix_linux_procfs::proc_self_fd()?,
        DecInt::from_fd(handle.as_fd()),
        Vec::new(),
    )?;
    let target = PathBuf::from(std::ffi::OsString::from_vec(target.into_bytes()));
    let parent = target
        .parent()
        .ok_or_else(|| invalid("runtime file has no parent; use a stable filesystem path"))?;
    let name = target
        .file_name()
        .ok_or_else(|| invalid("runtime file has no name; use a stable filesystem path"))?;
    let dir = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    if crate::dir_id(&rustix::fs::statat(
        &dir,
        name,
        rustix::fs::AtFlags::empty(),
    )?) != crate::dir_id(&rustix::fs::fstat(handle)?)
    {
        return Err(invalid(
            "runtime file changed during setup; keep grants stable",
        ));
    }
    Ok(crate::ancestry(&dir)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    #[test]
    fn file_grants_pin_identity_and_reopen_with_independent_offsets() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("library");
        fs::write(&path, b"original").unwrap();
        let mut runtime = Runtime::prepare(std::slice::from_ref(&path)).unwrap();
        fs::rename(&path, root.path().join("moved")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        for _ in 0..2 {
            let mut value = String::new();
            runtime
                .open_loader(&path)
                .unwrap()
                .read_to_string(&mut value)
                .unwrap();
            assert_eq!(value, "original");
        }
        runtime.revoke(&path, &Gate::new()).unwrap();
        assert!(runtime.open_loader(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
    }

    #[test]
    fn runtime_symlinks_stay_beneath_the_held_directory() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("runtime");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("library"), b"library").unwrap();
        fs::write(root.path().join("secret"), b"secret").unwrap();
        symlink("library", path.join("link")).unwrap();
        symlink("../secret", path.join("escape")).unwrap();
        let mut runtime = Runtime::prepare(std::slice::from_ref(&path)).unwrap();
        assert!(runtime.open_loader(&path.join("link")).is_ok());
        assert!(runtime.open_loader(&path.join("escape")).is_err());
        for (nofollow, no_symlinks) in [(true, false), (false, true)] {
            assert_eq!(
                runtime
                    .open_path(&path.join("link"), nofollow, no_symlinks)
                    .unwrap()
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ELOOP)
            );
        }
        runtime.revoke(&path, &Gate::new()).unwrap();
        assert!(runtime.open_loader(&path.join("library")).is_err());
        assert_eq!(fs::read(root.path().join("secret")).unwrap(), b"secret");
    }

    #[test]
    fn aliases_cannot_hide_runtime_data_overlap() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("file"), b"data").unwrap();
        let alias = root.path().join("alias");
        symlink(&data, &alias).unwrap();
        let mut gate = Gate::new();
        gate.grant(&data, Rights::READ).unwrap();
        for path in [&alias, &alias.join("file"), &root.path().to_path_buf()] {
            let runtime = Runtime::prepare(std::slice::from_ref(path)).unwrap();
            assert_eq!(
                runtime.check_overlap(&gate).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
