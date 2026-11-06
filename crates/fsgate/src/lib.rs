//! Filesystem authority as directory handles granted up front, enforced by
//! the kernel.
//!
//! A [`Gate`] holds a set of granted directories. Every operation takes an
//! absolute path, routes it to the grant that covers it, and performs the
//! operation relative to that grant's held descriptor via `cap-std` — on
//! Linux that means `openat2(2)` with `RESOLVE_BENEATH`, so a symlink or
//! `..` that leaves the grant fails at the kernel, not in a string check.
//! A path no grant covers fails with [`GateError::NoGrant`]; there is no
//! fallback to ambient access.
//!
//! ```no_run
//! use fsgate::{Gate, Rights};
//!
//! # fn main() -> Result<(), fsgate::GateError> {
//! let mut gate = Gate::new();
//! gate.grant("/srv/data", Rights::READ | Rights::WRITE | Rights::CREATE)?;
//!
//! let file = gate.open("/srv/data/users/1.json")?; // beneath the grant
//! assert!(gate.open("/etc/passwd").is_err());      // no grant: always an error
//! # Ok(())
//! # }
//! ```
//!
//! [`Gate::lock`] ends the granting phase and applies kernel containment:
//! on Linux, a Landlock ruleset built from the grants, so even code that
//! bypasses the `Gate` entirely cannot reach ungated paths. On platforms
//! without Landlock a strict lock fails closed; the broker process (M3)
//! will carry the same guarantee to macOS.

mod containment;

use std::fmt;
use std::fs::File;
use std::io;
use std::ops::BitOr;
use std::path::{Component, Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::Dir;

pub use cap_std::fs::{Metadata, ReadDir};

/// A set of rights attached to a grant.
///
/// Rights only narrow: a grant is created with a fixed set and nothing can
/// widen it afterwards.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    /// Open existing files for reading and stat them.
    pub const READ: Rights = Rights(1);
    /// Write to files (required by [`Gate::create`] together with `CREATE`).
    pub const WRITE: Rights = Rights(1 << 1);
    /// Create new files.
    pub const CREATE: Rights = Rights(1 << 2);
    /// List directory contents.
    pub const LIST: Rights = Rights(1 << 3);

    /// Returns true when every right in `needed` is present in `self`.
    pub const fn contains(self, needed: Rights) -> bool {
        self.0 & needed.0 == needed.0
    }

    /// Returns the rights in `self` that `held` is missing.
    pub const fn missing_from(self, held: Rights) -> Rights {
        Rights(self.0 & !held.0)
    }
}

impl BitOr for Rights {
    type Output = Rights;

    fn bitor(self, rhs: Rights) -> Rights {
        Rights(self.0 | rhs.0)
    }
}

impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (Rights::READ, "READ"),
            (Rights::WRITE, "WRITE"),
            (Rights::CREATE, "CREATE"),
            (Rights::LIST, "LIST"),
        ];
        let mut first = true;
        for (right, name) in names {
            if self.contains(right) {
                if !first {
                    f.write_str(" | ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("(none)")?;
        }
        Ok(())
    }
}

/// Why a gated operation failed.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// The requested path was not absolute.
    #[error("path `{path}` is not absolute; pass an absolute path")]
    NotAbsolute {
        /// The path as requested.
        path: PathBuf,
    },
    /// No grant covers the requested path.
    #[error("no grant covers `{path}`; grant a parent directory first")]
    NoGrant {
        /// The normalized requested path.
        path: PathBuf,
    },
    /// The covering grant lacks a right the operation needs.
    #[error(
        "grant for `{grant_path}` lacks {missing:?} needed to {op} `{path}`; \
         create the grant with those rights"
    )]
    RightsExceeded {
        /// The normalized requested path.
        path: PathBuf,
        /// The path of the grant that covered the request.
        grant_path: PathBuf,
        /// The rights the operation needs but the grant does not hold.
        missing: Rights,
        /// The attempted operation.
        op: &'static str,
    },
    /// The [`Grant`] was already revoked or belongs to another gate.
    #[error("grant was already revoked or does not belong to this gate")]
    UnknownGrant,
    /// The gate is locked; the granting phase is over.
    #[error("gate is locked; create every grant before calling `lock()`")]
    Locked,
    /// A strict lock cannot be fully enforced on this platform or kernel.
    #[error("kernel containment unavailable: {reason}")]
    LockUnsupported {
        /// Why enforcement is unavailable, and what to do instead.
        reason: String,
    },
    /// Building or applying the kernel ruleset failed.
    #[error("applying kernel containment failed: {source}")]
    LockFailed {
        /// The underlying error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Policy allowed the operation but the filesystem refused it. Escape
    /// attempts the kernel blocks (`RESOLVE_BENEATH`) surface here.
    #[error("filesystem operation on `{path}` failed: {source}")]
    Io {
        /// The normalized requested path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

/// How strictly [`Gate::lock`] treats missing kernel support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockPolicy {
    /// Fail unless the kernel fully enforces the containment rules.
    Strict,
    /// Apply whatever the platform supports and report what was achieved.
    /// Choosing this is an explicit decision to accept weaker containment.
    BestEffort,
}

/// What a successful lock actually achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockStatus {
    /// The kernel enforces the grants against all code in the thread family.
    FullyEnforced,
    /// The kernel enforces part of the rules (older Landlock ABI).
    PartiallyEnforced,
    /// Only the library's own checks apply; the kernel enforces nothing.
    LibraryOnly,
}

/// Handle to one grant inside a [`Gate`], used to revoke it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    index: usize,
}

struct GrantEntry {
    path: PathBuf,
    dir: Dir,
    rights: Rights,
}

/// A set of granted directories and the only way through them.
pub struct Gate {
    grants: Vec<Option<GrantEntry>>,
    locked: bool,
}

impl Gate {
    /// Creates a gate with no grants. Every operation fails until
    /// [`grant`](Gate::grant) is called.
    pub fn new() -> Gate {
        Gate {
            grants: Vec::new(),
            locked: false,
        }
    }

    /// Grants access to `path` with `rights`.
    ///
    /// The directory is opened now and held; later renames of `path` do not
    /// change what the grant reaches (protection is by the descriptor's
    /// identity, not the name).
    pub fn grant(&mut self, path: impl AsRef<Path>, rights: Rights) -> Result<Grant, GateError> {
        if self.locked {
            return Err(GateError::Locked);
        }
        let path = normalize(path.as_ref())?;
        let dir =
            Dir::open_ambient_dir(&path, ambient_authority()).map_err(|source| GateError::Io {
                path: path.clone(),
                source,
            })?;
        self.grants.push(Some(GrantEntry { path, dir, rights }));
        Ok(Grant {
            index: self.grants.len() - 1,
        })
    }

    /// Ends the granting phase and applies kernel containment, strictly:
    /// equivalent to [`lock_with(LockPolicy::Strict)`](Gate::lock_with).
    ///
    /// Irreversible. After a successful lock, [`grant`](Gate::grant) and a
    /// second `lock` fail with [`GateError::Locked`].
    ///
    /// On Linux this loads a Landlock ruleset covering every live grant
    /// (bound to the held descriptors, not path names), so filesystem
    /// access outside the grants fails at the kernel even for code that
    /// never touches this `Gate`. Landlock applies to the calling thread
    /// and everything it spawns afterwards — call `lock` on the main
    /// thread before spawning threads. On platforms without Landlock a
    /// strict lock fails with [`GateError::LockUnsupported`].
    pub fn lock(&mut self) -> Result<LockStatus, GateError> {
        self.lock_with(LockPolicy::Strict)
    }

    /// Ends the granting phase with an explicit [`LockPolicy`].
    ///
    /// `BestEffort` applies whatever the platform supports and reports the
    /// achieved level as a [`LockStatus`]; it never fails just because the
    /// kernel cannot enforce. The library-level lock (no new grants) is
    /// applied in every case.
    pub fn lock_with(&mut self, policy: LockPolicy) -> Result<LockStatus, GateError> {
        if self.locked {
            return Err(GateError::Locked);
        }
        let status = containment::apply(self.grants.iter().flatten(), policy)?;
        self.locked = true;
        Ok(status)
    }

    /// Revokes a grant. Subsequent operations under it fail with
    /// [`GateError::NoGrant`] unless another grant also covers them.
    ///
    /// Allowed after [`lock`](Gate::lock) — revocation only narrows. Note
    /// that after a lock the kernel rules are fixed: revoking then stops
    /// this `Gate` from using the grant, but code bypassing the gate keeps
    /// whatever the kernel ruleset allowed until the process exits.
    pub fn revoke(&mut self, grant: Grant) -> Result<(), GateError> {
        match self.grants.get_mut(grant.index) {
            Some(slot @ Some(_)) => {
                *slot = None;
                Ok(())
            }
            _ => Err(GateError::UnknownGrant),
        }
    }

    /// Opens an existing file for reading. Needs [`Rights::READ`].
    pub fn open(&self, path: impl AsRef<Path>) -> Result<File, GateError> {
        let (entry, rel, full) = self.resolve(path.as_ref(), Rights::READ, "open")?;
        entry
            .dir
            .open(&rel)
            .map(cap_std::fs::File::into_std)
            .map_err(|source| GateError::Io { path: full, source })
    }

    /// Creates (or truncates) a file for writing. Needs [`Rights::CREATE`]
    /// and [`Rights::WRITE`], because the returned handle writes data.
    pub fn create(&self, path: impl AsRef<Path>) -> Result<File, GateError> {
        let (entry, rel, full) =
            self.resolve(path.as_ref(), Rights::CREATE | Rights::WRITE, "create")?;
        entry
            .dir
            .create(&rel)
            .map(cap_std::fs::File::into_std)
            .map_err(|source| GateError::Io { path: full, source })
    }

    /// Reads metadata. Needs [`Rights::READ`].
    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, GateError> {
        let (entry, rel, full) = self.resolve(path.as_ref(), Rights::READ, "stat")?;
        entry
            .dir
            .metadata(&rel)
            .map_err(|source| GateError::Io { path: full, source })
    }

    /// Lists a directory. Needs [`Rights::LIST`].
    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<ReadDir, GateError> {
        let (entry, rel, full) = self.resolve(path.as_ref(), Rights::LIST, "list")?;
        entry
            .dir
            .read_dir(&rel)
            .map_err(|source| GateError::Io { path: full, source })
    }

    /// Routes a path to the longest covering grant and checks rights.
    ///
    /// This match is routing, not the security boundary: the subsequent
    /// cap-std call opens beneath the grant's held descriptor, and the
    /// kernel rejects anything (symlinks, races) that would leave it.
    fn resolve(
        &self,
        path: &Path,
        needed: Rights,
        op: &'static str,
    ) -> Result<(&GrantEntry, PathBuf, PathBuf), GateError> {
        let full = normalize(path)?;
        let entry = self
            .grants
            .iter()
            .flatten()
            .filter(|entry| full.starts_with(&entry.path))
            .max_by_key(|entry| entry.path.components().count())
            .ok_or_else(|| GateError::NoGrant { path: full.clone() })?;
        if !entry.rights.contains(needed) {
            return Err(GateError::RightsExceeded {
                path: full,
                grant_path: entry.path.clone(),
                missing: needed.missing_from(entry.rights),
                op,
            });
        }
        let rel = full
            .strip_prefix(&entry.path)
            .expect("grant path was verified as a prefix above");
        let rel = if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel.to_path_buf()
        };
        Ok((entry, rel, full))
    }
}

impl Default for Gate {
    fn default() -> Gate {
        Gate::new()
    }
}

/// Normalizes an absolute path lexically: resolves `.` and `..` without
/// touching the filesystem. Symlink behavior is deliberately not modeled
/// here; the kernel's beneath-handle resolution is what prevents escapes.
fn normalize(path: &Path) -> Result<PathBuf, GateError> {
    if !path.is_absolute() {
        return Err(GateError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
        }
    }
    Ok(out)
}
