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
//! bypasses the `Gate` entirely cannot reach ungated paths. Where Landlock
//! does not exist a strict lock fails closed, and containment is
//! structural instead: a [`Broker`] process holds the gate and serves a
//! worker that holds no filesystem authority of its own, passing
//! descriptors over a Unix socket to a [`BrokerGate`].

// The experimental launcher (RFC 0004) is unreviewed and not part of a
// release. The repository's `.cargo/config.toml` sets this cfg, and is not
// in the published crate.
#[cfg(all(feature = "experimental-intercept", not(fsgate_repository_build)))]
compile_error!(
    "`experimental-intercept` is not part of this release; build fsgate from its repository to \
     use the experimental launcher"
);

mod audit;
#[cfg(unix)]
mod broker;
#[cfg(unix)]
mod broker_sys;
mod containment;
#[cfg(all(feature = "experimental-intercept", target_os = "linux"))]
pub mod intercept;

pub use audit::{AuditDecision, AuditEvent, AuditOp, AuditReason, AuditSink};
#[cfg(unix)]
pub use broker::{Broker, BrokerGate, FileStat, ServeOptions};

use std::fmt;
use std::fs::File;
use std::io;
use std::ops::{BitAnd, BitOr, Sub};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use cap_std::ambient_authority;
use cap_std::fs::Dir;

pub use cap_std::fs::{Metadata, ReadDir};

/// A set of rights attached to a grant.
///
/// Rights only narrow: nothing widens a grant after it is created, and
/// [`Gate::narrow`] removes rights from a live grant.
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

    /// Returns the raw bit representation, for serialization.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Rebuilds a set from raw bits, dropping unknown bits.
    pub const fn from_bits_truncate(bits: u8) -> Rights {
        Rights(bits & 0b1111)
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
///
/// Failure kinds grow with the API, so a `match` outside fsgate needs a
/// wildcard arm. Existing variants keep their fields.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
        op: String,
    },
    /// [`Gate::narrow`] named a right the grant does not hold. Narrowing
    /// never adds rights; the grant is unchanged.
    #[error(
        "grant for `{grant_path}` holds {held:?}, not {extra:?}; \
         narrow it to a subset of its current rights"
    )]
    WouldWiden {
        /// The path of the grant.
        grant_path: PathBuf,
        /// The rights the grant holds.
        held: Rights,
        /// The requested rights the grant does not hold.
        extra: Rights,
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
    /// The broker transport failed or refused. The connection being gone
    /// means every operation fails: closed, with no fallback.
    #[error("broker error: {message}")]
    Broker {
        /// What went wrong, and the consequence.
        message: String,
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

/// How strictly [`Gate::lock`] treats missing kernel support for the
/// filesystem rules built from the grants (Landlock ABI v3).
///
/// The policy covers only those rules. A [`Restrictions`] member named in
/// [`LockOptions::require`] is required under either policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockPolicy {
    /// Fail unless the kernel fully enforces the filesystem rules.
    Strict,
    /// Apply whatever the platform supports and report what was achieved.
    /// Choosing this is an explicit decision to accept weaker containment.
    BestEffort,
}

/// What a successful lock achieved for the filesystem rules.
///
/// [`Gate::restrictions`] reports the [`Restrictions`] separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockStatus {
    /// The kernel enforces the grants against all code in the thread family.
    FullyEnforced,
    /// The kernel enforces part of the rules (older Landlock ABI).
    PartiallyEnforced,
    /// Only the library's own checks apply; the kernel enforces nothing.
    LibraryOnly,
}

/// Kernel restrictions [`Gate::lock`] applies beyond the filesystem rules
/// built from the grants ([RFC 0006]).
///
/// Each needs a Landlock ABI newer than the v3 the filesystem rules need.
/// A bare [`lock`](Gate::lock) requests all of them and applies those the
/// running kernel supports; [`Gate::restrictions`] reports which took
/// effect, and [`LockOptions`] drops or requires individual members.
///
/// [RFC 0006]: https://github.com/farming-labs/fsgate/blob/main/docs/rfcs/0006-lock-restrictions.md
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Restrictions(u8);

impl Restrictions {
    /// Character and block devices opened after the lock accept ioctls
    /// only beneath a grant holding [`Rights::WRITE`], apart from the
    /// generic commands Landlock always allows. Devices opened before the
    /// lock, such as an inherited terminal, are unaffected. Landlock ABI
    /// v5, Linux 6.10.
    pub const IOCTL_DEV: Restrictions = Restrictions(1);
    /// Connecting or sending to an abstract Unix socket created outside
    /// the locked process and its later descendants fails. Landlock ABI v6,
    /// Linux 6.12.
    pub const ABSTRACT_UNIX_SOCKET: Restrictions = Restrictions(1 << 1);
    /// Signalling a process outside the locked process and its later
    /// descendants fails. That includes the parent and anything spawned
    /// before the lock. Landlock ABI v6, Linux 6.12.
    pub const SIGNAL: Restrictions = Restrictions(1 << 2);
    /// The ruleset applies to every thread of the process in one step,
    /// not only to the thread that calls `lock` and what it spawns later.
    /// Landlock ABI v8, Linux 7.0.
    pub const ALL_THREADS: Restrictions = Restrictions(1 << 3);
    /// Connecting or sending to a pathname Unix socket created outside the
    /// locked process and its later descendants fails with `EACCES`, even
    /// beneath a grant: no [`Rights`] value permits it. Connections made
    /// before the lock keep working, so a [`BrokerGate`] worker connects
    /// before it locks. Landlock ABI v9, Linux 7.1.
    pub const RESOLVE_UNIX: Restrictions = Restrictions(1 << 4);

    /// Every restriction this fsgate version knows. A release that adds
    /// one is a minor release.
    pub const fn all() -> Restrictions {
        Restrictions(0b1_1111)
    }

    /// No restrictions.
    pub const fn empty() -> Restrictions {
        Restrictions(0)
    }

    /// Returns true when every restriction in `other` is in `self`.
    pub const fn contains(self, other: Restrictions) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns true when the set holds no restriction.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for Restrictions {
    type Output = Restrictions;

    fn bitor(self, rhs: Restrictions) -> Restrictions {
        Restrictions(self.0 | rhs.0)
    }
}

impl BitAnd for Restrictions {
    type Output = Restrictions;

    fn bitand(self, rhs: Restrictions) -> Restrictions {
        Restrictions(self.0 & rhs.0)
    }
}

/// Set difference: the restrictions in `self` that are not in `rhs`.
impl Sub for Restrictions {
    type Output = Restrictions;

    fn sub(self, rhs: Restrictions) -> Restrictions {
        Restrictions(self.0 & !rhs.0)
    }
}

impl fmt::Debug for Restrictions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for info in RESTRICTIONS {
            if self.contains(info.set) {
                if !first {
                    f.write_str(" | ")?;
                }
                f.write_str(info.name)?;
                first = false;
            }
        }
        if first {
            f.write_str("(none)")?;
        }
        Ok(())
    }
}

/// One [`Restrictions`] member: its name, the Landlock ABI it needs, and
/// the first Linux release with that ABI.
pub(crate) struct RestrictionInfo {
    pub(crate) set: Restrictions,
    pub(crate) name: &'static str,
    pub(crate) abi: u8,
    pub(crate) linux: &'static str,
}

/// Every member, in the order audit events and `Debug` list them.
pub(crate) const RESTRICTIONS: [RestrictionInfo; 5] = [
    RestrictionInfo {
        set: Restrictions::IOCTL_DEV,
        name: "IOCTL_DEV",
        abi: 5,
        linux: "6.10",
    },
    RestrictionInfo {
        set: Restrictions::ABSTRACT_UNIX_SOCKET,
        name: "ABSTRACT_UNIX_SOCKET",
        abi: 6,
        linux: "6.12",
    },
    RestrictionInfo {
        set: Restrictions::SIGNAL,
        name: "SIGNAL",
        abi: 6,
        linux: "6.12",
    },
    RestrictionInfo {
        set: Restrictions::ALL_THREADS,
        name: "ALL_THREADS",
        abi: 8,
        linux: "7.0",
    },
    RestrictionInfo {
        set: Restrictions::RESOLVE_UNIX,
        name: "RESOLVE_UNIX",
        abi: 9,
        linux: "7.1",
    },
];

/// How [`Gate::lock_with`] applies containment ([RFC 0006]).
///
/// A [`LockPolicy`] converts into options that request every
/// [`Restrictions`] member and require none, so
/// `lock_with(LockPolicy::BestEffort)` keeps working.
///
/// ```
/// use fsgate::{LockOptions, LockPolicy, Restrictions};
///
/// // Keep abstract sockets reachable (an X11 client, say), and fail
/// // unless the kernel can stop signals to outside processes.
/// let options = LockOptions::new(LockPolicy::Strict)
///     .restrict(Restrictions::all() - Restrictions::ABSTRACT_UNIX_SOCKET)
///     .require(Restrictions::SIGNAL);
/// # let _ = options;
/// ```
///
/// [RFC 0006]: https://github.com/farming-labs/fsgate/blob/main/docs/rfcs/0006-lock-restrictions.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockOptions {
    policy: LockPolicy,
    restrict: Restrictions,
    require: Restrictions,
}

impl LockOptions {
    /// Options with `policy` for the filesystem rules, requesting every
    /// restriction and requiring none.
    pub const fn new(policy: LockPolicy) -> LockOptions {
        LockOptions {
            policy,
            restrict: Restrictions::all(),
            require: Restrictions::empty(),
        }
    }

    /// Sets the restrictions to request. Members the kernel does not
    /// support are skipped, and [`Gate::restrictions`] leaves them out.
    #[must_use]
    pub const fn restrict(mut self, set: Restrictions) -> LockOptions {
        self.restrict = set;
        self
    }

    /// Sets restrictions that must take effect. Without kernel support for
    /// one, the lock fails with [`GateError::LockUnsupported`] before
    /// applying anything. Required members are requested even when
    /// [`restrict`](LockOptions::restrict) leaves them out, and they bind
    /// under [`LockPolicy::BestEffort`] too.
    #[must_use]
    pub const fn require(mut self, set: Restrictions) -> LockOptions {
        self.require = set;
        self
    }

    pub(crate) const fn policy(self) -> LockPolicy {
        self.policy
    }

    pub(crate) const fn requested(self) -> Restrictions {
        Restrictions(self.restrict.0 | self.require.0)
    }

    pub(crate) const fn required(self) -> Restrictions {
        self.require
    }
}

/// Strict about the filesystem rules, requesting every restriction.
impl Default for LockOptions {
    fn default() -> LockOptions {
        LockOptions::new(LockPolicy::Strict)
    }
}

impl From<LockPolicy> for LockOptions {
    fn from(policy: LockPolicy) -> LockOptions {
        LockOptions::new(policy)
    }
}

/// Handle to one grant inside a [`Gate`], used to narrow or revoke it.
///
/// A grant belongs to the gate that created it. Passing it to another
/// gate's [`revoke`](Gate::revoke) or [`narrow`](Gate::narrow) fails with
/// [`GateError::UnknownGrant`] and changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    gate: u64,
    index: usize,
}

struct GrantEntry {
    path: PathBuf,
    dir: Dir,
    rights: Rights,
}

/// Source of gate ids. Wrapping needs 2^64 gates, so ids never repeat in
/// practice.
static NEXT_GATE_ID: AtomicU64 = AtomicU64::new(0);

/// A set of granted directories and the only way through them.
pub struct Gate {
    id: u64,
    grants: Vec<Option<GrantEntry>>,
    locked: bool,
    restrictions: Option<Restrictions>,
    audit: Option<Arc<dyn AuditSink>>,
}

impl Gate {
    /// Creates a gate with no grants. Every operation fails until
    /// [`grant`](Gate::grant) is called.
    pub fn new() -> Gate {
        Gate {
            id: NEXT_GATE_ID.fetch_add(1, Ordering::Relaxed),
            grants: Vec::new(),
            locked: false,
            restrictions: None,
            audit: None,
        }
    }

    /// Installs an [`AuditSink`] that receives every allow/deny decision
    /// (RFC 0002). The default is no sink, which costs one branch.
    /// Observation only — a sink cannot veto or alter decisions.
    pub fn set_audit_sink(&mut self, sink: Arc<dyn AuditSink>) {
        self.audit = Some(sink);
    }

    /// Grants access to `path` with `rights`.
    ///
    /// The directory is opened now and held; later renames of `path` do not
    /// change what the grant reaches (protection is by the descriptor's
    /// identity, not the name).
    pub fn grant(&mut self, path: impl AsRef<Path>, rights: Rights) -> Result<Grant, GateError> {
        let requested = path.as_ref();
        if self.locked {
            self.emit(
                AuditOp::Grant,
                Some(requested),
                None,
                AuditDecision::Deny,
                AuditReason::Locked,
                None,
            );
            return Err(GateError::Locked);
        }
        let path = match normalize(requested) {
            Ok(path) => path,
            Err(err) => {
                self.emit(
                    AuditOp::Grant,
                    Some(requested),
                    None,
                    AuditDecision::Deny,
                    AuditReason::NotAbsolute,
                    None,
                );
                return Err(err);
            }
        };
        let dir = match Dir::open_ambient_dir(&path, ambient_authority()) {
            Ok(dir) => dir,
            Err(source) => {
                self.emit(
                    AuditOp::Grant,
                    Some(&path),
                    None,
                    AuditDecision::Allow,
                    AuditReason::Ok,
                    source.raw_os_error(),
                );
                return Err(GateError::Io { path, source });
            }
        };
        self.grants.push(Some(GrantEntry { path, dir, rights }));
        let index = self.grants.len() - 1;
        self.emit_rights(
            AuditOp::Grant,
            self.grants[index]
                .as_ref()
                .map(|entry| entry.path.clone())
                .as_deref(),
            Some(index),
            rights,
            AuditDecision::Allow,
            AuditReason::Ok,
        );
        Ok(Grant {
            gate: self.id,
            index,
        })
    }

    /// Ends the granting phase and applies kernel containment with
    /// [`LockOptions::default`]: strict about the filesystem rules, and
    /// requesting every [`Restrictions`] member.
    ///
    /// Irreversible. After a successful lock, [`grant`](Gate::grant) and a
    /// second `lock` fail with [`GateError::Locked`].
    ///
    /// On Linux this loads a Landlock ruleset covering every live grant
    /// (bound to the held descriptors, not path names), so filesystem
    /// access outside the grants fails at the kernel even for code that
    /// never touches this `Gate`. The ruleset also applies each
    /// [`Restrictions`] member the kernel supports, and
    /// [`restrictions`](Gate::restrictions) reports which took effect. On
    /// Linux 7.0 and later it covers every thread of the process
    /// ([`Restrictions::ALL_THREADS`]); on older kernels it covers the
    /// calling thread and what it spawns afterwards, so call `lock` before
    /// spawning threads. On platforms without Landlock a strict lock fails
    /// with [`GateError::LockUnsupported`].
    pub fn lock(&mut self) -> Result<LockStatus, GateError> {
        self.lock_with(LockOptions::default())
    }

    /// Ends the granting phase with explicit [`LockOptions`]. A
    /// [`LockPolicy`] converts into options that request every restriction.
    ///
    /// `BestEffort` applies whatever filesystem rules the platform supports
    /// and reports the achieved level as a [`LockStatus`]; it never fails
    /// just because the kernel cannot enforce them. A restriction named in
    /// [`LockOptions::require`] is never best effort: without kernel
    /// support for it, the lock fails before anything is applied, leaving
    /// the process unrestricted and the gate unlocked. Every successful
    /// lock also applies the library-level lock (no new grants).
    pub fn lock_with(&mut self, options: impl Into<LockOptions>) -> Result<LockStatus, GateError> {
        let options = options.into();
        if self.locked {
            self.emit(
                AuditOp::Lock,
                None,
                None,
                AuditDecision::Deny,
                AuditReason::Locked,
                None,
            );
            return Err(GateError::Locked);
        }
        let applied = match containment::apply(self.grants.iter().flatten(), options) {
            Ok(applied) => applied,
            Err(err) => {
                self.emit(
                    AuditOp::Lock,
                    None,
                    None,
                    AuditDecision::Deny,
                    AuditReason::Unsupported,
                    None,
                );
                return Err(err);
            }
        };
        self.locked = true;
        self.restrictions = Some(applied.restrictions);
        self.emit_lock(applied.restrictions);
        Ok(applied.status)
    }

    /// The [`Restrictions`] the kernel applied at [`lock`](Gate::lock), or
    /// `None` until a lock succeeds. Empty where Landlock is missing or too
    /// old for any of them.
    pub fn restrictions(&self) -> Option<Restrictions> {
        self.restrictions
    }

    /// Revokes a grant. Subsequent operations under it fail with
    /// [`GateError::NoGrant`] unless another grant also covers them.
    ///
    /// Allowed after [`lock`](Gate::lock) — revocation only narrows. Note
    /// that after a lock the kernel rules are fixed: revoking then stops
    /// this `Gate` from using the grant, but code bypassing the gate keeps
    /// whatever the kernel ruleset allowed until the process exits.
    ///
    /// Fails with [`GateError::UnknownGrant`] if the grant was already
    /// revoked or belongs to another gate; no grant changes.
    pub fn revoke(&mut self, grant: Grant) -> Result<(), GateError> {
        let index = self.index_of(grant);
        match index.and_then(|index| self.grants.get_mut(index)) {
            Some(slot @ Some(_)) => {
                let path = slot.take().map(|entry| entry.path);
                self.emit(
                    AuditOp::Revoke,
                    path.as_deref(),
                    index,
                    AuditDecision::Allow,
                    AuditReason::Ok,
                    None,
                );
                Ok(())
            }
            _ => {
                self.emit(
                    AuditOp::Revoke,
                    None,
                    index,
                    AuditDecision::Deny,
                    AuditReason::UnknownGrant,
                    None,
                );
                Err(GateError::UnknownGrant)
            }
        }
    }

    /// Narrows a grant to `rights`, which must be a subset of the rights it
    /// holds (RFC 0005). The grant keeps its id and its held descriptor;
    /// nothing re-resolves its path.
    ///
    /// Allowed after [`lock`](Gate::lock), because narrowing only removes
    /// authority. A grant narrowed before the lock is enforced by the kernel
    /// at its narrowed rights. After the lock the kernel rules are fixed:
    /// narrowing then binds operations through this `Gate`, but code
    /// bypassing the gate keeps whatever the kernel ruleset allowed, as with
    /// [`revoke`](Gate::revoke).
    ///
    /// Fails with [`GateError::WouldWiden`] if `rights` names a right the
    /// grant does not hold, and with [`GateError::UnknownGrant`] if the grant
    /// was revoked or belongs to another gate. Either way no grant changes.
    pub fn narrow(&mut self, grant: Grant, rights: Rights) -> Result<(), GateError> {
        let index = self.index_of(grant);
        let Some(Some(entry)) = index.and_then(|index| self.grants.get_mut(index)) else {
            self.emit(
                AuditOp::Narrow,
                None,
                index,
                AuditDecision::Deny,
                AuditReason::UnknownGrant,
                None,
            );
            return Err(GateError::UnknownGrant);
        };
        let held = entry.rights;
        let path = entry.path.clone();
        if !held.contains(rights) {
            self.emit_rights(
                AuditOp::Narrow,
                Some(&path),
                index,
                held,
                AuditDecision::Deny,
                AuditReason::RightsExceeded,
            );
            return Err(GateError::WouldWiden {
                grant_path: path,
                held,
                extra: rights.missing_from(held),
            });
        }
        entry.rights = rights;
        self.emit_rights(
            AuditOp::Narrow,
            Some(&path),
            index,
            rights,
            AuditDecision::Allow,
            AuditReason::Ok,
        );
        Ok(())
    }

    /// The grant's slot in this gate's table, or `None` for a grant created
    /// by another gate, whose index means nothing here.
    fn index_of(&self, grant: Grant) -> Option<usize> {
        (grant.gate == self.id).then_some(grant.index)
    }

    /// Opens an existing file for reading. Needs [`Rights::READ`].
    ///
    /// A directory fails with `EISDIR`, because a descriptor for one could
    /// list it without [`Rights::LIST`] and open paths relative to it. The
    /// check is on the opened descriptor, so a path that changes during
    /// resolution cannot get past it. Use [`read_dir`](Gate::read_dir) to
    /// list a directory.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<File, GateError> {
        self.gated(AuditOp::Open, path.as_ref(), Rights::READ, |entry, rel| {
            let file = entry.dir.open(rel)?.into_std();
            if file.metadata()?.is_dir() {
                return Err(rustix::io::Errno::ISDIR.into());
            }
            Ok(file)
        })
    }

    /// Opens an existing regular file for reading under the stricter rules
    /// of the RFC 0004 interception profile. Needs [`Rights::READ`].
    ///
    /// Compared with [`open`](Gate::open), every symlink on the way fails
    /// with `ELOOP`, even one that stays inside the grant; a directory fails
    /// with `EISDIR`; and FIFOs, devices, sockets, and procfs or sysfs files
    /// fail with `EOPNOTSUPP` without being opened for I/O, so a FIFO cannot
    /// block the caller. The path is resolved to an `O_PATH` handle, checked,
    /// and that same handle is reopened, so a rename between the check and
    /// the open cannot substitute another file. These refusals come after
    /// policy allowed the request: they are [`GateError::Io`] with the errno,
    /// audited as `allow` with that errno.
    ///
    /// **Experimental.** Linux only, behind the `experimental-intercept`
    /// feature, and not covered by semver.
    #[cfg(all(feature = "experimental-intercept", target_os = "linux"))]
    pub fn open_regular_strict(&self, path: impl AsRef<Path>) -> Result<File, GateError> {
        self.gated(AuditOp::Open, path.as_ref(), Rights::READ, |entry, rel| {
            intercept::open_regular_beneath(&entry.dir, rel)
        })
    }

    /// Decides one intercepted open request (RFC 0004) and returns the file
    /// to deliver to the worker.
    ///
    /// The request's copied arguments are checked against the interception
    /// profile's file-open contract, then authorized with
    /// [`open_regular_strict`](Gate::open_regular_strict). Exactly one `open`
    /// audit event is emitted, carrying the request's syscall and
    /// notification ID: a deny with `unsupported_input` or `invalid_memory`
    /// for a request refused before any grant is matched (with the path when
    /// a valid one was copied), and otherwise the same event
    /// `open_regular_strict` emits.
    ///
    /// Every error carries the errno to answer the worker with
    /// ([`io::Error::raw_os_error`]): `EACCES` when no grant covers the path
    /// or it lacks [`Rights::READ`], the contract's errno for a refused
    /// argument, and the filesystem's errno otherwise.
    ///
    /// **Experimental.** Linux only, behind the `experimental-intercept`
    /// feature, and not covered by semver.
    #[cfg(all(feature = "experimental-intercept", target_os = "linux"))]
    pub fn open_intercepted(&self, request: &intercept::OpenRequest) -> io::Result<File> {
        let origin = Origin {
            op: AuditOp::Open,
            notified: Some(Notified {
                syscall: request.call.name(),
                notification: request.notification,
            }),
        };
        let path = match intercept::validate(request) {
            Ok(path) => path,
            Err(refusal) => {
                self.emit(
                    origin,
                    refusal.path.as_deref().map(Path::new),
                    None,
                    AuditDecision::Deny,
                    refusal.reason,
                    None,
                );
                return Err(refusal.errno.into());
            }
        };
        let opened = self.gated(origin, Path::new(&path), Rights::READ, |entry, rel| {
            intercept::open_regular_beneath(&entry.dir, rel)
        });
        match opened {
            Ok(file) => Ok(file),
            Err(GateError::Io { source, .. }) => Err(source),
            // No grant or a missing right; the gate has audited the deny.
            Err(_) => Err(rustix::io::Errno::ACCESS.into()),
        }
    }

    /// Creates (or truncates) a file for writing. Needs [`Rights::CREATE`]
    /// and [`Rights::WRITE`], because the returned handle writes data.
    pub fn create(&self, path: impl AsRef<Path>) -> Result<File, GateError> {
        self.gated(
            AuditOp::Create,
            path.as_ref(),
            Rights::CREATE | Rights::WRITE,
            |entry, rel| entry.dir.create(rel).map(cap_std::fs::File::into_std),
        )
    }

    /// Reads metadata. Needs [`Rights::READ`].
    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<Metadata, GateError> {
        self.gated(
            AuditOp::Metadata,
            path.as_ref(),
            Rights::READ,
            |entry, rel| entry.dir.metadata(rel),
        )
    }

    /// Lists a directory. Needs [`Rights::LIST`].
    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<ReadDir, GateError> {
        self.gated(
            AuditOp::ReadDir,
            path.as_ref(),
            Rights::LIST,
            |entry, rel| entry.dir.read_dir(rel),
        )
    }

    /// Resolves, runs the operation, and emits exactly one audit event:
    /// a deny for policy refusals, or an allow (with `errno` when the
    /// filesystem then refused) once policy is satisfied.
    fn gated<T>(
        &self,
        origin: impl Into<Origin>,
        path: &Path,
        needed: Rights,
        run: impl FnOnce(&GrantEntry, &Path) -> io::Result<T>,
    ) -> Result<T, GateError> {
        let origin = origin.into();
        let op = origin.op;
        let (index, entry, rel, full) = match self.resolve(path) {
            Ok(resolved) => resolved,
            Err(err) => {
                let reason = match &err {
                    GateError::NotAbsolute { .. } => AuditReason::NotAbsolute,
                    GateError::NoGrant { .. } => AuditReason::NoGrant,
                    // resolve() returns no other variants.
                    _ => AuditReason::Ok,
                };
                self.emit(origin, Some(path), None, AuditDecision::Deny, reason, None);
                return Err(err);
            }
        };
        if !entry.rights.contains(needed) {
            self.emit(
                origin,
                Some(&full),
                Some(index),
                AuditDecision::Deny,
                AuditReason::RightsExceeded,
                None,
            );
            return Err(GateError::RightsExceeded {
                path: full,
                grant_path: entry.path.clone(),
                missing: needed.missing_from(entry.rights),
                op: op.as_str().to_string(),
            });
        }
        match run(entry, &rel) {
            Ok(value) => {
                self.emit(
                    origin,
                    Some(&full),
                    Some(index),
                    AuditDecision::Allow,
                    AuditReason::Ok,
                    None,
                );
                Ok(value)
            }
            Err(source) => {
                self.emit(
                    origin,
                    Some(&full),
                    Some(index),
                    AuditDecision::Allow,
                    AuditReason::Ok,
                    source.raw_os_error(),
                );
                Err(GateError::Io { path: full, source })
            }
        }
    }

    /// Routes a path to the longest covering grant.
    ///
    /// This match is routing, not the security boundary: the subsequent
    /// cap-std call opens beneath the grant's held descriptor, and the
    /// kernel rejects anything (symlinks, races) that would leave it.
    fn resolve(&self, path: &Path) -> Result<(usize, &GrantEntry, PathBuf, PathBuf), GateError> {
        let full = normalize(path)?;
        let (index, entry) = self
            .grants
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|entry| (index, entry)))
            .filter(|(_, entry)| full.starts_with(&entry.path))
            .max_by_key(|(_, entry)| entry.path.components().count())
            .ok_or_else(|| GateError::NoGrant { path: full.clone() })?;
        let rel = full
            .strip_prefix(&entry.path)
            .expect("grant path was verified as a prefix above");
        let rel = if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel.to_path_buf()
        };
        Ok((index, entry, rel, full))
    }

    fn emit(
        &self,
        origin: impl Into<Origin>,
        path: Option<&Path>,
        grant: Option<usize>,
        decision: AuditDecision,
        reason: AuditReason,
        errno: Option<i32>,
    ) {
        if let Some(sink) = &self.audit {
            let origin = origin.into();
            sink.event(&AuditEvent {
                ts: SystemTime::now(),
                op: origin.op,
                path: path.map(Path::to_path_buf),
                grant,
                rights: None,
                restrictions: None,
                decision,
                reason,
                errno,
                syscall: origin.notified.map(|notified| notified.syscall),
                notification: origin.notified.map(|notified| notified.notification),
            });
        }
    }

    /// [`emit`](Gate::emit) for a `grant` or `narrow` decision that leaves
    /// the grant holding `rights`. These decisions never carry an errno.
    fn emit_rights(
        &self,
        op: AuditOp,
        path: Option<&Path>,
        grant: Option<usize>,
        rights: Rights,
        decision: AuditDecision,
        reason: AuditReason,
    ) {
        if let Some(sink) = &self.audit {
            sink.event(&AuditEvent {
                ts: SystemTime::now(),
                op,
                path: path.map(Path::to_path_buf),
                grant,
                rights: Some(rights),
                restrictions: None,
                decision,
                reason,
                errno: None,
                syscall: None,
                notification: None,
            });
        }
    }

    /// [`emit`](Gate::emit) for a successful `lock`, recording the
    /// restrictions that took effect.
    fn emit_lock(&self, restrictions: Restrictions) {
        if let Some(sink) = &self.audit {
            sink.event(&AuditEvent {
                ts: SystemTime::now(),
                op: AuditOp::Lock,
                path: None,
                grant: None,
                rights: None,
                restrictions: Some(restrictions),
                decision: AuditDecision::Allow,
                reason: AuditReason::Ok,
                errno: None,
                syscall: None,
                notification: None,
            });
        }
    }
}

impl Default for Gate {
    fn default() -> Gate {
        Gate::new()
    }
}

/// The operation an audit event records, and, for an intercepted request,
/// which syscall and notification it answers.
#[derive(Clone, Copy)]
struct Origin {
    op: AuditOp,
    notified: Option<Notified>,
}

impl From<AuditOp> for Origin {
    fn from(op: AuditOp) -> Origin {
        Origin { op, notified: None }
    }
}

/// Identifies an intercepted request (RFC 0004) in its audit event.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(all(feature = "experimental-intercept", target_os = "linux")),
    allow(dead_code)
)]
struct Notified {
    syscall: &'static str,
    notification: u64,
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

/// Compile checks from outside the crate. The `compile_fail` block differs
/// from its passing twin only by the wildcard arm, so an unrelated compile
/// error cannot satisfy it.
///
/// ```
/// fn kind(err: &fsgate::GateError) {
///     use fsgate::GateError::*;
///     match err {
///         NotAbsolute { .. } | NoGrant { .. } | RightsExceeded { .. } | WouldWiden { .. }
///         | UnknownGrant | Locked | LockUnsupported { .. } | LockFailed { .. }
///         | Broker { .. } | Io { .. } => {}
///         _ => {}
///     }
/// }
/// ```
///
/// ```compile_fail
/// fn kind(err: &fsgate::GateError) {
///     use fsgate::GateError::*;
///     match err {
///         NotAbsolute { .. } | NoGrant { .. } | RightsExceeded { .. } | WouldWiden { .. }
///         | UnknownGrant | Locked | LockUnsupported { .. } | LockFailed { .. }
///         | Broker { .. } | Io { .. } => {}
///     }
/// }
/// ```
#[cfg(doctest)]
struct ExtensibleErrorDoctest;

/// The README's example must keep compiling; this pulls it into the
/// doctest suite without shipping it in the crate docs.
#[cfg(doctest)]
mod readme_doctest {
    #![doc = include_str!("../README.md")]
}
