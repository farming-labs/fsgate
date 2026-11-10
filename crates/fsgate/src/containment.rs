//! Kernel containment applied at [`Gate::lock`](crate::Gate::lock).
//!
//! On Linux this is a Landlock ruleset built from the live grants: the
//! ruleset handles every filesystem access ABI v3 knows, so anything not
//! explicitly allowed beneath a grant is denied by the kernel for the
//! whole thread family, including code that never touches the `Gate`.
//! On top of that floor it requests the [`Restrictions`] the options ask
//! for (RFC 0006). Filesystem path syscalls are mediated by Landlock
//! rather than seccomp; the reasoning is recorded in ADR 0002.

use crate::{
    GateError, GrantEntry, LockOptions, LockPolicy, LockStatus, RESTRICTIONS, RestrictionInfo,
    Restrictions,
};

/// What a successful lock achieved.
pub(crate) struct Applied {
    pub(crate) status: LockStatus,
    pub(crate) restrictions: Restrictions,
}

#[cfg(target_os = "linux")]
pub(crate) fn apply<'a>(
    grants: impl Iterator<Item = &'a GrantEntry>,
    options: LockOptions,
) -> Result<Applied, GateError> {
    use landlock::{
        ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, LandlockStatus, PathBeneath,
        RestrictSelfAttr, Ruleset, RulesetAttr, RulesetCreatedAttr, Scope,
    };

    use crate::Rights;

    let requested = options.requested();
    let required = options.required();
    // Required parts are hard requirements, so the crate rejects an
    // unsupported one here, while the ruleset is built, and nothing has
    // been applied when the lock fails.
    let level = |set: Restrictions| {
        if required.contains(set) {
            CompatLevel::HardRequirement
        } else {
            CompatLevel::BestEffort
        }
    };
    let floor_level = match options.policy() {
        LockPolicy::Strict => CompatLevel::HardRequirement,
        LockPolicy::BestEffort => CompatLevel::BestEffort,
    };

    // V3 adds Truncate, which `Gate::create` needs for existing files.
    let mut ruleset = Ruleset::default()
        .set_compatibility(floor_level)
        .handle_access(AccessFs::from_all(ABI::V3))
        .map_err(|err| unsupported_or_failed(err, unsupported_floor))?;
    for (set, access) in [
        (Restrictions::IOCTL_DEV, AccessFs::IoctlDev),
        // RFC 0006: no right grants this one, so no rule below names it.
        (Restrictions::RESOLVE_UNIX, AccessFs::ResolveUnix),
    ] {
        if requested.contains(set) {
            ruleset = ruleset
                .set_compatibility(level(set))
                .handle_access(access)
                .map_err(|err| member_error(set, err))?;
        }
    }
    for (set, scope) in [
        (
            Restrictions::ABSTRACT_UNIX_SOCKET,
            Scope::AbstractUnixSocket,
        ),
        (Restrictions::SIGNAL, Scope::Signal),
    ] {
        if requested.contains(set) {
            ruleset = ruleset
                .set_compatibility(level(set))
                .scope(scope)
                .map_err(|err| member_error(set, err))?;
        }
    }

    // Every requirement has been checked. Rules only name access rights
    // the ruleset requested, and best effort drops the ones this kernel
    // lacks, such as `IoctlDev` before ABI v5.
    let mut ruleset = ruleset
        .set_compatibility(CompatLevel::BestEffort)
        .create()
        .map_err(lock_failed)?;
    for entry in grants {
        let mut access = BitFlags::<AccessFs>::EMPTY;
        if entry.rights.contains(Rights::READ) {
            access |= AccessFs::ReadFile;
        }
        if entry.rights.contains(Rights::LIST) {
            access |= AccessFs::ReadDir;
        }
        if entry.rights.contains(Rights::WRITE) {
            access |= AccessFs::WriteFile | AccessFs::Truncate;
            // RFC 0006: device ioctls follow `WRITE`.
            if requested.contains(Restrictions::IOCTL_DEV) {
                access |= AccessFs::IoctlDev;
            }
        }
        if entry.rights.contains(Rights::CREATE) {
            access |= AccessFs::MakeReg;
        }
        // A grant with no rights allows nothing, which is what having no rule
        // means. Landlock rejects a rule with no access, so adding one would
        // fail the whole lock.
        if access.is_empty() {
            continue;
        }
        // The rule is bound to the held descriptor, not the path name.
        ruleset = ruleset
            .add_rule(PathBeneath::new(&entry.dir, access))
            .map_err(lock_failed)?;
    }
    if requested.contains(Restrictions::ALL_THREADS) {
        // The crate checks this flag when it is set, so a required one
        // still fails before anything is applied.
        ruleset = ruleset
            .set_compatibility(level(Restrictions::ALL_THREADS))
            .all_threads(true)
            .map_err(|err| member_error(Restrictions::ALL_THREADS, err))?;
    }

    let status = ruleset.restrict_self().map_err(lock_failed)?;
    let abi = match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => {
            // `ABI` is non-exhaustive but ordered: count the versions it reaches.
            [
                ABI::V1,
                ABI::V2,
                ABI::V3,
                ABI::V4,
                ABI::V5,
                ABI::V6,
                ABI::V7,
                ABI::V8,
                ABI::V9,
            ]
            .into_iter()
            .filter(|known| effective_abi >= *known)
            .count() as u8
        }
        _ => 0,
    };
    let applied = achieved(abi, status.all_threads, requested);
    // The hard requirements above make these unreachable. They are checked
    // anyway, so an unexpected crate or kernel answer cannot pass as success.
    if options.policy() == LockPolicy::Strict && applied.status != LockStatus::FullyEnforced {
        return Err(unsupported_floor());
    }
    check_required(required, applied.restrictions)?;
    Ok(applied)
}

#[cfg(target_os = "linux")]
fn unsupported_floor() -> GateError {
    GateError::LockUnsupported {
        reason: "this kernel does not fully enforce Landlock ABI v3; \
                 opt into `LockPolicy::BestEffort` or run under the broker (M3)"
            .into(),
    }
}

/// A failed build step that was a hard requirement: a missing kernel
/// feature becomes `LockUnsupported`, anything else stays `LockFailed`.
#[cfg(target_os = "linux")]
fn unsupported_or_failed(
    err: landlock::RulesetError,
    unsupported: impl FnOnce() -> GateError,
) -> GateError {
    use landlock::{HandleAccessError, HandleAccessesError, RulesetError, ScopeError};

    match err {
        RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError::Compat(_)))
        | RulesetError::Scope(ScopeError::Compat(_))
        | RulesetError::RestrictSelfFlags(_) => unsupported(),
        other => lock_failed(other),
    }
}

#[cfg(target_os = "linux")]
fn member_error(set: Restrictions, err: landlock::RulesetError) -> GateError {
    unsupported_or_failed(err, || {
        let info = RESTRICTIONS
            .iter()
            .find(|info| info.set == set)
            .expect("every member has an entry in RESTRICTIONS");
        unsupported_member(info)
    })
}

#[cfg(target_os = "linux")]
fn lock_failed<E: std::error::Error + Send + Sync + 'static>(source: E) -> GateError {
    GateError::LockFailed {
        source: Box::new(source),
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn apply<'a>(
    grants: impl Iterator<Item = &'a GrantEntry>,
    options: LockOptions,
) -> Result<Applied, GateError> {
    let _ = grants;
    if options.policy() == LockPolicy::Strict {
        return Err(GateError::LockUnsupported {
            reason: format!(
                "kernel containment is not implemented on {}; \
                 opt into `LockPolicy::BestEffort` or run under the broker (M3)",
                std::env::consts::OS
            ),
        });
    }
    let applied = achieved(0, false, options.requested());
    check_required(options.required(), applied.restrictions)?;
    Ok(applied)
}

/// What a lock achieved, from the kernel's effective Landlock ABI (`0`
/// without Landlock) and whether the ruleset reached every thread.
///
/// The status describes the ABI v3 filesystem rules alone. The crate's
/// aggregate `RulesetStatus` is not used for it, because that reads as
/// partial whenever any requested restriction is missing.
fn achieved(abi: u8, all_threads: bool, requested: Restrictions) -> Applied {
    let status = match abi {
        0 => LockStatus::LibraryOnly,
        1 | 2 => LockStatus::PartiallyEnforced,
        _ => LockStatus::FullyEnforced,
    };
    // The crate reports all-thread enforcement directly; the rest follow
    // from the ABI.
    let mut supported = if all_threads {
        Restrictions::ALL_THREADS
    } else {
        Restrictions::empty()
    };
    for info in RESTRICTIONS {
        if info.set != Restrictions::ALL_THREADS && abi >= info.abi {
            supported = supported | info.set;
        }
    }
    Applied {
        status,
        restrictions: supported & requested,
    }
}

fn check_required(required: Restrictions, achieved: Restrictions) -> Result<(), GateError> {
    match RESTRICTIONS
        .iter()
        .find(|info| required.contains(info.set) && !achieved.contains(info.set))
    {
        Some(info) => Err(unsupported_member(info)),
        None => Ok(()),
    }
}

fn unsupported_member(info: &RestrictionInfo) -> GateError {
    GateError::LockUnsupported {
        reason: format!(
            "`Restrictions::{}` needs Landlock ABI v{} (Linux {}), which this system \
             does not provide; remove it from `LockOptions::require` or run on a newer \
             Linux kernel",
            info.name, info.abi, info.linux
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: Restrictions = Restrictions::all();

    #[test]
    fn status_follows_the_filesystem_floor_alone() {
        assert_eq!(achieved(0, false, ALL).status, LockStatus::LibraryOnly);
        for abi in 1..=2 {
            assert_eq!(
                achieved(abi, false, ALL).status,
                LockStatus::PartiallyEnforced
            );
        }
        // Fully enforced from v3 on, whatever restrictions are missing.
        for abi in 3..=9 {
            assert_eq!(achieved(abi, false, ALL).status, LockStatus::FullyEnforced);
        }
    }

    #[test]
    fn restrictions_follow_the_abi_that_provides_them() {
        let expected = |abi: u8| {
            let mut set = Restrictions::empty();
            if abi >= 5 {
                set = set | Restrictions::IOCTL_DEV;
            }
            if abi >= 6 {
                set = set | Restrictions::ABSTRACT_UNIX_SOCKET | Restrictions::SIGNAL;
            }
            if abi >= 9 {
                set = set | Restrictions::RESOLVE_UNIX;
            }
            set
        };
        for abi in 0..=9 {
            assert_eq!(
                achieved(abi, false, ALL).restrictions,
                expected(abi),
                "v{abi}"
            );
        }
        // All-thread enforcement comes from the crate's report, not the ABI.
        assert_eq!(
            achieved(8, true, ALL).restrictions,
            expected(8) | Restrictions::ALL_THREADS
        );
        assert!(
            !achieved(9, false, ALL)
                .restrictions
                .contains(Restrictions::ALL_THREADS)
        );
    }

    #[test]
    fn only_requested_restrictions_are_reported() {
        let requested = ALL - Restrictions::SIGNAL - Restrictions::ALL_THREADS;
        assert_eq!(
            achieved(8, true, requested).restrictions,
            Restrictions::IOCTL_DEV | Restrictions::ABSTRACT_UNIX_SOCKET
        );
        assert!(
            achieved(9, true, Restrictions::empty())
                .restrictions
                .is_empty()
        );
    }

    #[test]
    fn a_missing_requirement_names_the_kernel_that_provides_it() {
        let have = Restrictions::IOCTL_DEV;
        assert!(check_required(Restrictions::IOCTL_DEV, have).is_ok());
        assert!(check_required(Restrictions::empty(), Restrictions::empty()).is_ok());

        let err = check_required(Restrictions::SIGNAL | Restrictions::ALL_THREADS, have)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("`Restrictions::SIGNAL` needs Landlock ABI v6 (Linux 6.12)"),
            "{err}"
        );
        assert!(
            err.contains("remove it from `LockOptions::require`"),
            "{err}"
        );
    }

    #[test]
    fn every_member_has_one_entry_in_rfc_order() {
        let mut seen = Restrictions::empty();
        for info in RESTRICTIONS {
            assert!(!seen.contains(info.set), "{} listed twice", info.name);
            seen = seen | info.set;
        }
        assert_eq!(seen, Restrictions::all());
        let abis: Vec<u8> = RESTRICTIONS.iter().map(|info| info.abi).collect();
        assert!(abis.windows(2).all(|pair| pair[0] <= pair[1]));
    }
}
