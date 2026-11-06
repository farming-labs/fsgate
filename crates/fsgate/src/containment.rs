//! Kernel containment applied at [`Gate::lock`](crate::Gate::lock).
//!
//! On Linux this is a Landlock ruleset built from the live grants: the
//! ruleset handles every filesystem access the ABI knows, so anything not
//! explicitly allowed beneath a grant is denied by the kernel for the
//! whole thread family, including code that never touches the `Gate`.
//! Filesystem path syscalls are mediated by Landlock rather than seccomp;
//! the reasoning is recorded in ADR 0002.

use crate::{GateError, GrantEntry, LockPolicy, LockStatus};

#[cfg(target_os = "linux")]
pub(crate) fn apply<'a>(
    grants: impl Iterator<Item = &'a GrantEntry>,
    policy: LockPolicy,
) -> Result<LockStatus, GateError> {
    use landlock::{
        ABI, Access, AccessFs, BitFlags, PathBeneath, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus,
    };

    use crate::Rights;

    // V3 adds Truncate, which `Gate::create` needs for existing files.
    let abi = ABI::V3;

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(lock_failed)?
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
        }
        if entry.rights.contains(Rights::CREATE) {
            access |= AccessFs::MakeReg;
        }
        // The rule is bound to the held descriptor, not the path name.
        ruleset = ruleset
            .add_rule(PathBeneath::new(&entry.dir, access))
            .map_err(lock_failed)?;
    }

    let status = ruleset.restrict_self().map_err(lock_failed)?;
    match (policy, status.ruleset) {
        (_, RulesetStatus::FullyEnforced) => Ok(LockStatus::FullyEnforced),
        (LockPolicy::BestEffort, RulesetStatus::PartiallyEnforced) => {
            Ok(LockStatus::PartiallyEnforced)
        }
        (LockPolicy::BestEffort, RulesetStatus::NotEnforced) => Ok(LockStatus::LibraryOnly),
        (LockPolicy::Strict, _) => Err(GateError::LockUnsupported {
            reason: "this kernel does not fully enforce Landlock ABI v3; \
                     opt into `LockPolicy::BestEffort` or run under the broker (M3)"
                .into(),
        }),
    }
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
    policy: LockPolicy,
) -> Result<LockStatus, GateError> {
    let _ = grants;
    match policy {
        LockPolicy::Strict => Err(GateError::LockUnsupported {
            reason: format!(
                "kernel containment is not implemented on {}; \
                 opt into `LockPolicy::BestEffort` or run under the broker (M3)",
                std::env::consts::OS
            ),
        }),
        LockPolicy::BestEffort => Ok(LockStatus::LibraryOnly),
    }
}
