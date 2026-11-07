//! Audit events: one per authority decision, delivered to an embedder
//! sink. Format and semantics are RFC 0002.
//!
//! Auditing is observation only — nothing in a sink can veto or alter a
//! decision. Delivery is synchronous in the calling thread, after the
//! decision and before the result returns, so a sink always sees a
//! denial even if the caller swallows the error.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Receives every allow/deny decision a [`Gate`](crate::Gate) makes.
///
/// The embedder owns buffering and backpressure; fsgate calls `event`
/// inline and never drops an event itself.
pub trait AuditSink: Send + Sync {
    /// Called once per decision.
    fn event(&self, event: &AuditEvent);
}

/// The operation an event describes.
///
/// Operations grow with the API, so a `match` outside fsgate needs a
/// wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditOp {
    /// A grant was requested.
    Grant,
    /// A grant was revoked.
    Revoke,
    /// A grant's rights were narrowed (RFC 0005).
    Narrow,
    /// The gate was locked.
    Lock,
    /// A file open for reading.
    Open,
    /// A file create for writing.
    Create,
    /// A metadata read.
    Metadata,
    /// A directory listing.
    ReadDir,
}

impl AuditOp {
    /// The wire name from RFC 0002.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditOp::Grant => "grant",
            AuditOp::Revoke => "revoke",
            AuditOp::Narrow => "narrow",
            AuditOp::Lock => "lock",
            AuditOp::Open => "open",
            AuditOp::Create => "create",
            AuditOp::Metadata => "metadata",
            AuditOp::ReadDir => "read_dir",
        }
    }
}

/// Whether policy said yes or no.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditDecision {
    /// Policy allowed the operation (the OS may still have refused it;
    /// then `errno` is set).
    Allow,
    /// Policy denied the operation; it did not happen.
    Deny,
}

impl AuditDecision {
    /// The wire name from RFC 0002.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditDecision::Allow => "allow",
            AuditDecision::Deny => "deny",
        }
    }
}

/// Why the decision came out the way it did.
///
/// Reasons grow with the API, so a `match` outside fsgate needs a
/// wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditReason {
    /// Policy was satisfied.
    Ok,
    /// No grant covered the path.
    NoGrant,
    /// The covering grant lacked a needed right. For `narrow`, the
    /// requested set named a right the grant does not hold.
    RightsExceeded,
    /// The requested path was not absolute.
    NotAbsolute,
    /// The gate was already locked.
    Locked,
    /// Kernel containment was unavailable or failed to apply.
    Unsupported,
    /// The revoked or narrowed grant did not exist.
    UnknownGrant,
}

impl AuditReason {
    /// The wire name from RFC 0002.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditReason::Ok => "ok",
            AuditReason::NoGrant => "no_grant",
            AuditReason::RightsExceeded => "rights_exceeded",
            AuditReason::NotAbsolute => "not_absolute",
            AuditReason::Locked => "locked",
            AuditReason::Unsupported => "unsupported",
            AuditReason::UnknownGrant => "unknown_grant",
        }
    }
}

/// One authority decision (RFC 0002, format version 1).
///
/// Fields may be added without a breaking release, so code outside
/// fsgate reads fields or destructures with `..`; only a
/// [`Gate`](crate::Gate) creates events.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AuditEvent {
    /// When the decision was made.
    pub ts: SystemTime,
    /// The operation.
    pub op: AuditOp,
    /// The normalized requested path; the grant's path for
    /// `grant`/`revoke`/`narrow`; `None` for `lock`.
    pub path: Option<PathBuf>,
    /// The matched grant's id, when one matched.
    pub grant: Option<usize>,
    /// Allow or deny.
    pub decision: AuditDecision,
    /// Why.
    pub reason: AuditReason,
    /// OS error number when policy allowed but the syscall failed.
    pub errno: Option<i32>,
}

impl AuditEvent {
    /// The canonical JSON Lines form from RFC 0002 (no trailing newline).
    ///
    /// Non-UTF-8 path bytes are rendered lossily; the typed event keeps
    /// the exact [`PathBuf`].
    pub fn to_json_line(&self) -> String {
        let value = serde_json::json!({
            "v": 1,
            "ts": rfc3339_millis(self.ts),
            "op": self.op.as_str(),
            "path": self.path.as_ref().map(|path| path.to_string_lossy()),
            "grant": self.grant,
            "decision": self.decision.as_str(),
            "reason": self.reason.as_str(),
            "errno": self.errno,
        });
        value.to_string()
    }
}

/// Compile checks from outside the crate. Each `compile_fail` block has a
/// passing twin that differs only by the wildcard or `..`, so an unrelated
/// compile error cannot satisfy it.
///
/// ```
/// fn op(op: fsgate::AuditOp) {
///     use fsgate::AuditOp::*;
///     match op {
///         Grant | Revoke | Narrow | Lock | Open | Create | Metadata | ReadDir => {}
///         _ => {}
///     }
/// }
/// ```
///
/// ```compile_fail
/// fn op(op: fsgate::AuditOp) {
///     use fsgate::AuditOp::*;
///     match op {
///         Grant | Revoke | Narrow | Lock | Open | Create | Metadata | ReadDir => {}
///     }
/// }
/// ```
///
/// ```
/// fn reason(reason: fsgate::AuditReason) {
///     use fsgate::AuditReason::*;
///     match reason {
///         Ok | NoGrant | RightsExceeded | NotAbsolute | Locked | Unsupported | UnknownGrant => {}
///         _ => {}
///     }
/// }
/// ```
///
/// ```compile_fail
/// fn reason(reason: fsgate::AuditReason) {
///     use fsgate::AuditReason::*;
///     match reason {
///         Ok | NoGrant | RightsExceeded | NotAbsolute | Locked | Unsupported | UnknownGrant => {}
///     }
/// }
/// ```
///
/// ```
/// fn fields(event: &fsgate::AuditEvent) {
///     let fsgate::AuditEvent { ts, op, path, grant, decision, reason, errno, .. } = event;
///     let _ = (ts, op, path, grant, decision, reason, errno);
/// }
/// ```
///
/// ```compile_fail
/// fn fields(event: &fsgate::AuditEvent) {
///     let fsgate::AuditEvent { ts, op, path, grant, decision, reason, errno } = event;
///     let _ = (ts, op, path, grant, decision, reason, errno);
/// }
/// ```
#[cfg(doctest)]
struct ExtensibleTypesDoctest;

/// RFC 3339 UTC with milliseconds, from civil-date arithmetic — no
/// clock/calendar dependency for one format.
fn rfc3339_millis(ts: SystemTime) -> String {
    let duration = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let (hour, minute, second) = {
        let rem = secs % 86_400;
        (rem / 3_600, (rem % 3_600) / 60, rem % 60)
    };
    // Days-to-civil conversion (Howard Hinnant's algorithm).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe as i64 + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn rfc3339_matches_known_timestamps() {
        let epoch = UNIX_EPOCH;
        assert_eq!(rfc3339_millis(epoch), "1970-01-01T00:00:00.000Z");
        // 2026-01-01T00:00:00Z
        let ts = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        assert_eq!(rfc3339_millis(ts), "2026-01-01T00:00:00.000Z");
        // Leap-year day: 2024-02-29T12:34:56.789Z
        let ts = UNIX_EPOCH + Duration::from_millis(1_709_210_096_789);
        assert_eq!(rfc3339_millis(ts), "2024-02-29T12:34:56.789Z");
    }
}
