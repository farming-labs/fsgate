//! Audit events: one per authority decision, delivered to an embedder
//! sink. Format and semantics are RFC 0002.
//!
//! Auditing is observation only — nothing in a sink can veto or alter a
//! decision. Delivery is synchronous in the calling thread, after the
//! decision and before the result returns, so a sink always sees a
//! denial even if the caller swallows the error.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Restrictions, Rights};

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
    /// A connection a [`Broker`](crate::Broker) accepted with
    /// [`serve_with`](crate::Broker::serve_with), admitted or refused
    /// before any request (RFC 0011).
    Connect,
    /// A broker request that never reached the gate, because its frame or
    /// its contents broke the protocol (RFC 0011). A request that parses is
    /// audited by the gate under its own operation.
    Request,
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
            AuditOp::Connect => "connect",
            AuditOp::Request => "request",
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
    /// An intercepted request (RFC 0004) asked for something the
    /// interception profile does not support: a path that is relative,
    /// non-canonical, or not UTF-8, a write or other unsupported flag, or an
    /// unsupported `openat2` layout or resolve flag.
    UnsupportedInput,
    /// An intercepted request's arguments could not be copied out of the
    /// worker's memory: unreadable, inaccessible, or with no terminator
    /// within the path limit.
    InvalidMemory,
    /// A broker connection from a uid the broker does not admit, or whose
    /// uid could not be read.
    PeerRefused,
    /// A broker connection past
    /// [`ServeOptions::max_connections`](crate::ServeOptions::max_connections).
    ConnectionLimit,
    /// A broker connection the process could not start a thread for.
    NoThread,
    /// A broker request whose length prefix is over the protocol's 1 MiB
    /// limit.
    FrameTooLarge,
    /// A broker request with bytes past its declared length, or with a
    /// file descriptor attached.
    MalformedFrame,
    /// A broker request whose frame is not a valid request.
    MalformedRequest,
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
            AuditReason::UnsupportedInput => "unsupported_input",
            AuditReason::InvalidMemory => "invalid_memory",
            AuditReason::PeerRefused => "peer_refused",
            AuditReason::ConnectionLimit => "connection_limit",
            AuditReason::NoThread => "no_thread",
            AuditReason::FrameTooLarge => "frame_too_large",
            AuditReason::MalformedFrame => "malformed_frame",
            AuditReason::MalformedRequest => "malformed_request",
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
    /// For `grant` and `narrow`, the rights the grant holds after the
    /// decision; `None` when no grant was created or matched, and for
    /// every other operation.
    pub rights: Option<Rights>,
    /// For a successful `lock`, the [`Restrictions`] that took effect;
    /// `None` for a refused lock and every other operation.
    pub restrictions: Option<Restrictions>,
    /// Allow or deny.
    pub decision: AuditDecision,
    /// Why.
    pub reason: AuditReason,
    /// OS error number when policy allowed but the syscall failed.
    pub errno: Option<i32>,
    /// For a request intercepted from a worker's syscall (RFC 0004), that
    /// syscall: `open`, `openat`, or `openat2`. `None` otherwise.
    pub syscall: Option<&'static str>,
    /// For an intercepted request, its seccomp notification ID. `None`
    /// otherwise.
    pub notification: Option<u64>,
    /// For a `connect` event, and a `request` event on a connection
    /// [`Broker::serve_with`](crate::Broker::serve_with) accepted, the
    /// peer's effective uid. `None` when it could not be read, on a
    /// connection given to [`Broker::serve_conn`](crate::Broker::serve_conn),
    /// and for every other operation.
    pub peer_uid: Option<u32>,
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
            "rights": self.rights.map(right_names),
            "restrictions": self.restrictions.map(restriction_names),
            "decision": self.decision.as_str(),
            "reason": self.reason.as_str(),
            "errno": self.errno,
            "syscall": self.syscall,
            "notification": self.notification,
            "peer_uid": self.peer_uid,
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
///     let fsgate::AuditEvent { ts, op, path, grant, rights, decision, reason, errno, .. } = event;
///     let _ = (ts, op, path, grant, rights, decision, reason, errno);
/// }
/// ```
///
/// ```compile_fail
/// fn fields(event: &fsgate::AuditEvent) {
///     let fsgate::AuditEvent { ts, op, path, grant, rights, decision, reason, errno } = event;
///     let _ = (ts, op, path, grant, rights, decision, reason, errno);
/// }
/// ```
#[cfg(doctest)]
struct ExtensibleTypesDoctest;

/// The RFC 0002 wire names of `rights`, in a fixed order.
/// RFC 0006 restriction names for the `restrictions` key, in the fixed
/// order of [`crate::RESTRICTIONS`].
fn restriction_names(restrictions: Restrictions) -> Vec<String> {
    crate::RESTRICTIONS
        .iter()
        .filter(|info| restrictions.contains(info.set))
        .map(|info| info.name.to_ascii_lowercase())
        .collect()
}

fn right_names(rights: Rights) -> Vec<&'static str> {
    [
        (Rights::READ, "read"),
        (Rights::WRITE, "write"),
        (Rights::CREATE, "create"),
        (Rights::LIST, "list"),
    ]
    .into_iter()
    .filter(|(right, _)| rights.contains(*right))
    .map(|(_, name)| name)
    .collect()
}

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

    fn lock_event(restrictions: Option<Restrictions>) -> serde_json::Value {
        let event = AuditEvent {
            ts: UNIX_EPOCH,
            op: AuditOp::Lock,
            path: None,
            grant: None,
            rights: None,
            restrictions,
            decision: AuditDecision::Allow,
            reason: AuditReason::Ok,
            errno: None,
            syscall: None,
            notification: None,
            peer_uid: None,
        };
        serde_json::from_str(&event.to_json_line()).unwrap()
    }

    #[test]
    fn restrictions_key_lists_names_in_rfc_order() {
        let all = lock_event(Some(Restrictions::all()));
        assert_eq!(
            all["restrictions"],
            serde_json::json!([
                "ioctl_dev",
                "abstract_unix_socket",
                "signal",
                "all_threads",
                "resolve_unix"
            ])
        );
        // Insertion order does not matter; the key always uses RFC order.
        let two = lock_event(Some(Restrictions::ALL_THREADS | Restrictions::IOCTL_DEV));
        assert_eq!(
            two["restrictions"],
            serde_json::json!(["ioctl_dev", "all_threads"])
        );
        let none = lock_event(Some(Restrictions::empty()));
        assert_eq!(none["restrictions"], serde_json::json!([]));
        let refused = lock_event(None);
        assert!(refused["restrictions"].is_null());
    }
}
