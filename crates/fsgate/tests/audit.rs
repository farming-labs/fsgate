//! Audit sink tests: every allow and deny is observed (RFC 0002),
//! including denials the caller swallows and decisions made broker-side.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fsgate::{AuditDecision, AuditEvent, AuditOp, AuditReason, AuditSink, Gate, GateError, Rights};
use tempfile::TempDir;

#[derive(Default)]
struct Capture(Mutex<Vec<AuditEvent>>);

impl AuditSink for Capture {
    fn event(&self, event: &AuditEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

impl Capture {
    fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().unwrap().clone()
    }
}

fn setup() -> (TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let granted = root.path().join("granted");
    let outside = root.path().join("outside");
    fs::create_dir(&granted).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(granted.join("a.txt"), b"inside").unwrap();
    (root, granted, outside)
}

fn audited_gate(granted: &PathBuf, rights: Rights) -> (Gate, Arc<Capture>) {
    let sink = Arc::new(Capture::default());
    let mut gate = Gate::new();
    gate.set_audit_sink(sink.clone());
    gate.grant(granted, rights).unwrap();
    (gate, sink)
}

#[test]
fn success_emits_an_allow_event() {
    let (_root, granted, _) = setup();
    let (gate, sink) = audited_gate(&granted, Rights::READ);

    gate.open(granted.join("a.txt")).unwrap();

    let events = sink.events();
    let last = events.last().unwrap();
    assert_eq!(last.op, AuditOp::Open);
    assert_eq!(last.decision, AuditDecision::Allow);
    assert_eq!(last.reason, AuditReason::Ok);
    assert_eq!(last.grant, Some(0));
    assert_eq!(last.errno, None);
    assert_eq!(last.path.as_deref(), Some(granted.join("a.txt").as_path()));
}

#[test]
fn swallowed_denial_is_still_observed() {
    let (_root, granted, outside) = setup();
    let (gate, sink) = audited_gate(&granted, Rights::READ);

    // The caller discards the error; the sink must see the denial anyway.
    let _ = gate.open(outside.join("secret.txt"));

    let last = sink.events().pop().unwrap();
    assert_eq!(last.op, AuditOp::Open);
    assert_eq!(last.decision, AuditDecision::Deny);
    assert_eq!(last.reason, AuditReason::NoGrant);
    assert_eq!(last.grant, None);
}

#[test]
fn rights_exceeded_names_the_matched_grant() {
    let (_root, granted, _) = setup();
    let (mut gate, sink) = audited_gate(&granted, Rights::READ | Rights::WRITE | Rights::CREATE);
    gate.grant(&granted, Rights::READ).unwrap();

    for name in ["new.txt", "a.txt"] {
        let path = granted.join(name);
        let err = gate.create(granted.join("sub/..").join(name)).unwrap_err();
        assert!(matches!(err, GateError::RightsExceeded { .. }), "{err:?}");

        let last = sink.events().pop().unwrap();
        assert_eq!(last.op, AuditOp::Create);
        assert_eq!(last.decision, AuditDecision::Deny);
        assert_eq!(last.reason, AuditReason::RightsExceeded);
        assert_eq!(last.grant, Some(1));
        assert_eq!(last.path.as_deref(), Some(path.as_path()));
        assert_eq!(last.errno, None);
    }
    assert_eq!(sink.events().len(), 4);
    assert!(!granted.join("new.txt").exists());
    assert_eq!(fs::read(granted.join("a.txt")).unwrap(), b"inside");
}

#[test]
fn rights_denials_follow_routing_and_revocation_for_every_operation() {
    let (_root, granted, _) = setup();
    let (mut gate, sink) = audited_gate(
        &granted,
        Rights::READ | Rights::WRITE | Rights::CREATE | Rights::LIST,
    );
    let sub = granted.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("a.txt"), b"inside").unwrap();
    let restricted = gate.grant(&sub, Rights::from_bits_truncate(0)).unwrap();
    let path = sub.join("a.txt");

    let results = [
        gate.open(&path).map(|_| ()),
        gate.create(&path).map(|_| ()),
        gate.metadata(&path).map(|_| ()),
        gate.read_dir(&sub).map(|_| ()),
    ];
    for result in results {
        assert!(matches!(result, Err(GateError::RightsExceeded { .. })));
    }
    let events = sink.events();
    assert_eq!(events.len(), 6);
    for (event, op) in events[2..].iter().zip([
        AuditOp::Open,
        AuditOp::Create,
        AuditOp::Metadata,
        AuditOp::ReadDir,
    ]) {
        assert_eq!(event.op, op);
        assert_eq!(event.decision, AuditDecision::Deny);
        assert_eq!(event.reason, AuditReason::RightsExceeded);
        assert_eq!(event.grant, Some(1));
        assert_eq!(event.errno, None);
    }
    assert_eq!(fs::read(&path).unwrap(), b"inside");

    gate.revoke(restricted).unwrap();
    gate.open(&path).unwrap();
    let last = sink.events().pop().unwrap();
    assert_eq!(last.grant, Some(0));
    assert_eq!(last.decision, AuditDecision::Allow);
}

#[test]
fn kernel_refusal_is_allow_with_errno() {
    let (_root, granted, _) = setup();
    let (gate, sink) = audited_gate(&granted, Rights::READ);

    // Policy says yes; the OS says ENOENT. Both facts are recorded.
    let _ = gate.open(granted.join("missing.txt"));

    let last = sink.events().pop().unwrap();
    assert_eq!(last.decision, AuditDecision::Allow);
    assert_eq!(last.reason, AuditReason::Ok);
    assert!(last.errno.is_some(), "expected an errno, got {last:?}");
}

/// A symlink out of the grant is refused while the path resolves, after
/// policy allowed the request, so the event is `allow` with an errno. Without
/// one it reads as a success. cap-std's component walk, which macOS always
/// uses, reported this refusal with no errno.
#[cfg(unix)]
#[test]
fn an_escape_is_audited_with_its_errno() {
    let (_root, granted, outside) = setup();
    fs::write(outside.join("secret.txt"), b"secret").unwrap();
    std::os::unix::fs::symlink("../outside", granted.join("link")).unwrap();
    let all = Rights::READ | Rights::WRITE | Rights::CREATE | Rights::LIST;
    let (gate, sink) = audited_gate(&granted, all);
    let exdev = rustix::io::Errno::XDEV.raw_os_error();

    for op in [
        AuditOp::Open,
        AuditOp::Create,
        AuditOp::Metadata,
        AuditOp::ReadDir,
    ] {
        let err = match op {
            AuditOp::Open => gate.open(granted.join("link/secret.txt")).err(),
            AuditOp::Create => gate.create(granted.join("link/new.txt")).err(),
            AuditOp::Metadata => gate.metadata(granted.join("link/secret.txt")).err(),
            _ => gate.read_dir(granted.join("link")).err(),
        };
        assert!(
            matches!(&err, Some(GateError::Io { source, .. }) if source.raw_os_error() == Some(exdev)),
            "{op:?}: {err:?}"
        );
        let last = sink.events().pop().unwrap();
        assert_eq!(last.op, op);
        assert_eq!(last.decision, AuditDecision::Allow);
        assert_eq!(last.reason, AuditReason::Ok);
        assert_eq!(last.grant, Some(0));
        assert_eq!(last.errno, Some(exdev), "{op:?}: {last:?}");
    }
    assert!(!outside.join("new.txt").exists());
    assert_eq!(fs::read(outside.join("secret.txt")).unwrap(), b"secret");
}

#[test]
fn lifecycle_events_cover_grant_revoke_and_lock() {
    let (_root, granted, _) = setup();
    let sink = Arc::new(Capture::default());
    let mut gate = Gate::new();
    gate.set_audit_sink(sink.clone());

    let grant = gate.grant(&granted, Rights::READ).unwrap();
    gate.revoke(grant).unwrap();
    // On Linux this lock applies Landlock inside the test process. Leaving
    // out ALL_THREADS confines it to this test's thread.
    let options = fsgate::LockOptions::new(fsgate::LockPolicy::BestEffort)
        .restrict(fsgate::Restrictions::all() - fsgate::Restrictions::ALL_THREADS);
    gate.lock_with(options).unwrap();
    let _ = gate.grant(&granted, Rights::READ); // denied: locked
    let _ = gate.lock(); // denied: already locked

    let events = sink.events();
    let kinds: Vec<_> = events
        .iter()
        .map(|event| (event.op, event.decision, event.reason))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (AuditOp::Grant, AuditDecision::Allow, AuditReason::Ok),
            (AuditOp::Revoke, AuditDecision::Allow, AuditReason::Ok),
            (AuditOp::Lock, AuditDecision::Allow, AuditReason::Ok),
            (AuditOp::Grant, AuditDecision::Deny, AuditReason::Locked),
            (AuditOp::Lock, AuditDecision::Deny, AuditReason::Locked),
        ]
    );

    // The successful lock records the restrictions the gate reports; every
    // other event, the refused lock included, records none (RFC 0006).
    let applied = gate.restrictions().expect("locked");
    assert!(!applied.contains(fsgate::Restrictions::ALL_THREADS));
    assert_eq!(events[2].restrictions, Some(applied));
    for (index, event) in events.iter().enumerate().filter(|(index, _)| *index != 2) {
        assert!(event.restrictions.is_none(), "event {index}: {event:?}");
    }
}

#[test]
fn narrow_emits_one_event_per_decision() {
    let (_root, granted, _) = setup();
    let (mut gate, sink) = audited_gate(&granted, Rights::READ | Rights::WRITE);
    // Narrow a second grant so the events must name grant 1, not grant 0.
    let grant = gate.grant(&granted, Rights::READ | Rights::WRITE).unwrap();

    gate.narrow(grant, Rights::READ).unwrap();
    let _ = gate.narrow(grant, Rights::READ | Rights::WRITE); // denied: widens
    gate.revoke(grant).unwrap();
    let _ = gate.narrow(grant, Rights::READ); // denied: revoked

    let events = sink.events();
    let narrow: Vec<_> = events[2..]
        .iter()
        .filter(|event| event.op != AuditOp::Revoke)
        .collect();
    assert_eq!(events.len(), 6);
    assert_eq!(narrow.len(), 3);
    let expected = [
        (
            AuditDecision::Allow,
            AuditReason::Ok,
            Some(granted.as_path()),
        ),
        (
            AuditDecision::Deny,
            AuditReason::RightsExceeded,
            Some(granted.as_path()),
        ),
        (AuditDecision::Deny, AuditReason::UnknownGrant, None),
    ];
    for (event, (decision, reason, path)) in narrow.iter().zip(expected) {
        assert_eq!(event.op, AuditOp::Narrow);
        assert_eq!(event.decision, decision);
        assert_eq!(event.reason, reason);
        assert_eq!(event.path.as_deref(), path);
        assert_eq!(event.grant, Some(1));
        assert_eq!(event.errno, None);
    }

    let value: serde_json::Value = serde_json::from_str(&narrow[0].to_json_line()).unwrap();
    assert_eq!(value["op"], "narrow");
}

#[test]
fn json_lines_match_the_rfc_shape() {
    let (_root, granted, _) = setup();
    let (gate, sink) = audited_gate(&granted, Rights::READ);
    gate.open(granted.join("a.txt")).unwrap();

    let line = sink.events().pop().unwrap().to_json_line();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["v"], 1);
    assert_eq!(value["op"], "open");
    assert_eq!(value["decision"], "allow");
    assert_eq!(value["reason"], "ok");
    assert_eq!(value["grant"], 0);
    assert!(
        value["rights"].is_null(),
        "only grant and narrow carry rights"
    );
    assert!(value["errno"].is_null());
    let ts = value["ts"].as_str().unwrap();
    assert!(
        ts.len() == 24 && ts.ends_with('Z') && ts.contains('T'),
        "ts not RFC 3339 with milliseconds: {ts}"
    );
}

#[cfg(unix)]
#[test]
fn broker_decisions_are_audited_server_side() {
    use std::os::unix::net::UnixStream;

    use fsgate::{Broker, BrokerGate};

    let (_root, granted, outside) = setup();
    let (mut gate, sink) = audited_gate(&granted, Rights::READ | Rights::WRITE | Rights::CREATE);
    gate.grant(&granted, Rights::READ).unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let broker = Broker::new(gate);
        let _ = broker.serve_conn(server);
    });
    let mut client = BrokerGate::from_stream(client);

    client.open(granted.join("a.txt")).unwrap();
    let _ = client.open(outside.join("secret.txt"));
    let err = client.create(granted.join("new.txt")).unwrap_err();
    assert!(matches!(err, GateError::RightsExceeded { .. }));
    drop(client);
    handle.join().unwrap();

    let decisions: Vec<_> = sink
        .events()
        .iter()
        .filter(|event| event.op == AuditOp::Open)
        .map(|event| (event.decision, event.reason))
        .collect();
    assert_eq!(
        decisions,
        vec![
            (AuditDecision::Allow, AuditReason::Ok),
            (AuditDecision::Deny, AuditReason::NoGrant),
        ]
    );
    let last = sink.events().pop().unwrap();
    assert_eq!(last.op, AuditOp::Create);
    assert_eq!(last.decision, AuditDecision::Deny);
    assert_eq!(last.reason, AuditReason::RightsExceeded);
    assert_eq!(last.grant, Some(1));
    assert_eq!(sink.events().len(), 5);
    assert!(!granted.join("new.txt").exists());
}

#[test]
fn a_grant_from_another_gate_is_denied_without_naming_a_grant_here() {
    let (_root, granted, _) = setup();
    let (mut gate, sink) = audited_gate(&granted, Rights::READ);
    let mut other = Gate::new();
    let foreign = other.grant(&granted, Rights::READ).unwrap();

    let _ = gate.revoke(foreign);
    let _ = gate.narrow(foreign, Rights::READ);

    let events = sink.events();
    assert_eq!(events.len(), 3);
    for (event, op) in events[1..].iter().zip([AuditOp::Revoke, AuditOp::Narrow]) {
        assert_eq!(event.op, op);
        assert_eq!(event.decision, AuditDecision::Deny);
        assert_eq!(event.reason, AuditReason::UnknownGrant);
        assert_eq!(event.path, None);
        // Grant 0 of this gate is a different, live grant: the event must
        // not name it.
        assert_eq!(event.grant, None);
    }
}

#[test]
fn grant_and_narrow_events_record_the_rights_the_grant_holds_after() {
    let (_root, granted, _) = setup();
    let (mut gate, sink) = audited_gate(&granted, Rights::READ);
    let none = Rights::from_bits_truncate(0);

    let grant = gate.grant(&granted, Rights::READ | Rights::WRITE).unwrap();
    gate.narrow(grant, Rights::READ).unwrap();
    // Denied: widens. The grant keeps READ, and the event says so.
    let _ = gate.narrow(grant, Rights::READ | Rights::WRITE);
    gate.narrow(grant, none).unwrap();
    gate.revoke(grant).unwrap();
    // Denied: revoked, so no grant holds anything.
    let _ = gate.narrow(grant, none);
    // Denied: no grant is created.
    let _ = gate.grant("relative", Rights::READ);

    let events = sink.events();
    let seen: Vec<_> = events
        .iter()
        .map(|event| (event.op, event.decision, event.rights))
        .collect();
    use AuditDecision::{Allow, Deny};
    assert_eq!(
        seen,
        [
            (AuditOp::Grant, Allow, Some(Rights::READ)),
            (AuditOp::Grant, Allow, Some(Rights::READ | Rights::WRITE)),
            (AuditOp::Narrow, Allow, Some(Rights::READ)),
            (AuditOp::Narrow, Deny, Some(Rights::READ)),
            (AuditOp::Narrow, Allow, Some(none)),
            (AuditOp::Revoke, Allow, None),
            (AuditOp::Narrow, Deny, None),
            (AuditOp::Grant, Deny, None),
        ]
    );

    let rights_json = |index: usize| {
        let value: serde_json::Value = serde_json::from_str(&events[index].to_json_line()).unwrap();
        value["rights"].clone()
    };
    assert_eq!(rights_json(1), serde_json::json!(["read", "write"]));
    assert_eq!(rights_json(4), serde_json::json!([]));
    assert!(rights_json(5).is_null());
}
