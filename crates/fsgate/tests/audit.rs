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

#[test]
fn lifecycle_events_cover_grant_revoke_and_lock() {
    let (_root, granted, _) = setup();
    let sink = Arc::new(Capture::default());
    let mut gate = Gate::new();
    gate.set_audit_sink(sink.clone());

    let grant = gate.grant(&granted, Rights::READ).unwrap();
    gate.revoke(grant).unwrap();
    gate.lock_with(fsgate::LockPolicy::BestEffort).unwrap();
    let _ = gate.grant(&granted, Rights::READ); // denied: locked

    let kinds: Vec<_> = sink
        .events()
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
        ]
    );
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
