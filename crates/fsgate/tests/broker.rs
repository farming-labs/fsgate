//! Broker transport tests: the same authority decisions over a socket,
//! descriptors via SCM_RIGHTS, and fail-closed behavior when the broker
//! disappears. The end-to-end test drives the real `fsgate-broker`
//! binary.

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use fsgate::{Broker, BrokerGate, Gate, GateError, Rights};
use tempfile::TempDir;

fn setup() -> (TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("create temp root");
    let granted = root.path().join("granted");
    let outside = root.path().join("outside");
    fs::create_dir(&granted).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(granted.join("a.txt"), b"inside").unwrap();
    fs::write(outside.join("secret.txt"), b"secret").unwrap();
    (root, granted, outside)
}

/// A client connected to a broker serving one socketpair connection.
fn brokered(gate: Gate) -> (BrokerGate, thread::JoinHandle<()>) {
    let (client, server) = UnixStream::pair().expect("socketpair");
    let handle = thread::spawn(move || {
        let broker = Broker::new(gate);
        let _ = broker.serve_conn(server);
    });
    (BrokerGate::from_stream(client), handle)
}

#[test]
fn open_travels_over_the_socket() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();
    let (mut client, _server) = brokered(gate);

    let mut file = client.open(granted.join("a.txt")).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content, "inside");
}

/// The worker's own opens are close-on-exec, so a descriptor the broker
/// delivers must not survive into a program the worker starts.
#[test]
fn delivered_descriptors_do_not_leak_into_spawned_programs() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();
    let (mut client, _server) = brokered(gate);

    let file = client.open(granted.join("a.txt")).unwrap();

    // `/dev/fd/N` names the child's descriptor N, which is the delivered
    // file only if it was inherited across exec.
    let output = Command::new("cat")
        .arg(format!("/dev/fd/{}", file.as_raw_fd()))
        .output()
        .expect("run cat");
    assert!(
        !output.status.success(),
        "descriptor leaked across exec: child read {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.stdout.is_empty());

    // The descriptor is still valid in the worker itself.
    let mut content = String::new();
    (&file).read_to_string(&mut content).unwrap();
    assert_eq!(content, "inside");
}

#[test]
fn create_travels_over_the_socket() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();
    let (mut client, _server) = brokered(gate);

    let mut file = client.create(granted.join("new.txt")).unwrap();
    file.write_all(b"written").unwrap();
    drop(file);
    assert_eq!(
        fs::read_to_string(granted.join("new.txt")).unwrap(),
        "written"
    );
}

#[test]
fn denials_cross_the_wire_typed_and_leave_no_side_effect() {
    let (_root, granted, outside) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();
    let (mut client, _server) = brokered(gate);

    // No grant: typed error, nothing created.
    let target = outside.join("planted.txt");
    let err = client.create(&target).unwrap_err();
    assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");
    assert!(!target.exists());

    // Rights exceeded: the missing rights survive serialization.
    let target = granted.join("planted.txt");
    match client.create(&target).unwrap_err() {
        GateError::RightsExceeded { missing, op, .. } => {
            assert!(missing.contains(Rights::CREATE));
            assert!(missing.contains(Rights::WRITE));
            assert_eq!(op, "create");
        }
        other => panic!("expected RightsExceeded, got {other:?}"),
    }
    assert!(!target.exists());
}

#[test]
fn metadata_and_read_dir_cross_the_wire() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::LIST).unwrap();
    let (mut client, _server) = brokered(gate);

    let stat = client.metadata(granted.join("a.txt")).unwrap();
    assert!(stat.is_file);
    assert_eq!(stat.len, "inside".len() as u64);

    let entries = client.read_dir(&granted).unwrap();
    assert_eq!(entries, vec!["a.txt".to_string()]);
}

#[test]
fn dead_broker_fails_every_operation_closed() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let (client_stream, server_stream) = UnixStream::pair().unwrap();
    drop(server_stream); // the "broker" is gone before the first request
    drop(gate);
    let mut client = BrokerGate::from_stream(client_stream);

    let err = client.open(granted.join("a.txt")).unwrap_err();
    assert!(matches!(err, GateError::Broker { .. }), "got {err:?}");
}

/// End to end against the real binary, including the roadmap acceptance:
/// killing the broker fails all subsequent operations closed.
#[test]
fn broker_binary_serves_and_dies_closed() {
    let (root, granted, outside) = setup();
    let socket = root.path().join("broker.sock");

    let mut broker = std::process::Command::new(env!("CARGO_BIN_EXE_fsgate-broker"))
        .args([
            "--grant",
            &format!("{}:rl", granted.display()),
            "--socket",
            &socket.display().to_string(),
            "--",
            "sh",
            "-c",
            "sleep 30",
        ])
        .spawn()
        .expect("spawn fsgate-broker");

    // Wait for the socket to appear.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "broker socket never appeared");
        thread::sleep(Duration::from_millis(20));
    }

    let mut client = BrokerGate::connect(&socket).unwrap();

    // Granted read works through the real binary.
    let mut file = client.open(granted.join("a.txt")).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content, "inside");

    // Ungated path is denied server-side.
    let err = client.open(outside.join("secret.txt")).unwrap_err();
    assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");

    // Kill the broker: everything fails closed from here on.
    broker.kill().expect("kill broker");
    broker.wait().expect("reap broker");
    let err = client.open(granted.join("a.txt")).unwrap_err();
    assert!(matches!(err, GateError::Broker { .. }), "got {err:?}");
}
