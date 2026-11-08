//! Broker transport tests: the same authority decisions over a socket,
//! descriptors via SCM_RIGHTS, and fail-closed behavior when the broker
//! disappears. The end-to-end test drives the real `fsgate-broker`
//! binary.

#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;

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

/// A frame is exactly as long as its prefix says (RFC 0003). A request
/// with more bytes than its prefix declares is a protocol violation, so the
/// broker closes the connection without acting on any of it.
#[test]
fn bytes_beyond_the_declared_length_fail_the_connection_closed() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();
    let planted = granted.join("planted.txt");

    let (mut client, server) = UnixStream::pair().unwrap();
    let broker = thread::spawn(move || Broker::new(gate).serve_conn(server));

    let body = serde_json::json!({ "op": "create", "path": planted }).to_string();
    let mut frame = 2u32.to_le_bytes().to_vec(); // declares 2 bytes, sends more
    frame.extend_from_slice(body.as_bytes());
    client.write_all(&frame).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let err = broker.join().unwrap().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    assert!(
        response.is_empty(),
        "the broker answered a misframed request"
    );
    assert!(!planted.exists(), "the broker acted on a misframed request");
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
            "echo ready; exec sleep 30",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn fsgate-broker");

    // The socket file exists from bind(), but connecting before listen() is
    // refused. The broker starts its command only after both, so the
    // command's first line is the readiness signal.
    let mut ready = String::new();
    BufReader::new(broker.stdout.take().expect("piped stdout"))
        .read_line(&mut ready)
        .expect("read the broker command's output");
    assert_eq!(
        ready, "ready\n",
        "broker exited before starting its command"
    );

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

fn broker_usage(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_fsgate-broker"))
        .args(args)
        .output()
        .expect("run fsgate-broker")
}

#[test]
fn interception_flags_do_not_mix_with_socket_mode() {
    let both = broker_usage(&[
        "--experimental-intercept",
        "--socket",
        "/tmp/unused.sock",
        "--grant",
        "/tmp:r",
        "--",
        "/bin/true",
    ]);
    let stray = broker_usage(&[
        "--apply",
        "--socket",
        "/tmp/unused.sock",
        "--grant",
        "/tmp:r",
        "--",
        "/bin/true",
    ]);

    assert_eq!(both.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&both.stderr).contains("separate modes"));
    assert_eq!(stray.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&stray.stderr).contains("need `--experimental-intercept`"));
}

#[cfg(not(all(
    feature = "experimental-intercept",
    target_os = "linux",
    target_arch = "x86_64"
)))]
#[test]
fn interception_mode_is_a_usage_error_without_the_feature() {
    let output = broker_usage(&[
        "--experimental-intercept",
        "--grant",
        "/tmp:r",
        "--apply",
        "--",
        "/bin/true",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("interception mode"));
    assert!(output.stdout.is_empty());
}
