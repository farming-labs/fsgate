//! Broker transport tests: the same authority decisions over a socket,
//! descriptors via SCM_RIGHTS, and fail-closed behavior when the broker
//! disappears. The end-to-end test drives the real `fsgate-broker`
//! binary.

#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

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

/// Names cross this transport as UTF-8 (RFC 0003). A directory holding a
/// name that is not is refused as a whole, never listed with a lossy
/// name, which could name a different file. Linux only: APFS refuses to
/// create such a name.
#[cfg(target_os = "linux")]
#[test]
fn a_directory_entry_name_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;

    let (_root, granted, _) = setup();
    let latin1 = std::ffi::OsStr::from_bytes(b"caf\xe9.txt");
    fs::write(granted.join(latin1), b"latin-1").unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::LIST).unwrap();
    let (mut client, _server) = brokered(gate);

    match client.read_dir(&granted).unwrap_err() {
        GateError::Broker { message } => {
            assert!(message.contains("not valid UTF-8"), "{message}")
        }
        other => panic!("expected a broker error, got {other:?}"),
    }
    // A refusal, not a lost connection: the next request is served.
    assert!(client.metadata(granted.join("a.txt")).unwrap().is_file);
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

/// Writes raw bytes to one broker connection as a worker would, closes the
/// write side, and returns how the broker ended and everything it answered.
fn serve_raw(gate: Gate, bytes: &[u8]) -> (std::io::Result<()>, Vec<u8>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    let broker = thread::spawn(move || Broker::new(gate).serve_conn(server));
    client.write_all(bytes).unwrap();
    // The broker may already have hung up, which macOS reports as
    // `NotConnected`. Either way it reads nothing more from this end.
    match client.shutdown(std::net::Shutdown::Write) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotConnected => {}
        Err(err) => panic!("shutdown failed: {err}"),
    }
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    (broker.join().unwrap(), response)
}

/// A gate that may create files beneath `granted`, so a request the broker
/// wrongly served would leave a file behind.
fn writable_gate(granted: &Path) -> Gate {
    let mut gate = Gate::new();
    gate.grant(granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();
    gate
}

fn create_request(path: &Path) -> Vec<u8> {
    serde_json::json!({ "op": "create", "path": path })
        .to_string()
        .into_bytes()
}

fn frame(declared: u32, body: &[u8]) -> Vec<u8> {
    let mut frame = declared.to_le_bytes().to_vec();
    frame.extend_from_slice(body);
    frame
}

fn assert_closed_without_acting(result: std::io::Result<()>, response: &[u8], planted: &Path) {
    let err = result.expect_err("the broker accepted a protocol violation");
    assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
    assert!(
        response.is_empty(),
        "the broker answered a protocol violation"
    );
    assert!(
        !planted.exists(),
        "the broker acted on a protocol violation"
    );
}

/// The protocol is lockstep, so a response is matched to a request only by
/// its position. After one is lost, the next response to arrive belongs to
/// the wrong request, and `open` would hand back the wrong file.
#[test]
fn a_lost_response_fails_every_later_request_closed() {
    let (client, mut broker) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut gate = BrokerGate::from_stream(client);

    // The broker has not answered yet, so the read times out.
    let err = gate.metadata("/first").unwrap_err();
    assert!(matches!(err, GateError::Broker { .. }), "got {err:?}");

    // The answer to the first request arrives late.
    let body = br#"{"result":"stat","stat":{"is_dir":false,"is_file":true,"len":111}}"#;
    broker
        .write_all(&frame(body.len() as u32, body))
        .expect("answer the first request");

    match gate.metadata("/second") {
        Err(GateError::Broker { message }) => assert!(message.contains("earlier"), "{message}"),
        Err(other) => panic!("expected a broker error, got {other:?}"),
        Ok(stat) => panic!("the answer to /first was returned for /second: {stat:?}"),
    }

    // Refused without asking: only the first request ever reached the broker.
    broker.set_nonblocking(true).unwrap();
    let mut sent = Vec::new();
    let _ = broker.read_to_end(&mut sent);
    let first = String::from_utf8_lossy(&sent);
    assert!(first.contains("/first"), "{first}");
    assert!(!first.contains("/second"), "{first}");
}

/// A frame is exactly as long as its prefix says (RFC 0003). A request
/// with more bytes than its prefix declares is a protocol violation, so the
/// broker closes the connection without acting on any of it.
#[test]
fn bytes_beyond_the_declared_length_fail_the_connection_closed() {
    let (_root, granted, _) = setup();
    let planted = granted.join("planted.txt");
    // Declares 2 bytes, then sends a whole request.
    let bytes = frame(2, &create_request(&planted));

    let (result, response) = serve_raw(writable_gate(&granted), &bytes);
    assert_closed_without_acting(result, &response, &planted);
}

/// RFC 0003 caps a frame at 1 MiB. A larger prefix fails the connection
/// before the broker reads the body.
#[test]
fn a_prefix_over_the_size_limit_fails_the_connection_closed() {
    let (_root, granted, _) = setup();
    let planted = granted.join("planted.txt");
    let bytes = frame((1 << 20) + 1, &create_request(&planted));

    let (result, response) = serve_raw(writable_gate(&granted), &bytes);
    assert_closed_without_acting(result, &response, &planted);
}

/// A body that is not exactly one known request fails the connection
/// instead of being guessed at, including a path that is not UTF-8.
#[test]
fn a_malformed_request_fails_the_connection_closed() {
    let (_root, granted, _) = setup();
    let planted = granted.join("planted.txt");
    let valid = create_request(&planted);
    let mut not_utf8 = valid.clone();
    let inside_path = not_utf8.len() - 3; // the last `t` of `planted.txt`
    not_utf8[inside_path] = 0xff;

    let bodies: [&[u8]; 4] = [
        &valid[..valid.len() - 1],
        br#"{"op":"unlink","path":"/tmp"}"#,
        br#"{"path":"/tmp"}"#,
        &not_utf8,
    ];
    for body in bodies {
        let declared = u32::try_from(body.len()).unwrap();
        let (result, response) = serve_raw(writable_gate(&granted), &frame(declared, body));
        assert_closed_without_acting(result, &response, &planted);
    }
}

/// End to end against the real binary, including the roadmap acceptance:
/// killing the broker fails all subsequent operations closed.
#[test]
fn broker_binary_serves_and_dies_closed() {
    let (root, granted, outside) = setup();
    let socket = root.path().join("broker.sock");

    let mut broker = std::process::Command::new(env!("CARGO_BIN_EXE_fsgate-broker"))
        .args([
            "--unconfined",
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

/// The real binary under the loosest umask. The command exits when the
/// test closes its standard input.
#[test]
fn a_socket_is_owner_only_whatever_the_umask() {
    let (root, granted, _) = setup();
    let socket = root.path().join("broker.sock");
    let mut broker = Command::new("sh")
        .args(["-c", "umask 000; exec \"$@\"", "sh"])
        .arg(env!("CARGO_BIN_EXE_fsgate-broker"))
        .arg("--unconfined")
        .args(["--grant", &format!("{}:r", granted.display())])
        .args(["--socket", &socket.display().to_string()])
        .args(["--", "sh", "-c", "echo ready; read line; exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn fsgate-broker");

    let mut ready = String::new();
    BufReader::new(broker.stdout.take().expect("piped stdout"))
        .read_line(&mut ready)
        .expect("read the broker command's output");
    assert_eq!(
        ready, "ready\n",
        "broker exited before starting its command"
    );

    let mode = fs::metadata(&socket).unwrap().permissions().mode() & 0o7777;
    let mut client = BrokerGate::connect(&socket).unwrap();
    assert!(client.metadata(granted.join("a.txt")).unwrap().is_file);

    drop(broker.stdin.take());
    broker.wait().expect("reap broker");
    assert_eq!(mode, 0o600, "socket mode was {mode:o}");
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
