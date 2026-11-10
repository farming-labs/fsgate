//! `Broker::serve` and `ServeOptions`, over real sockets. A test binary of
//! its own, run one test at a time: these tests depend on a hang-up
//! reaching the broker. macOS marks a new socket close-on-exec only after
//! creating it, so a program another test started at that moment could
//! inherit a copy and hold the connection open.

#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use fsgate::{Broker, BrokerGate, Gate, GateError, Rights, ServeOptions};
use tempfile::TempDir;

fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn setup() -> (TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("create temp root");
    // `--socket` refuses a directory that others can write to, and under
    // `umask 000` a new one is.
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let granted = root.path().join("granted");
    let outside = root.path().join("outside");
    fs::create_dir(&granted).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(granted.join("a.txt"), b"inside").unwrap();
    (root, granted, outside)
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

/// Serves `gate` on a new socket at `path`. `serve_with` blocks for the
/// life of the listener, so its thread lasts until the test binary exits.
fn serving(gate: Gate, path: &Path, options: ServeOptions) {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || Broker::new(gate).serve_with(&listener, options));
}

/// Sends `bytes` on a new connection and returns everything the broker
/// answers. The broker may hang up first, which each platform reports
/// differently on the write and the read.
fn raw_answer(socket: &Path, bytes: &[u8]) -> Vec<u8> {
    let hung_up = |err: &std::io::Error| {
        matches!(
            err.kind(),
            ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::NotConnected
        )
    };
    let mut stream = UnixStream::connect(socket).unwrap();
    match stream.write_all(bytes) {
        Ok(()) => {}
        Err(err) if hung_up(&err) => {}
        Err(err) => panic!("writing failed: {err}"),
    }
    let mut answer = Vec::new();
    match stream.read_to_end(&mut answer) {
        Ok(_) => {}
        Err(err) if hung_up(&err) => {}
        Err(err) => panic!("reading failed: {err}"),
    }
    answer
}

fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// CI has one user, so this admits only a uid other than the test's own.
/// That exercises the kernel's real credentials without a second account.
#[test]
fn a_peer_of_another_user_gets_no_answer() {
    let _serial = serial();
    let (root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();
    let socket = root.path().join("broker.sock");
    let options = ServeOptions::default().allow_peer_uids([own_uid().wrapping_add(1)]);
    serving(gate, &socket, options);

    let planted = granted.join("planted.txt");
    let body = create_request(&planted);
    let answer = raw_answer(&socket, &frame(body.len() as u32, &body));
    assert!(answer.is_empty(), "the broker answered a refused peer");
    assert!(!planted.exists(), "the broker served a refused peer");
}

#[test]
fn an_admitted_peer_is_served() {
    let _serial = serial();
    for options in [
        ServeOptions::default(),
        ServeOptions::default().allow_peer_uids([own_uid()]),
        ServeOptions::default().any_peer(),
    ] {
        let (root, granted, _) = setup();
        let mut gate = Gate::new();
        gate.grant(&granted, Rights::READ).unwrap();
        let socket = root.path().join("broker.sock");
        serving(gate, &socket, options.clone());

        let mut client = BrokerGate::connect(&socket).unwrap();
        let stat = client.metadata(granted.join("a.txt"));
        assert!(stat.unwrap().is_file, "not served under {options:?}");
    }
}

#[test]
fn connections_past_the_limit_are_closed_until_one_ends() {
    let _serial = serial();
    let (root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();
    let socket = root.path().join("broker.sock");
    let options = ServeOptions::default().max_connections(NonZeroUsize::MIN);
    serving(gate, &socket, options);
    let file = granted.join("a.txt");

    // An answered request shows the broker has taken this connection.
    let mut first = BrokerGate::connect(&socket).unwrap();
    assert!(first.metadata(&file).unwrap().is_file);

    let body = serde_json::json!({ "op": "metadata", "path": file }).to_string();
    let answer = raw_answer(&socket, &frame(body.len() as u32, body.as_bytes()));
    assert!(answer.is_empty(), "the broker answered past its limit");

    // The slot frees once the broker sees the hang-up, and nothing reports
    // that, so a new connection is retried until the deadline.
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut next = BrokerGate::connect(&socket).unwrap();
        match next.metadata(&file) {
            Ok(stat) => {
                assert!(stat.is_file);
                break;
            }
            Err(GateError::Broker { .. }) if Instant::now() < deadline => thread::yield_now(),
            Err(err) => panic!("the slot was never freed: {err:?}"),
        }
    }
}

/// The peer check is by user, not by program, so another process of the
/// broker's user that finds the socket gets the grants.
#[test]
fn another_process_of_the_admitted_user_gets_the_grants() {
    let _serial = serial();
    let (root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();
    let socket = root.path().join("broker.sock");
    serving(gate, &socket, ServeOptions::default());

    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "stranger_scenario", "--nocapture"])
        .env("FSGATE_STRANGER_SOCKET", &socket)
        .env("FSGATE_STRANGER_FILE", granted.join("a.txt"))
        .output()
        .expect("run another process");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stranger_scenario() {
    let Some(socket) = std::env::var_os("FSGATE_STRANGER_SOCKET") else {
        return;
    };
    let file = std::env::var_os("FSGATE_STRANGER_FILE").unwrap();
    let mut client = BrokerGate::connect(socket).unwrap();
    let mut content = String::new();
    client
        .open(file)
        .unwrap()
        .read_to_string(&mut content)
        .unwrap();
    assert_eq!(content, "inside");
}

/// The real binary under a tight descriptor limit. `accept` fails while
/// the table is full, and the broker must come back once a slot frees
/// rather than stop accepting for good.
#[test]
fn a_full_descriptor_table_does_not_stop_the_broker() {
    let _serial = serial();
    let (root, granted, _) = setup();
    let socket = root.path().join("broker.sock");
    let mut broker = Command::new("sh")
        .args(["-c", "ulimit -n 16; exec \"$@\"", "sh"])
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

    // More connections than the limit allows, so the last ones wait.
    let held: Vec<_> = (0..24)
        .map(|_| UnixStream::connect(&socket).unwrap())
        .collect();
    let probe = held.last().unwrap();
    probe
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let file = granted.join("a.txt");
    let mut waiting = BrokerGate::from_stream(probe.try_clone().unwrap());
    assert!(
        waiting.metadata(&file).is_err(),
        "the descriptor table never filled, so this test proved nothing"
    );
    drop(waiting);
    drop(held);

    // Nothing reports when the broker has freed those, so this retries.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut client = BrokerGate::from_stream(stream);
        match client.metadata(&file) {
            Ok(stat) => {
                assert!(stat.is_file);
                break;
            }
            Err(_) if Instant::now() < deadline => thread::yield_now(),
            Err(err) => panic!("the broker never came back: {err:?}"),
        }
    }

    drop(broker.stdin.take());
    assert_eq!(broker.wait().expect("reap broker").code(), Some(0));
}
