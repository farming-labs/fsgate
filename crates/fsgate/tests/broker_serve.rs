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

/// Sends `bytes` on a new connection, hangs up its own side, and returns
/// everything the broker answers. A broker that serves the request then
/// sees the hang-up and closes, so a wrong answer fails the test instead of
/// leaving it waiting. The broker may hang up first, which each platform
/// reports differently on the write, the shutdown, and the read.
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
    match stream.shutdown(std::net::Shutdown::Write) {
        Ok(()) => {}
        Err(err) if hung_up(&err) => {}
        Err(err) => panic!("shutdown failed: {err}"),
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

/// Each option keeps the ones set before it: a limit set first still holds
/// after the peers are chosen.
#[test]
fn choosing_peers_keeps_the_connection_limit() {
    let _serial = serial();
    for options in [
        ServeOptions::default()
            .max_connections(NonZeroUsize::MIN)
            .any_peer(),
        ServeOptions::default()
            .max_connections(NonZeroUsize::MIN)
            .allow_peer_uids([own_uid()]),
    ] {
        let (root, granted, _) = setup();
        let mut gate = Gate::new();
        gate.grant(&granted, Rights::READ).unwrap();
        let socket = root.path().join("broker.sock");
        serving(gate, &socket, options.clone());
        let file = granted.join("a.txt");

        let mut first = BrokerGate::connect(&socket).unwrap();
        assert!(first.metadata(&file).unwrap().is_file);
        let body = serde_json::json!({ "op": "metadata", "path": file }).to_string();
        let answer = raw_answer(&socket, &frame(body.len() as u32, body.as_bytes()));
        assert!(answer.is_empty(), "past the limit under {options:?}");
    }
}

/// `serve` returns when its listener fails, rather than retrying. A
/// non-blocking listener with nothing waiting fails with `EAGAIN`, which
/// is not a shortage that can pass.
#[test]
fn serve_returns_when_its_listener_fails() {
    let _serial = serial();
    let (root, granted, _) = setup();
    let socket = root.path().join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let (done, result) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let broker = Broker::new(gate);
        let _ = done.send(broker.serve(&listener));
        let _ = done.send(broker.serve_with(&listener, ServeOptions::default()));
    });
    for _ in 0..2 {
        let served = result
            .recv_timeout(Duration::from_secs(5))
            .expect("serve kept accepting after its listener failed");
        let err = served.expect_err("serve returned without an error");
        assert_eq!(err.kind(), ErrorKind::WouldBlock, "{err}");
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

/// The real binary when it cannot start a thread for a connection. That
/// connection is closed, and the broker keeps accepting. The limit is
/// lowered on the running broker, so only threads it starts afterwards
/// fail.
#[cfg(target_os = "linux")]
#[test]
fn a_connection_without_a_thread_is_closed_and_serving_continues() {
    use rustix::process::{Pid, Resource, Rlimit, getrlimit, prlimit};

    let _serial = serial();
    let (root, granted, _) = setup();
    let socket = root.path().join("broker.sock");
    let mut broker = Command::new(env!("CARGO_BIN_EXE_fsgate-broker"))
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

    let pid = Pid::from_child(&broker);
    let own = getrlimit(Resource::Nproc);
    // This user already runs more than one task, so the broker can start
    // no new one.
    let none_left = Rlimit {
        current: Some(1),
        maximum: own.maximum,
    };
    prlimit(Some(pid), Resource::Nproc, none_left).unwrap();

    let file = granted.join("a.txt");
    let client = || {
        let stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        BrokerGate::from_stream(stream)
    };
    assert!(
        client().metadata(&file).is_err(),
        "the broker started a thread past its limit, so this test proved nothing"
    );

    prlimit(Some(pid), Resource::Nproc, own).unwrap();
    let stat = client()
        .metadata(&file)
        .expect("the broker stopped serving");
    assert!(stat.is_file);

    drop(broker.stdin.take());
    assert_eq!(broker.wait().expect("reap broker").code(), Some(0));
}

/// The real binary when it cannot start the thread that serves its socket:
/// an error and exit 1, with the socket removed.
#[cfg(target_os = "linux")]
#[test]
fn a_broker_that_cannot_start_its_serve_thread_exits_with_an_error() {
    let _serial = serial();
    let (root, granted, _) = setup();
    let socket = root.path().join("broker.sock");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "no_threads_scenario", "--nocapture"])
        .env("FSGATE_NO_THREADS_SOCKET", &socket)
        .env("FSGATE_NO_THREADS_GRANTED", &granted)
        .output()
        .expect("run the scenario");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("thread"), "{stderr}");
    assert!(!socket.exists(), "the broker left its socket behind");
}

/// Starts the broker with no tasks left for this user. `exec` replaces
/// this process without starting one.
#[cfg(target_os = "linux")]
#[test]
fn no_threads_scenario() {
    use std::os::unix::process::CommandExt;

    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let Some(socket) = std::env::var_os("FSGATE_NO_THREADS_SOCKET") else {
        return;
    };
    let granted = std::env::var("FSGATE_NO_THREADS_GRANTED").unwrap();
    let own = getrlimit(Resource::Nproc);
    let none_left = Rlimit {
        current: Some(1),
        maximum: own.maximum,
    };
    setrlimit(Resource::Nproc, none_left).unwrap();
    let err = Command::new(env!("CARGO_BIN_EXE_fsgate-broker"))
        .arg("--unconfined")
        .args(["--grant", &format!("{granted}:r")])
        .arg("--socket")
        .arg(socket)
        .args(["--", "true"])
        .exec();
    panic!("exec failed: {err}");
}
