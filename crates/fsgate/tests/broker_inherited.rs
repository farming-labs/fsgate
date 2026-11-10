//! The connection `fsgate-broker` passes its command. A process can adopt
//! it at most once, so each case re-executes this test binary.

#![cfg(unix)]

use std::env;
use std::fs::{self, File};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::process::{Command, Stdio};

use fsgate::{BrokerGate, GateError};
#[cfg(target_os = "linux")]
use fsgate::{Gate, LockPolicy, Rights};
use rustix::io::FdFlags;
use rustix::net::{AddressFamily, SocketType};

fn in_child(scenario: &str) -> bool {
    env::var_os("FSGATE_CHILD").is_some_and(|child| child == scenario)
}

/// A command that re-executes this test binary to run one child scenario.
fn child_args(command: &mut Command, scenario: &str) {
    command
        .arg(env::current_exe().unwrap())
        .args(["--exact", scenario, "--nocapture"])
        .env("FSGATE_CHILD", scenario);
}

/// Whether a program this process starts would have this descriptor.
fn child_would_inherit(number: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!(": <&{number}"))
        .stderr(Stdio::null())
        .status()
        .expect("run sh")
        .success()
}

/// Runs `scenario` as the command of the real broker, granted `granted/`.
fn run_under_broker(scenario: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let granted = root.path().join("granted");
    let outside = root.path().join("outside");
    fs::create_dir(&granted).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(granted.join("a.txt"), b"inside").unwrap();
    fs::write(outside.join("secret.txt"), b"secret").unwrap();

    // These cases are about the connection. Confinement has its own file.
    let mut command = Command::new(env!("CARGO_BIN_EXE_fsgate-broker"));
    command.args([
        "--unconfined",
        "--grant",
        &format!("{}:r", granted.display()),
        "--",
    ]);
    child_args(&mut command, scenario);
    let output = command
        .env("FSGATE_GRANTED", &granted)
        .env("FSGATE_OUTSIDE", &outside)
        .env_remove("FSGATE_BROKER_SOCKET")
        .current_dir(root.path())
        .output()
        .expect("run fsgate-broker");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("1 passed"),
        "the worker did not run: {stdout}"
    );
    root
}

#[test]
fn a_worker_is_served_over_an_inherited_connection() {
    let root = run_under_broker("worker_scenario");

    // The connection has no name in the filesystem.
    let mut names: Vec<_> = fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["granted", "outside"]);
}

/// From Linux 7.1 a lock refuses new connects to sockets created outside
/// it, and an inherited connection is not a connect.
#[cfg(target_os = "linux")]
#[test]
fn an_inherited_connection_works_after_lock() {
    run_under_broker("locked_worker_scenario");
}

#[cfg(target_os = "linux")]
#[test]
fn locked_worker_scenario() {
    if !in_child("locked_worker_scenario") {
        return;
    }
    let granted = env::var("FSGATE_GRANTED").unwrap();
    let mut own = Gate::new();
    own.grant(&granted, Rights::READ).unwrap();
    own.lock_with(LockPolicy::BestEffort).expect("lock");

    let mut gate = BrokerGate::from_inherited().expect("adopt after the lock");
    assert!(gate.metadata(format!("{granted}/a.txt")).unwrap().is_file);
}

#[test]
fn worker_scenario() {
    if !in_child("worker_scenario") {
        return;
    }
    let number = env::var("FSGATE_BROKER_FD").expect("the broker names the connection");
    assert!(env::var_os("FSGATE_BROKER_SOCKET").is_none());
    assert!(
        child_would_inherit(&number),
        "the connection was not inherited"
    );

    let mut gate = BrokerGate::from_inherited().expect("adopt the connection");
    assert!(
        !child_would_inherit(&number),
        "the connection leaks to children"
    );

    let granted = env::var("FSGATE_GRANTED").unwrap();
    let outside = env::var("FSGATE_OUTSIDE").unwrap();
    assert!(gate.metadata(format!("{granted}/a.txt")).unwrap().is_file);
    let err = gate.open(format!("{outside}/secret.txt")).unwrap_err();
    assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");

    // A descriptor has one owner, and refusing a second does not hurt the first.
    match BrokerGate::from_inherited() {
        Err(GateError::Broker { message }) => assert!(message.contains("already"), "{message}"),
        Err(other) => panic!("expected a broker error, got {other:?}"),
        Ok(_) => panic!("the connection was adopted twice"),
    }
    assert!(gate.metadata(format!("{granted}/a.txt")).unwrap().is_file);
}

fn inheritable(fd: BorrowedFd<'_>) -> String {
    rustix::io::fcntl_setfd(fd, FdFlags::empty()).unwrap();
    fd.as_raw_fd().to_string()
}

fn assert_refused(value: Option<&str>, stays_open: bool, stdin: Stdio) {
    let mut command = Command::new(env::current_exe().unwrap());
    command
        .args(["--exact", "refusal_scenario", "--nocapture"])
        .env("FSGATE_CHILD", "refusal_scenario")
        .env("FSGATE_STAYS_OPEN", if stays_open { "1" } else { "" })
        .env_remove("FSGATE_BROKER_FD")
        .stdin(stdin);
    if let Some(value) = value {
        command.env("FSGATE_BROKER_FD", value);
    }
    let output = command.output().expect("run the child");
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{value:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn from_inherited_refuses_anything_but_an_inherited_connection() {
    assert_refused(None, false, Stdio::null());
    assert_refused(Some("not-a-number"), false, Stdio::null());
    assert_refused(Some("4000"), false, Stdio::null());

    // A real Unix stream socket, so only its number can be why it is refused.
    let (stdin, _peer) = UnixStream::pair().unwrap();
    assert_refused(Some("0"), true, Stdio::from(OwnedFd::from(stdin)));

    let file = File::open(env::current_exe().unwrap()).unwrap();
    assert_refused(Some(&inheritable(file.as_fd())), true, Stdio::null());

    // A stream socket, so only its family can be why it is refused.
    let inet = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).unwrap();
    assert_refused(Some(&inheritable(inet.as_fd())), true, Stdio::null());

    let (datagram, _peer) = UnixDatagram::pair().unwrap();
    assert_refused(Some(&inheritable(datagram.as_fd())), true, Stdio::null());
}

#[test]
fn refusal_scenario() {
    if !in_child("refusal_scenario") {
        return;
    }
    match BrokerGate::from_inherited() {
        Err(GateError::Broker { message }) => {
            assert!(message.contains("fsgate-broker"), "no remedy in: {message}");
        }
        Err(other) => panic!("expected a broker error, got {other:?}"),
        Ok(_) => panic!("adopted something that is not an inherited connection"),
    }
    // A refused descriptor may be someone else's, so it stays open.
    if env::var("FSGATE_STAYS_OPEN").unwrap() == "1" {
        let number = env::var("FSGATE_BROKER_FD").unwrap();
        assert!(fs::metadata(format!("/dev/fd/{number}")).is_ok());
    }
}
