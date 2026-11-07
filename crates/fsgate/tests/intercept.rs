//! `Gate::open_regular_strict` on the real filesystem: regular files beneath
//! a grant open; symlinks, directories, and special files are refused
//! without being opened for I/O; policy and audit work as for `open`.

#![cfg(all(feature = "experimental-intercept", target_os = "linux"))]

use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fsgate::{AuditDecision, AuditEvent, AuditOp, AuditReason, AuditSink, Gate, GateError, Rights};
use rustix::fs::{FileType, Mode};
use tempfile::TempDir;

const ELOOP: i32 = 40;
const EISDIR: i32 = 21;
const EOPNOTSUPP: i32 = 95;

fn setup() -> (TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let granted = root.path().join("granted");
    let outside = root.path().join("outside");
    fs::create_dir_all(granted.join("sub")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(granted.join("a.txt"), b"inside").unwrap();
    fs::write(granted.join("sub/b.txt"), b"nested").unwrap();
    fs::write(outside.join("secret.txt"), b"secret").unwrap();
    (root, granted, outside)
}

fn gate(granted: &Path, rights: Rights) -> Gate {
    let mut gate = Gate::new();
    gate.grant(granted, rights).unwrap();
    gate
}

fn errno(result: Result<fs::File, GateError>) -> i32 {
    match result {
        Err(GateError::Io { source, .. }) => source.raw_os_error().expect("an OS error"),
        other => panic!("expected an Io error, got {other:?}"),
    }
}

fn read(mut file: fs::File) -> String {
    let mut out = String::new();
    file.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn a_regular_file_beneath_the_grant_opens_read_only() {
    let (_root, granted, _) = setup();
    let gate = gate(&granted, Rights::READ);

    assert_eq!(
        read(gate.open_regular_strict(granted.join("a.txt")).unwrap()),
        "inside"
    );
    assert_eq!(
        read(gate.open_regular_strict(granted.join("sub/b.txt")).unwrap()),
        "nested"
    );
}

#[test]
fn a_symlink_fails_with_eloop_even_inside_the_grant() {
    let (_root, granted, outside) = setup();
    symlink("a.txt", granted.join("inner")).unwrap();
    symlink(outside.join("secret.txt"), granted.join("outer")).unwrap();
    let gate = gate(&granted, Rights::READ);

    assert_eq!(
        errno(gate.open_regular_strict(granted.join("inner"))),
        ELOOP
    );
    assert_eq!(
        errno(gate.open_regular_strict(granted.join("outer"))),
        ELOOP
    );
    // `open` still follows the inner one; only the strict profile refuses it.
    assert_eq!(read(gate.open(granted.join("inner")).unwrap()), "inside");
}

#[test]
fn a_symlinked_directory_on_the_way_fails_with_eloop() {
    let (_root, granted, _) = setup();
    symlink("sub", granted.join("alias")).unwrap();
    let gate = gate(&granted, Rights::READ);

    assert_eq!(
        errno(gate.open_regular_strict(granted.join("alias/b.txt"))),
        ELOOP
    );
}

#[test]
fn a_directory_fails_with_eisdir() {
    let (_root, granted, _) = setup();
    let gate = gate(&granted, Rights::READ | Rights::LIST);

    assert_eq!(errno(gate.open_regular_strict(granted.join("sub"))), EISDIR);
    assert_eq!(errno(gate.open_regular_strict(&granted)), EISDIR);
}

#[test]
fn a_fifo_is_refused_without_blocking() {
    let (_root, granted, _) = setup();
    let fifo = granted.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )
    .unwrap();
    let gate = gate(&granted, Rights::READ);

    // An ordinary read-only open of a FIFO with no writer would block here.
    assert_eq!(errno(gate.open_regular_strict(&fifo)), EOPNOTSUPP);
}

#[test]
fn devices_and_procfs_files_are_refused() {
    let mut gate = Gate::new();
    gate.grant("/dev", Rights::READ).unwrap();
    gate.grant("/proc/self", Rights::READ).unwrap();

    assert_eq!(errno(gate.open_regular_strict("/dev/null")), EOPNOTSUPP);
    // `status` is a regular file, but on procfs.
    assert_eq!(
        errno(gate.open_regular_strict("/proc/self/status")),
        EOPNOTSUPP
    );
}

#[test]
fn policy_still_needs_a_grant_and_the_read_right() {
    let (_root, granted, outside) = setup();
    let gate = gate(&granted, Rights::LIST);

    assert!(matches!(
        gate.open_regular_strict(granted.join("a.txt")),
        Err(GateError::RightsExceeded { .. })
    ));
    assert!(matches!(
        gate.open_regular_strict(outside.join("secret.txt")),
        Err(GateError::NoGrant { .. })
    ));
}

#[derive(Default)]
struct Capture(Mutex<Vec<AuditEvent>>);

impl AuditSink for Capture {
    fn event(&self, event: &AuditEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[test]
fn a_refusal_after_policy_is_audited_as_allow_with_errno() {
    let (_root, granted, _) = setup();
    symlink("a.txt", granted.join("inner")).unwrap();
    let sink = Arc::new(Capture::default());
    let mut gate = gate(&granted, Rights::READ);
    gate.set_audit_sink(sink.clone());

    let _ = gate.open_regular_strict(granted.join("inner"));

    let events = sink.0.lock().unwrap();
    let last = events.last().unwrap();
    assert_eq!(last.op, AuditOp::Open);
    assert_eq!(last.decision, AuditDecision::Allow);
    assert_eq!(last.reason, AuditReason::Ok);
    assert_eq!(last.errno, Some(ELOOP));
    assert_eq!(last.grant, Some(0));
}
