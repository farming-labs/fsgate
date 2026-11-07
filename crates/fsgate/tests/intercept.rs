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

mod dispatcher {
    use super::*;

    use fsgate::intercept::{CopyFault, OpenCall, OpenRequest};

    const EACCES: i32 = 13;
    const EFAULT: i32 = 14;
    const O_RDONLY: u32 = 0;

    fn request(notification: u64, path: &[u8]) -> OpenRequest {
        OpenRequest {
            notification,
            call: OpenCall::Openat { flags: O_RDONLY },
            path: Ok(path.to_vec()),
        }
    }

    fn audited(granted: &Path) -> (Gate, Arc<Capture>) {
        let sink = Arc::new(Capture::default());
        let mut gate = gate(granted, Rights::READ);
        gate.set_audit_sink(sink.clone());
        (gate, sink)
    }

    /// Every captured event. The sink is installed after the setup grant,
    /// so these are the dispatcher's decisions only.
    fn decisions(sink: &Capture) -> Vec<AuditEvent> {
        sink.0.lock().unwrap().clone()
    }

    #[test]
    fn a_granted_request_is_delivered_and_audited_once_with_its_syscall() {
        let (_root, granted, _) = setup();
        let (gate, sink) = audited(&granted);
        let path = granted.join("a.txt");

        let file = gate
            .open_intercepted(&request(7, path.to_str().unwrap().as_bytes()))
            .unwrap();

        assert_eq!(read(file), "inside");
        let events = decisions(&sink);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(
            (event.op, event.decision, event.reason),
            (AuditOp::Open, AuditDecision::Allow, AuditReason::Ok)
        );
        assert_eq!(event.path.as_deref(), Some(path.as_path()));
        assert_eq!(
            (event.syscall, event.notification),
            (Some("openat"), Some(7))
        );

        let value: serde_json::Value = serde_json::from_str(&event.to_json_line()).unwrap();
        assert_eq!(value["syscall"], "openat");
        assert_eq!(value["notification"], 7);
    }

    #[test]
    fn a_request_refused_before_grant_selection_is_still_audited() {
        let (_root, granted, _) = setup();
        let (gate, sink) = audited(&granted);

        let err = gate.open_intercepted(&request(8, b"a.txt")).unwrap_err();

        assert_eq!(err.raw_os_error(), Some(EOPNOTSUPP));
        let events = decisions(&sink);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(
            (event.decision, event.reason),
            (AuditDecision::Deny, AuditReason::UnsupportedInput)
        );
        assert_eq!(event.path.as_deref(), Some(Path::new("a.txt")));
        assert_eq!(event.grant, None);
        assert_eq!(event.errno, None);
        assert_eq!(
            (event.syscall, event.notification),
            (Some("openat"), Some(8))
        );
    }

    #[test]
    fn unreadable_arguments_are_invalid_memory_without_a_path() {
        let (_root, granted, _) = setup();
        let (gate, sink) = audited(&granted);
        let mut unreadable = request(9, b"");
        unreadable.path = Err(CopyFault::Unreadable);

        let err = gate.open_intercepted(&unreadable).unwrap_err();

        assert_eq!(err.raw_os_error(), Some(EFAULT));
        let events = decisions(&sink);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, AuditReason::InvalidMemory);
        assert_eq!(events[0].path, None);
    }

    #[test]
    fn policy_and_filesystem_refusals_keep_the_gates_events() {
        let (_root, granted, outside) = setup();
        symlink("a.txt", granted.join("inner")).unwrap();
        let (gate, sink) = audited(&granted);
        let secret = outside.join("secret.txt");
        let inner = granted.join("inner");

        let denied = gate.open_intercepted(&request(10, secret.to_str().unwrap().as_bytes()));
        let looped = gate.open_intercepted(&request(11, inner.to_str().unwrap().as_bytes()));

        assert_eq!(denied.unwrap_err().raw_os_error(), Some(EACCES));
        assert_eq!(looped.unwrap_err().raw_os_error(), Some(ELOOP));
        let events = decisions(&sink);
        assert_eq!(events.len(), 2);
        assert_eq!(
            (events[0].decision, events[0].reason, events[0].notification),
            (AuditDecision::Deny, AuditReason::NoGrant, Some(10))
        );
        assert_eq!(
            (events[1].decision, events[1].errno, events[1].notification),
            (AuditDecision::Allow, Some(ELOOP), Some(11))
        );
        assert!(events.iter().all(|event| event.syscall == Some("openat")));
    }
}
