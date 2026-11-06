//! Behavior and denial tests for the M1 handle layer.
//!
//! Denial tests assert both the error and the absence of the side effect,
//! against the real filesystem.

use std::fs;
use std::io::Read;
use std::path::PathBuf;

use fsgate::{Gate, GateError, Rights};
use tempfile::TempDir;

/// Two sibling directories: `granted` (goes into the gate) and `outside`
/// (never granted, holds a secret file escape attempts aim for).
fn setup() -> (TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("create temp root");
    let granted = root.path().join("granted");
    let outside = root.path().join("outside");
    fs::create_dir(&granted).expect("create granted dir");
    fs::create_dir(&outside).expect("create outside dir");
    fs::write(outside.join("secret.txt"), b"secret").expect("write secret");
    (root, granted, outside)
}

fn read_to_string(mut file: fs::File) -> String {
    let mut out = String::new();
    file.read_to_string(&mut out).expect("read file");
    out
}

#[test]
fn open_reads_a_file_beneath_the_grant() {
    let (_root, granted, _) = setup();
    fs::write(granted.join("a.txt"), b"hello").unwrap();

    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let file = gate.open(granted.join("a.txt")).unwrap();
    assert_eq!(read_to_string(file), "hello");
}

#[test]
fn create_writes_a_file_with_create_and_write_rights() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();

    use std::io::Write;
    let mut file = gate.create(granted.join("new.txt")).unwrap();
    file.write_all(b"written").unwrap();
    drop(file);

    assert_eq!(
        fs::read_to_string(granted.join("new.txt")).unwrap(),
        "written"
    );
}

#[test]
fn ungranted_path_is_no_grant() {
    let (_root, granted, outside) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let err = gate.open(outside.join("secret.txt")).unwrap_err();
    assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");
}

#[test]
fn denied_create_leaves_no_file_behind() {
    let (_root, granted, outside) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();

    let target = outside.join("planted.txt");
    let err = gate.create(&target).unwrap_err();
    assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");
    assert!(!target.exists(), "denied create must not create the file");
}

#[test]
fn read_only_grant_rejects_create_and_leaves_no_file() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let target = granted.join("planted.txt");
    let err = gate.create(&target).unwrap_err();
    match err {
        GateError::RightsExceeded { missing, .. } => {
            assert!(missing.contains(Rights::CREATE));
            assert!(missing.contains(Rights::WRITE));
        }
        other => panic!("expected RightsExceeded, got {other:?}"),
    }
    assert!(!target.exists(), "denied create must not create the file");
}

#[test]
fn list_requires_the_list_right() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    let grant = gate.grant(&granted, Rights::READ).unwrap();

    let err = gate.read_dir(&granted).unwrap_err();
    assert!(
        matches!(err, GateError::RightsExceeded { .. }),
        "got {err:?}"
    );

    gate.revoke(grant).unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::LIST).unwrap();
    assert!(gate.read_dir(&granted).is_ok());
}

#[test]
fn dotdot_cannot_reroute_to_an_ungranted_directory() {
    let (_root, granted, outside) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    // Lexically this escapes the grant, so routing must land on NoGrant.
    let sneaky = granted.join("..").join("outside").join("secret.txt");
    let err = gate.open(&sneaky).unwrap_err();
    assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");
    let _ = outside;
}

#[test]
fn dotdot_that_stays_inside_the_grant_works() {
    let (_root, granted, _) = setup();
    fs::create_dir(granted.join("sub")).unwrap();
    fs::write(granted.join("a.txt"), b"inside").unwrap();

    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let path = granted.join("sub").join("..").join("a.txt");
    assert_eq!(read_to_string(gate.open(path).unwrap()), "inside");
}

#[cfg(unix)]
#[test]
fn symlink_to_an_outside_directory_cannot_escape() {
    let (_root, granted, outside) = setup();
    std::os::unix::fs::symlink(&outside, granted.join("link")).unwrap();

    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    // Routing sees a path beneath the grant; the kernel/cap-std must still
    // refuse to follow the symlink out of it.
    let err = gate
        .open(granted.join("link").join("secret.txt"))
        .unwrap_err();
    assert!(matches!(err, GateError::Io { .. }), "got {err:?}");
}

#[cfg(unix)]
#[test]
fn absolute_symlink_target_cannot_escape() {
    let (_root, granted, outside) = setup();
    std::os::unix::fs::symlink(outside.join("secret.txt"), granted.join("abs_link")).unwrap();

    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let err = gate.open(granted.join("abs_link")).unwrap_err();
    assert!(matches!(err, GateError::Io { .. }), "got {err:?}");
}

#[cfg(unix)]
#[test]
fn relative_symlink_staying_inside_the_grant_works() {
    let (_root, granted, _) = setup();
    fs::write(granted.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", granted.join("inner_link")).unwrap();

    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let file = gate.open(granted.join("inner_link")).unwrap();
    assert_eq!(read_to_string(file), "real");
}

#[test]
fn revoked_grant_stops_covering_its_paths() {
    let (_root, granted, _) = setup();
    fs::write(granted.join("a.txt"), b"hello").unwrap();

    let mut gate = Gate::new();
    let grant = gate.grant(&granted, Rights::READ).unwrap();
    assert!(gate.open(granted.join("a.txt")).is_ok());

    gate.revoke(grant).unwrap();
    let err = gate.open(granted.join("a.txt")).unwrap_err();
    assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");

    // Revoking twice is an error, not a silent no-op.
    assert!(matches!(gate.revoke(grant), Err(GateError::UnknownGrant)));
}

#[test]
fn longest_grant_wins_routing() {
    let (_root, granted, _) = setup();
    let sub = granted.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("a.txt"), b"sub").unwrap();

    // Outer grant is read-only; inner grant on the subdirectory can create.
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();
    gate.grant(&sub, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();

    // Inside `sub`, the more specific grant's rights apply.
    assert!(gate.create(sub.join("new.txt")).is_ok());
    // Outside `sub`, only the outer read-only grant applies.
    assert!(matches!(
        gate.create(granted.join("new.txt")),
        Err(GateError::RightsExceeded { .. })
    ));
}

#[test]
fn relative_paths_are_rejected() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let err = gate.open("relative/path.txt").unwrap_err();
    assert!(matches!(err, GateError::NotAbsolute { .. }), "got {err:?}");
}

#[test]
fn grant_root_metadata_works() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    assert!(gate.metadata(&granted).unwrap().is_dir());
}
