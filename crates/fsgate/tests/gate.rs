//! Behavior and denial tests for the M1 handle layer.
//!
//! Denial tests assert both the error and the absence of the side effect,
//! against the real filesystem.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

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

/// A descriptor for a directory could list it, and `read_dir` is what needs
/// `LIST`. Both the grant's root and a directory beneath it are refused.
#[cfg(unix)]
#[test]
fn open_refuses_a_directory() {
    let (_root, granted, _) = setup();
    fs::create_dir(granted.join("sub")).unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    for path in [granted.join("sub"), granted.clone()] {
        let err = gate.open(&path).unwrap_err();
        let GateError::Io { source, .. } = &err else {
            panic!("got {err:?}");
        };
        assert_eq!(
            source.raw_os_error(),
            Some(rustix::io::Errno::ISDIR.raw_os_error()),
            "got {err:?}"
        );
    }
}

/// A FIFO with no writer would block `open` until one appears, and one with
/// no reader would block `create`, holding the caller, or a broker's serve
/// thread, indefinitely. Neither waits: `open` returns the FIFO, `create`
/// returns it once it has a reader and fails with `ENXIO` before, and the
/// descriptors block as usual afterwards.
#[cfg(unix)]
#[test]
fn a_fifo_does_not_block_open_or_create() {
    use std::io::Write;
    use std::sync::mpsc;
    use std::time::Duration;

    use rustix::fs::OFlags;

    let (_root, granted, _) = setup();
    let fifo = granted.join("fifo");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    assert!(made.unwrap().success(), "mkfifo failed");
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();

    // The timeout turns a regression into a failure instead of a hang.
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = gate.open(&fifo).expect("open the FIFO");
        let mut writer = gate.create(&fifo).expect("create with a reader");
        for file in [&reader, &writer] {
            let flags = rustix::fs::fcntl_getfl(file).unwrap();
            assert!(!flags.contains(OFlags::NONBLOCK), "{flags:?}");
        }
        writer.write_all(b"x").unwrap();
        let mut byte = [0; 1];
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
        drop((reader, writer));

        let err = gate.create(&fifo).unwrap_err();
        let GateError::Io { source, .. } = &err else {
            panic!("got {err:?}");
        };
        assert_eq!(
            source.raw_os_error(),
            Some(rustix::io::Errno::NXIO.raw_os_error()),
            "got {err:?}"
        );
        done.send(()).unwrap();
    });
    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("a FIFO blocked the gate");
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

/// A listing is names and types, read when `read_dir` returns, without `.`
/// and `..`. A symlink is listed as a symlink, not as what it points to.
#[cfg(unix)]
#[test]
fn read_dir_returns_each_entry_name_and_type() {
    let (_root, granted, _) = setup();
    fs::write(granted.join("a.txt"), b"a").unwrap();
    fs::create_dir(granted.join("sub")).unwrap();
    std::os::unix::fs::symlink("sub", granted.join("link")).unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::LIST).unwrap();

    let entries = gate.read_dir(&granted).unwrap();
    fs::remove_file(granted.join("a.txt")).unwrap();

    let mut listed: Vec<_> = entries
        .iter()
        .map(|entry| {
            let kind = entry.file_type();
            let name = entry.file_name().to_str().unwrap().to_owned();
            (name, kind.is_file(), kind.is_dir(), kind.is_symlink())
        })
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        [
            ("a.txt".to_owned(), true, false, false),
            ("link".to_owned(), false, false, true),
            ("sub".to_owned(), false, true, false),
        ]
    );
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
    assert_is_escape(&err);
}

/// An escape is `EXDEV` on every platform: `openat2` returns it on Linux,
/// and the gate gives cap-std's component walk the same errno.
#[cfg(unix)]
fn assert_is_escape(err: &GateError) {
    let GateError::Io { source, .. } = err else {
        panic!("got {err:?}");
    };
    assert_eq!(
        source.raw_os_error(),
        Some(rustix::io::Errno::XDEV.raw_os_error()),
        "got {err:?}"
    );
}

/// Only an escape becomes `EXDEV`. A file the process may not read beneath
/// the grant keeps `EACCES`, so its audit event and a broker's worker see
/// a permission problem, not an escape.
#[cfg(unix)]
#[test]
fn a_permission_denied_open_keeps_its_errno() {
    use std::os::unix::fs::PermissionsExt;

    let (_root, granted, _) = setup();
    let locked = granted.join("locked.txt");
    fs::write(&locked, b"locked").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let err = gate.open(&locked).unwrap_err();
    let GateError::Io { source, .. } = &err else {
        panic!("got {err:?}");
    };
    assert_eq!(
        source.raw_os_error(),
        Some(rustix::io::Errno::ACCESS.raw_os_error()),
        "got {err:?}"
    );
}

#[cfg(unix)]
#[test]
fn absolute_symlink_target_cannot_escape() {
    let (_root, granted, outside) = setup();
    std::os::unix::fs::symlink(outside.join("secret.txt"), granted.join("abs_link")).unwrap();

    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let err = gate.open(granted.join("abs_link")).unwrap_err();
    assert_is_escape(&err);
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

/// Asserts that `err` refuses a grant for `inner_path` holding `inner`
/// within one for `outer_path` holding `outer`.
fn assert_nested(
    err: GateError,
    inner_path: &Path,
    inner: Rights,
    outer_path: &Path,
    outer: Rights,
) {
    match err {
        GateError::NestedGrant {
            inner_path: got_inner_path,
            inner: got_inner,
            outer_path: got_outer_path,
            outer: got_outer,
        } => {
            assert_eq!(
                (got_inner_path.as_path(), got_inner),
                (inner_path, inner),
                "inner grant"
            );
            assert_eq!(
                (got_outer_path.as_path(), got_outer),
                (outer_path, outer),
                "outer grant"
            );
        }
        other => panic!("expected NestedGrant, got {other:?}"),
    }
}

/// The policy "the project read-write, `.git` read-only" cannot be held: a
/// symlink in the project into `.git`, or `.GIT` on a case-insensitive
/// filesystem, routes to the project's grant and lands in `.git` with its
/// rights. So the read-only grant is refused (RFC 0012), and the project's
/// grant still answers for `.git`, as it would through those routes.
#[test]
fn a_nested_grant_with_fewer_rights_is_refused() {
    let (_root, granted, _) = setup();
    let git = granted.join(".git");
    fs::create_dir(&git).unwrap();
    let all = Rights::READ | Rights::WRITE | Rights::CREATE | Rights::LIST;
    let mut gate = Gate::new();
    gate.grant(&granted, all).unwrap();

    let err = gate.grant(&git, Rights::READ).unwrap_err();
    assert_nested(err, &git, Rights::READ, &granted, all);
    // A nested grant lacking only one of the outer grant's rights is refused
    // too.
    let err = gate
        .grant(&git, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap_err();
    assert_nested(
        err,
        &git,
        Rights::READ | Rights::WRITE | Rights::CREATE,
        &granted,
        all,
    );

    // No grant was added: a create in `.git` routes to the outer grant.
    gate.create(git.join("hook")).unwrap();
    assert!(git.join("hook").exists());
}

/// The same pair granted the other way round: the outer grant comes second.
#[test]
fn a_grant_around_a_grant_with_fewer_rights_is_refused() {
    let (_root, granted, _) = setup();
    let sub = granted.join("sub");
    fs::create_dir(&sub).unwrap();
    let mut gate = Gate::new();
    gate.grant(&sub, Rights::READ).unwrap();

    let err = gate
        .grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap_err();
    assert_nested(
        err,
        &sub,
        Rights::READ,
        &granted,
        Rights::READ | Rights::WRITE | Rights::CREATE,
    );

    // No grant covers `granted` itself, and nothing was created in `sub`.
    assert!(matches!(
        gate.create(granted.join("new.txt")),
        Err(GateError::NoGrant { .. })
    ));
    assert!(matches!(
        gate.create(sub.join("new.txt")),
        Err(GateError::RightsExceeded { .. })
    ));
    assert!(!granted.join("new.txt").exists());
    assert!(!sub.join("new.txt").exists());
}

/// Nesting is read from the directories, not their names: a grant named
/// through a symlink to a subdirectory of another grant is nested in it.
#[test]
fn a_nested_grant_named_through_a_symlink_is_refused() {
    let (root, granted, _) = setup();
    let git = granted.join(".git");
    fs::create_dir(&git).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&git, &alias).unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE).unwrap();

    let err = gate.grant(&alias, Rights::READ).unwrap_err();
    assert_nested(
        err,
        &alias,
        Rights::READ,
        &granted,
        Rights::READ | Rights::WRITE,
    );
}

/// On a case-insensitive filesystem, as macOS uses by default, another case
/// names the same directory, and the grant is refused. On a case-sensitive
/// one the name does not exist.
#[test]
fn a_nested_grant_spelled_in_another_case_is_refused_or_missing() {
    let (root, _, _) = setup();
    let project = root.path().join("project");
    fs::create_dir_all(project.join("sub")).unwrap();
    let respelled = root.path().join("PROJECT").join("sub");
    let mut gate = Gate::new();
    gate.grant(&project, Rights::READ | Rights::WRITE).unwrap();

    let err = gate.grant(&respelled, Rights::READ).unwrap_err();
    if fs::metadata(&respelled).is_ok() {
        assert_nested(
            err,
            &respelled,
            Rights::READ,
            &project,
            Rights::READ | Rights::WRITE,
        );
    } else {
        assert!(
            matches!(&err, GateError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound),
            "got {err:?}"
        );
    }
}

/// A second grant on the same directory, under any name, must hold the same
/// rights, since either name reaches every file in it.
#[test]
fn a_second_grant_on_the_same_directory_needs_the_same_rights() {
    let (root, granted, _) = setup();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&granted, &alias).unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    gate.grant(&alias, Rights::READ).unwrap();
    let err = gate
        .grant(&alias, Rights::READ | Rights::WRITE)
        .unwrap_err();
    assert_nested(
        err,
        &granted,
        Rights::READ,
        &alias,
        Rights::READ | Rights::WRITE,
    );
    let err = gate.grant(&granted, Rights::LIST).unwrap_err();
    assert_nested(err, &granted, Rights::LIST, &granted, Rights::READ);
}

/// Revoking the outer grant ends the nesting, so the inner grant can then
/// be made.
#[test]
fn a_nested_grant_with_fewer_rights_is_allowed_once_the_outer_is_revoked() {
    let (_root, granted, _) = setup();
    let sub = granted.join("sub");
    fs::create_dir(&sub).unwrap();
    let mut gate = Gate::new();
    let outer = gate.grant(&granted, Rights::READ | Rights::WRITE).unwrap();
    assert!(gate.grant(&sub, Rights::READ).is_err());

    gate.revoke(outer).unwrap();
    gate.grant(&sub, Rights::READ).unwrap();
}

/// Each grant records where its directory is when it is made, so a
/// directory moved into another grant afterwards is not rechecked: the
/// outer grant's rights reach it by its new path (RFC 0012's limits).
#[test]
fn a_directory_moved_into_another_grant_later_is_not_rechecked() {
    let (root, granted, _) = setup();
    let apart = root.path().join("apart");
    fs::create_dir(&apart).unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();
    gate.grant(&apart, Rights::READ).unwrap();

    fs::rename(&apart, granted.join("moved")).unwrap();

    gate.create(granted.join("moved/new.txt")).unwrap();
    assert!(granted.join("moved/new.txt").exists());
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

#[test]
fn narrow_drops_rights_and_denied_writes_leave_files_unchanged() {
    let (_root, granted, _) = setup();
    fs::write(granted.join("a.txt"), b"hello").unwrap();
    let mut gate = Gate::new();
    let grant = gate
        .grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();
    assert!(gate.create(granted.join("before.txt")).is_ok());

    gate.narrow(grant, Rights::READ).unwrap();

    let target = granted.join("after.txt");
    match gate.create(&target).unwrap_err() {
        GateError::RightsExceeded { missing, .. } => {
            assert!(missing.contains(Rights::CREATE));
            assert!(missing.contains(Rights::WRITE));
        }
        other => panic!("expected RightsExceeded, got {other:?}"),
    }
    assert!(!target.exists(), "denied create must not create the file");

    // `create` truncates an existing file; the denial must leave it intact.
    assert!(gate.create(granted.join("a.txt")).is_err());
    assert_eq!(fs::read(granted.join("a.txt")).unwrap(), b"hello");

    // The kept right still works.
    let file = gate.open(granted.join("a.txt")).unwrap();
    assert_eq!(read_to_string(file), "hello");
}

#[test]
fn narrow_cannot_widen_even_back_to_the_original_rights() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    let all = Rights::READ | Rights::WRITE | Rights::CREATE;
    let grant = gate.grant(&granted, all).unwrap();
    gate.narrow(grant, Rights::READ).unwrap();

    match gate.narrow(grant, all).unwrap_err() {
        GateError::WouldWiden {
            grant_path,
            held,
            extra,
        } => {
            assert_eq!(grant_path, granted);
            assert_eq!(held, Rights::READ);
            assert_eq!(extra, Rights::WRITE | Rights::CREATE);
        }
        other => panic!("expected WouldWiden, got {other:?}"),
    }

    // The refused call left the grant read-only.
    let target = granted.join("planted.txt");
    assert!(matches!(
        gate.create(&target),
        Err(GateError::RightsExceeded { .. })
    ));
    assert!(!target.exists());
}

#[test]
fn narrowing_a_revoked_grant_is_unknown_grant() {
    let (_root, granted, _) = setup();
    let mut gate = Gate::new();
    let grant = gate.grant(&granted, Rights::READ).unwrap();
    gate.revoke(grant).unwrap();

    assert!(matches!(
        gate.narrow(grant, Rights::READ),
        Err(GateError::UnknownGrant)
    ));
}

#[test]
fn narrow_keeps_the_held_directory_instead_of_reopening_the_path() {
    let (root, granted, _) = setup();
    fs::write(granted.join("a.txt"), b"original").unwrap();
    let mut gate = Gate::new();
    let grant = gate.grant(&granted, Rights::READ | Rights::WRITE).unwrap();

    // Swap a different directory in under the granted name.
    fs::rename(&granted, root.path().join("moved")).unwrap();
    fs::create_dir(&granted).unwrap();
    fs::write(granted.join("a.txt"), b"impostor").unwrap();

    gate.narrow(grant, Rights::READ).unwrap();

    // The grant still reaches the directory it opened, not the new one.
    let file = gate.open(granted.join("a.txt")).unwrap();
    assert_eq!(read_to_string(file), "original");
}

#[test]
fn narrowing_to_no_rights_keeps_routing_to_the_grant() {
    let (_root, granted, _) = setup();
    fs::write(granted.join("a.txt"), b"a").unwrap();
    let mut gate = Gate::new();
    let grant = gate.grant(&granted, Rights::READ).unwrap();

    gate.narrow(grant, Rights::from_bits_truncate(0)).unwrap();

    // Unlike `revoke`, the path still has a grant, one without the right.
    assert!(matches!(
        gate.open(granted.join("a.txt")),
        Err(GateError::RightsExceeded { .. })
    ));
}

/// Narrowing a nested grant below the grant around it would leave a right
/// the outer grant gives through other routes (RFC 0012), so it is refused
/// and the grant keeps its rights. Narrowing the outer grant is allowed.
#[test]
fn narrowing_a_nested_grant_below_the_grant_around_it_is_refused() {
    let (_root, granted, _) = setup();
    let sub = granted.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("a.txt"), b"sub").unwrap();
    let mut gate = Gate::new();
    let outer = gate.grant(&granted, Rights::READ).unwrap();
    let inner = gate.grant(&sub, Rights::READ | Rights::LIST).unwrap();

    let err = gate.narrow(inner, Rights::LIST).unwrap_err();
    assert_nested(err, &sub, Rights::LIST, &granted, Rights::READ);
    // The inner grant, which `sub` routes to, still reads.
    let file = gate.open(sub.join("a.txt")).unwrap();
    assert_eq!(read_to_string(file), "sub");

    gate.narrow(outer, Rights::from_bits_truncate(0)).unwrap();
    gate.narrow(inner, Rights::LIST).unwrap();
    assert!(matches!(
        gate.open(sub.join("a.txt")),
        Err(GateError::RightsExceeded { .. })
    ));
}

#[test]
fn revoking_a_grant_from_another_gate_is_unknown_grant_and_changes_neither_gate() {
    let (root, granted, _) = setup();
    let other_dir = root.path().join("other");
    fs::create_dir(&other_dir).unwrap();
    fs::write(granted.join("a.txt"), b"a").unwrap();
    fs::write(other_dir.join("b.txt"), b"b").unwrap();

    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();
    let mut other = Gate::new();
    let foreign = other.grant(&other_dir, Rights::READ).unwrap();

    // Each grant is the first in its own gate, so only the gate tells them
    // apart.
    assert!(matches!(gate.revoke(foreign), Err(GateError::UnknownGrant)));

    let file = gate.open(granted.join("a.txt")).unwrap();
    assert_eq!(read_to_string(file), "a");
    let file = other.open(other_dir.join("b.txt")).unwrap();
    assert_eq!(read_to_string(file), "b");
}

#[test]
fn narrowing_a_grant_from_another_gate_is_unknown_grant_and_keeps_both_rights() {
    let (root, granted, _) = setup();
    let other_dir = root.path().join("other");
    fs::create_dir(&other_dir).unwrap();
    let all = Rights::READ | Rights::WRITE | Rights::CREATE;

    let mut gate = Gate::new();
    gate.grant(&granted, all).unwrap();
    let mut other = Gate::new();
    let foreign = other.grant(&other_dir, all).unwrap();

    assert!(matches!(
        gate.narrow(foreign, Rights::READ),
        Err(GateError::UnknownGrant)
    ));

    // Neither grant lost the rights to create a file.
    gate.create(granted.join("a.txt")).unwrap();
    other.create(other_dir.join("b.txt")).unwrap();
    assert!(granted.join("a.txt").exists());
    assert!(other_dir.join("b.txt").exists());
}

/// `/proc/self/fd/N` names whatever the process has open, wherever it is.
/// The ordinary open shows this one reaches the secret.
#[cfg(target_os = "linux")]
#[test]
fn a_magic_link_beneath_a_grant_is_refused() {
    use std::os::fd::AsRawFd;

    let (_root, _granted, outside) = setup();
    let held = fs::File::open(outside.join("secret.txt")).unwrap();
    let link = format!("/proc/self/fd/{}", held.as_raw_fd());
    assert_eq!(fs::read_to_string(&link).unwrap(), "secret");

    let mut gate = Gate::new();
    gate.grant("/proc/self/fd", Rights::READ).unwrap();

    let err = gate.open(&link).unwrap_err();
    let GateError::Io { source, .. } = &err else {
        panic!("got {err:?}");
    };
    assert_eq!(
        source.raw_os_error(),
        Some(rustix::io::Errno::LOOP.raw_os_error()),
        "got {err:?}"
    );
}

/// Resolution follows the directory tree, and a hard link is an ordinary
/// entry in it, so the grant reaches the file. The threat model lists this
/// as a gap.
#[cfg(unix)]
#[test]
fn a_hard_link_beneath_a_grant_reaches_the_file_elsewhere() {
    let (_root, granted, outside) = setup();
    fs::hard_link(outside.join("secret.txt"), granted.join("link.txt")).unwrap();

    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let file = gate.open(granted.join("link.txt")).unwrap();
    assert_eq!(read_to_string(file), "secret");
}

/// Stops the swapping thread even when an assertion unwinds, because
/// `thread::scope` would otherwise wait for it forever.
#[cfg(unix)]
struct StopOnDrop<'a>(&'a std::sync::atomic::AtomicBool);

#[cfg(unix)]
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Opens `path` through the gate while another thread replaces `link`, by an
/// atomic rename, with a symlink to `inside` and then to `outside`.
///
/// This can show an escape, not rule one out. Two things keep it honest:
/// ordinary opens must see both the file inside and the secret, so the swap
/// really happens and really reaches outside, and the gate must both serve
/// and refuse, so it opened through both states.
#[cfg(unix)]
fn assert_swap_never_escapes(
    gate: &Gate,
    path: &std::path::Path,
    link: &std::path::Path,
    inside: &std::path::Path,
    outside: &std::path::Path,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    const OPENS: usize = 20_000;
    let deadline = Instant::now() + Duration::from_secs(60);
    let stop = AtomicBool::new(false);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            let next = link.with_extension("next");
            let mut targets = [inside, outside].into_iter().cycle();
            while !stop.load(Ordering::Relaxed) {
                std::os::unix::fs::symlink(targets.next().unwrap(), &next).unwrap();
                fs::rename(&next, link).unwrap();
            }
        });
        let _stop = StopOnDrop(&stop);

        let (mut saw_inside, mut saw_secret) = (false, false);
        while !(saw_inside && saw_secret) && Instant::now() < deadline {
            match fs::read_to_string(path).as_deref() {
                Ok("inside") => saw_inside = true,
                Ok("secret") => saw_secret = true,
                _ => {}
            }
        }
        assert!(saw_inside && saw_secret, "the swap was never observed");

        let (mut served, mut refused, mut opens) = (0_usize, 0_usize, 0_usize);
        while (opens < OPENS || served == 0 || refused == 0) && Instant::now() < deadline {
            opens += 1;
            match gate.open(path) {
                Ok(file) => {
                    assert_eq!(read_to_string(file), "inside", "escaped on open {opens}");
                    served += 1;
                }
                Err(GateError::Io { .. }) => refused += 1,
                Err(other) => panic!("got {other:?}"),
            }
        }
        assert!(
            served > 0 && refused > 0,
            "the gate saw only one state: {served} served, {refused} refused"
        );
    });
}

/// A symlink swapped in during resolution, as the last component and as a
/// directory on the way, with an absolute and a relative target.
#[cfg(unix)]
#[test]
fn a_symlink_swapped_during_resolution_never_reaches_outside() {
    use std::path::Path;

    let (_root, granted, outside) = setup();
    fs::create_dir(granted.join("real")).unwrap();
    fs::write(granted.join("real/secret.txt"), b"inside").unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();

    let directory = granted.join("directory");
    std::os::unix::fs::symlink("real", &directory).unwrap();
    assert_swap_never_escapes(
        &gate,
        &directory.join("secret.txt"),
        &directory,
        Path::new("real"),
        &outside,
    );

    let last = granted.join("last");
    std::os::unix::fs::symlink("real/secret.txt", &last).unwrap();
    assert_swap_never_escapes(
        &gate,
        &last,
        &last,
        Path::new("real/secret.txt"),
        Path::new("../outside/secret.txt"),
    );
}

/// A union of rights holds each right once, and the error messages name
/// rights through `Debug`.
#[test]
fn rights_combine_and_print_as_a_set() {
    let read_list = Rights::READ | Rights::LIST;
    assert_eq!(read_list | Rights::READ, read_list);
    assert_eq!(Rights::WRITE | Rights::WRITE, Rights::WRITE);

    assert_eq!(format!("{read_list:?}"), "READ | LIST");
    assert_eq!(
        format!("{:?}", Rights::from_bits_truncate(0b1111)),
        "READ | WRITE | CREATE | LIST"
    );
    assert_eq!(format!("{:?}", Rights::from_bits_truncate(0)), "(none)");
}

/// On macOS `/dev/fd/N` is a devfs entry, not a symlink: opening it
/// duplicates the process's own descriptor `N`, with that descriptor's file
/// and access mode. A grant covering `/dev` must not hand out a descriptor
/// the process holds for a file outside every grant, or one open for more
/// than the gate asked for.
#[cfg(target_os = "macos")]
#[test]
fn dev_fd_beneath_a_grant_does_not_hand_out_a_held_descriptor() {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let outside = tempfile::tempdir().unwrap();
    let path = outside.path().join("state.txt");
    fs::write(&path, b"untouched").unwrap();
    let read_write = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let read_only = fs::File::open(&path).unwrap();

    let mut gate = Gate::new();
    gate.grant("/dev", Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();

    for held in [read_write.as_raw_fd(), read_only.as_raw_fd()] {
        let node = format!("/dev/fd/{held}");
        // Before the fix, this returned a descriptor for the file outside,
        // writable when the held one was.
        if let Ok(mut file) = gate.open(&node) {
            let _ = file.write_all(b"OVERWRIT");
            panic!("open handed out descriptor {held}");
        }
        assert_is_escape(&gate.open(&node).unwrap_err());
    }
    assert_is_escape(
        &gate
            .create(format!("/dev/fd/{}", read_write.as_raw_fd()))
            .unwrap_err(),
    );
    // The kernel itself refuses to open a read-only descriptor for writing.
    let GateError::Io { source, .. } = gate
        .create(format!("/dev/fd/{}", read_only.as_raw_fd()))
        .unwrap_err()
    else {
        panic!("expected an I/O error");
    };
    assert_eq!(
        source.raw_os_error(),
        Some(rustix::io::Errno::ACCESS.raw_os_error())
    );
    assert_eq!(fs::read(&path).unwrap(), b"untouched");

    // The control: a device opened by its own name still works.
    gate.open("/dev/null").unwrap();
    gate.create("/dev/null").unwrap();
}

/// A path that ends in `/` or `/.` names a directory, as the kernel reads
/// it. The gate keeps that ending through its lexical normalization, so
/// each call fails as `std::fs` does on the same path, and `create` makes
/// no file.
#[test]
fn a_trailing_slash_names_a_directory() {
    let (_root, granted, _) = setup();
    fs::write(granted.join("file"), b"untouched").unwrap();
    fs::create_dir(granted.join("dir")).unwrap();
    let mut gate = Gate::new();
    gate.grant(
        &granted,
        Rights::READ | Rights::WRITE | Rights::CREATE | Rights::LIST,
    )
    .unwrap();
    let errno = |result: Result<(), GateError>| match result {
        Err(GateError::Io { source, .. }) => source.raw_os_error(),
        other => panic!("got {other:?}"),
    };
    let std_create = |path: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map(drop)
            .unwrap_err()
            .raw_os_error()
    };
    let slashed = |name: &str, tail: &str| {
        let mut path = granted.join(name).into_os_string();
        path.push(tail);
        PathBuf::from(path)
    };

    for tail in ["/", "/."] {
        let file = slashed("file", tail);
        let shown = file.display();
        let opened = fs::File::open(&file).map(drop).unwrap_err().raw_os_error();
        assert!(opened.is_some(), "std opened {shown}");
        assert_eq!(errno(gate.open(&file).map(drop)), opened, "open {shown}");
        assert_eq!(
            errno(gate.metadata(&file).map(drop)),
            fs::metadata(&file).unwrap_err().raw_os_error(),
            "metadata {shown}"
        );
        let new = slashed("new", tail);
        for path in [&file, &new] {
            let created = errno(gate.create(path).map(drop));
            let expected = std_create(path);
            eprintln!("create {}: {created:?}, std {expected:?}", path.display());
            // Linux's `openat2` fails as `open` does. On macOS cap-std
            // resolves the path itself and fails a create whose path ends
            // in `/` with `EINVAL`.
            if cfg!(target_os = "linux") || tail == "/." {
                assert_eq!(created, expected, "create {}", path.display());
            } else {
                assert!(created.is_some(), "create {}", path.display());
            }
        }
        assert!(
            !granted.join("new").exists(),
            "create {} made a file",
            new.display()
        );
    }
    assert_eq!(fs::read(granted.join("file")).unwrap(), b"untouched");

    // A directory named with a slash still lists, and the file without one
    // still opens.
    assert!(gate.read_dir(slashed("dir", "/")).unwrap().is_empty());
    assert_eq!(
        read_to_string(gate.open(granted.join("file")).unwrap()),
        "untouched"
    );
}
