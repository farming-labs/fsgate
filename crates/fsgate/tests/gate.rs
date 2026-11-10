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
    let sub = granted.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("a.txt"), b"sub").unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ).unwrap();
    let inner = gate.grant(&sub, Rights::READ).unwrap();

    gate.narrow(inner, Rights::from_bits_truncate(0)).unwrap();

    // Unlike `revoke`, the outer grant does not take over the subdirectory.
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

    const OPENS: usize = usize::MAX;
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
        let mut directories = 0_usize;
        while (opens < OPENS || served == 0 || refused == 0) && Instant::now() < deadline {
            opens += 1;
            match gate.open(path) {
                Ok(file) => {
                    assert_eq!(read_to_string(file), "inside", "escaped on open {opens}");
                    served += 1;
                }
                Err(GateError::Io { source, .. }) => {
                    if source.raw_os_error() == Some(rustix::io::Errno::ISDIR.raw_os_error()) {
                        directories += 1;
                    }
                    refused += 1;
                }
                Err(other) => panic!("got {other:?}"),
            }
        }
        assert!(
            served > 0 && refused > 0,
            "the gate saw only one state: {served} served, {refused} refused"
        );
        std::io::Write::write_all(
            &mut std::io::stderr(),
            format!(
                "SWAP-STRESS {path:?}: opens={opens} served={served} refused={refused} directories={directories}\n"
            )
            .as_bytes(),
        )
        .unwrap();
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
