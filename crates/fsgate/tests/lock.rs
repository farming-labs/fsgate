//! Tests for `lock()`: library-level locking on every platform, and the
//! kernel-enforcement proof on Linux.
//!
//! The Linux proof runs in a child process (re-executing this test binary
//! with `FSGATE_LOCK_CHILD=1`) because Landlock restrictions cannot be
//! removed once applied and would poison the rest of the suite.

use fsgate::{Gate, GateError, LockPolicy, LockStatus, Rights};

#[cfg(not(target_os = "linux"))]
#[test]
fn strict_lock_fails_closed_without_kernel_support() {
    let dir = tempfile::tempdir().unwrap();
    let mut gate = Gate::new();
    gate.grant(dir.path(), Rights::READ).unwrap();

    let err = gate.lock().unwrap_err();
    assert!(
        matches!(err, GateError::LockUnsupported { .. }),
        "got {err:?}"
    );
    // A failed lock does not end the granting phase.
    assert!(gate.grant(dir.path(), Rights::READ).is_ok());
}

#[test]
fn best_effort_lock_ends_the_granting_phase() {
    let dir = tempfile::tempdir().unwrap();
    let mut gate = Gate::new();
    gate.grant(dir.path(), Rights::READ).unwrap();

    let status = gate.lock_with(LockPolicy::BestEffort).unwrap();
    #[cfg(not(target_os = "linux"))]
    assert_eq!(status, LockStatus::LibraryOnly);
    #[cfg(target_os = "linux")]
    let _ = status; // level depends on the kernel; the child test pins it

    let err = gate.grant(dir.path(), Rights::READ).unwrap_err();
    assert!(matches!(err, GateError::Locked), "got {err:?}");
    let err = gate.lock_with(LockPolicy::BestEffort).unwrap_err();
    assert!(matches!(err, GateError::Locked), "got {err:?}");
}

#[cfg(target_os = "linux")]
mod kernel {
    use std::fs;
    use std::io::ErrorKind;
    use std::process::Command;

    use super::*;

    /// Parent half: sets up directories, re-executes this binary as a
    /// locked child, and requires it to succeed.
    #[test]
    fn kernel_blocks_filesystem_access_that_bypasses_the_gate() {
        let root = tempfile::tempdir().unwrap();
        let granted = root.path().join("granted");
        let outside = root.path().join("outside");
        fs::create_dir(&granted).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(granted.join("a.txt"), b"inside").unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "kernel::locked_child_scenario", "--nocapture"])
            .env("FSGATE_LOCK_CHILD", "1")
            .env("FSGATE_GRANTED", &granted)
            .env("FSGATE_OUTSIDE", &outside)
            .status()
            .expect("spawn locked child");
        assert!(status.success(), "locked child failed: {status}");
    }

    /// Child half: a no-op unless `FSGATE_LOCK_CHILD` is set.
    #[test]
    fn locked_child_scenario() {
        if std::env::var_os("FSGATE_LOCK_CHILD").is_none() {
            return;
        }
        let granted = std::env::var("FSGATE_GRANTED").unwrap();
        let outside = std::env::var("FSGATE_OUTSIDE").unwrap();

        let mut gate = Gate::new();
        gate.grant(&granted, Rights::READ | Rights::LIST).unwrap();
        let status = gate.lock().expect("strict lock on CI kernel");
        assert_eq!(status, LockStatus::FullyEnforced);

        // Through the gate, the grant still works.
        assert!(gate.open(format!("{granted}/a.txt")).is_ok());

        // Bypassing the gate with std::fs must fail AT THE KERNEL for an
        // ungated path — this is the whole point of lock().
        let err = fs::File::open(format!("{outside}/secret.txt")).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);

        // Writes outside are blocked too, and leave nothing behind.
        let planted = format!("{outside}/planted.txt");
        assert!(fs::write(&planted, b"x").is_err());
        assert!(!std::path::Path::new(&planted).exists());

        // The grant was read-only: even through the kernel rules, writing
        // beneath the granted directory is not allowed.
        assert!(fs::write(format!("{granted}/new.txt"), b"x").is_err());
    }
}
