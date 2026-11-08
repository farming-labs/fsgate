//! Tests for `lock()`: library-level locking on every platform, and the
//! kernel-enforcement proof on Linux.
//!
//! The Linux proof runs in a child process (re-executing this test binary
//! with `FSGATE_LOCK_CHILD=1`) because Landlock restrictions cannot be
//! removed once applied and would poison the rest of the suite.

use fsgate::{Gate, GateError, LockOptions, LockPolicy, LockStatus, Restrictions, Rights};

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

    // On Linux this lock applies Landlock inside the test process. Leaving
    // out ALL_THREADS confines it to this test's thread.
    let options = LockOptions::new(LockPolicy::BestEffort)
        .restrict(Restrictions::all() - Restrictions::ALL_THREADS);
    let status = gate.lock_with(options).unwrap();
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(status, LockStatus::LibraryOnly);
        assert_eq!(gate.restrictions(), Some(Restrictions::empty()));
    }
    #[cfg(target_os = "linux")]
    {
        let _ = status; // level depends on the kernel; the child tests pin it
        let applied = gate.restrictions().expect("locked");
        assert!(!applied.contains(Restrictions::ALL_THREADS), "{applied:?}");
    }

    let err = gate.grant(dir.path(), Rights::READ).unwrap_err();
    assert!(matches!(err, GateError::Locked), "got {err:?}");
    let err = gate.lock_with(LockPolicy::BestEffort).unwrap_err();
    assert!(matches!(err, GateError::Locked), "got {err:?}");
}

/// A required restriction binds even under `BestEffort`, and a lock that
/// cannot meet it changes nothing (RFC 0006).
#[cfg(not(target_os = "linux"))]
#[test]
fn a_required_restriction_fails_without_kernel_support() {
    let dir = tempfile::tempdir().unwrap();
    let mut gate = Gate::new();
    gate.grant(dir.path(), Rights::READ).unwrap();

    let options = LockOptions::new(LockPolicy::BestEffort).require(Restrictions::SIGNAL);
    let err = gate.lock_with(options).unwrap_err();
    assert!(
        matches!(err, GateError::LockUnsupported { .. }),
        "got {err:?}"
    );
    let message = err.to_string();
    assert!(
        message.contains("`Restrictions::SIGNAL` needs Landlock ABI v6 (Linux 6.12)"),
        "{message}"
    );

    // Nothing changed: the gate is still granting, and a lock without the
    // requirement succeeds.
    assert_eq!(gate.restrictions(), None);
    assert!(gate.grant(dir.path(), Rights::READ).is_ok());
    let status = gate.lock_with(LockPolicy::BestEffort).unwrap();
    assert_eq!(status, LockStatus::LibraryOnly);
    assert_eq!(gate.restrictions(), Some(Restrictions::empty()));
}

/// Linux runs the same check in a locked child (`kernel` below), because a
/// best-effort lock there applies Landlock to the test thread.
#[cfg(not(target_os = "linux"))]
#[test]
fn narrow_is_allowed_after_a_lock() {
    let dir = tempfile::tempdir().unwrap();
    let mut gate = Gate::new();
    let grant = gate
        .grant(dir.path(), Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();
    let status = gate.lock_with(LockPolicy::BestEffort).unwrap();
    assert_eq!(status, LockStatus::LibraryOnly);

    gate.narrow(grant, Rights::READ).unwrap();

    let target = dir.path().join("after.txt");
    let err = gate.create(&target).unwrap_err();
    assert!(
        matches!(err, GateError::RightsExceeded { .. }),
        "got {err:?}"
    );
    assert!(!target.exists());
}

/// Linux kernel enforcement, each proof run in a locked child.
///
/// The RFC 0006 restriction tests require the Landlock ABI each restriction
/// needs (CI boots Linux 7.0). On an older kernel the required lock fails,
/// so those tests fail rather than skip.
#[cfg(target_os = "linux")]
mod kernel {
    use std::ffi::OsStr;
    use std::fs;
    use std::io::ErrorKind;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::sync::mpsc;

    use rustix::io::Errno;

    use super::*;

    /// Re-executes this test binary to run one child scenario in `mode`.
    fn run_child(scenario: &str, mode: &str, envs: &[(&str, &OsStr)]) {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("kernel::{scenario}"), "--nocapture"])
            .env("FSGATE_CHILD", scenario)
            .env("FSGATE_MODE", mode)
            .envs(envs.iter().copied())
            .status()
            .expect("spawn locked child");
        assert!(status.success(), "{scenario} ({mode}) failed: {status}");
    }

    /// The mode a child scenario runs in, or `None` outside its child.
    fn child_mode(scenario: &str) -> Option<String> {
        (std::env::var_os("FSGATE_CHILD")? == scenario)
            .then(|| std::env::var("FSGATE_MODE").expect("FSGATE_MODE"))
    }

    /// Locks strictly. The `control` mode leaves `member` out; every other
    /// mode requires it, so an older kernel fails the test instead of
    /// skipping the restriction.
    fn lock_for(gate: &mut Gate, member: Restrictions, mode: &str) {
        let options = if mode == "control" {
            LockOptions::default().restrict(Restrictions::all() - member)
        } else {
            LockOptions::default().require(member)
        };
        let status = gate.lock_with(options).expect("strict lock on CI kernel");
        assert_eq!(status, LockStatus::FullyEnforced);
        let applied = gate.restrictions().expect("locked");
        assert_eq!(
            applied.contains(member),
            mode != "control",
            "applied {applied:?}"
        );
    }

    /// A gate granting `FSGATE_GRANTED` read access.
    fn granted_gate() -> Gate {
        let mut gate = Gate::new();
        gate.grant(std::env::var("FSGATE_GRANTED").unwrap(), Rights::READ)
            .unwrap();
        gate
    }

    #[test]
    fn kernel_scopes_abstract_unix_sockets() {
        for mode in ["control", "restricted"] {
            let dir = tempfile::tempdir().unwrap();
            let name = format!("fsgate-test-{}-{mode}", std::process::id());
            let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
            let listener = UnixListener::bind_addr(&address).unwrap();
            listener.set_nonblocking(true).unwrap();

            run_child(
                "abstract_socket_child",
                mode,
                &[
                    ("FSGATE_GRANTED", dir.path().as_os_str()),
                    ("FSGATE_ABSTRACT", OsStr::new(&name)),
                ],
            );

            let accepted = listener.accept();
            if mode == "control" {
                assert!(accepted.is_ok(), "control never connected: {accepted:?}");
            } else {
                let err = accepted.expect_err("a restricted child reached the listener");
                assert_eq!(err.kind(), ErrorKind::WouldBlock);
            }
        }
    }

    #[test]
    fn abstract_socket_child() {
        let Some(mode) = child_mode("abstract_socket_child") else {
            return;
        };
        let mut gate = granted_gate();
        lock_for(&mut gate, Restrictions::ABSTRACT_UNIX_SOCKET, &mode);

        let name = std::env::var("FSGATE_ABSTRACT").unwrap();
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let result = UnixStream::connect_addr(&address);
        if mode == "control" {
            result.expect("connect without the scope");
        } else {
            let err = result.expect_err("connected outside the domain");
            assert_eq!(
                err.raw_os_error(),
                Some(Errno::PERM.raw_os_error()),
                "{err:?}"
            );
        }
    }

    #[test]
    fn kernel_scopes_signals() {
        for mode in ["control", "restricted"] {
            let dir = tempfile::tempdir().unwrap();
            // Spawned by this unlocked process, so outside the child's domain.
            let mut victim = Command::new("sleep").arg("30").spawn().unwrap();
            let pid = victim.id().to_string();

            run_child(
                "signal_child",
                mode,
                &[
                    ("FSGATE_GRANTED", dir.path().as_os_str()),
                    ("FSGATE_VICTIM", OsStr::new(&pid)),
                ],
            );

            if mode == "control" {
                let exit = victim.wait().unwrap();
                assert_eq!(exit.signal(), Some(rustix::process::Signal::TERM.as_raw()));
            } else {
                let still = victim.try_wait().unwrap();
                victim.kill().unwrap();
                victim.wait().unwrap();
                assert!(
                    still.is_none(),
                    "a restricted child signalled outside its domain"
                );
            }
        }
    }

    #[test]
    fn signal_child() {
        let Some(mode) = child_mode("signal_child") else {
            return;
        };
        let mut gate = granted_gate();
        lock_for(&mut gate, Restrictions::SIGNAL, &mode);

        let raw: i32 = std::env::var("FSGATE_VICTIM").unwrap().parse().unwrap();
        let pid = rustix::process::Pid::from_raw(raw).expect("nonzero pid");
        let result = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        if mode == "control" {
            result.expect("signal without the scope");
        } else {
            assert_eq!(result, Err(Errno::PERM));
        }
    }

    #[test]
    fn kernel_restricts_device_ioctls() {
        for mode in ["control", "restricted", "write"] {
            run_child("ioctl_child", mode, &[]);
        }
    }

    #[test]
    fn ioctl_child() {
        let Some(mode) = child_mode("ioctl_child") else {
            return;
        };
        let rights = if mode == "write" {
            Rights::READ | Rights::WRITE
        } else {
            Rights::READ
        };
        let mut gate = Gate::new();
        gate.grant("/dev", rights).unwrap();
        lock_for(&mut gate, Restrictions::IOCTL_DEV, &mode);

        // Opened after the lock, beneath the grant. `/dev/null` is no
        // terminal, so an ioctl that reaches the driver fails with ENOTTY.
        let null = fs::File::open("/dev/null").unwrap();
        let result = rustix::termios::tcgetattr(&null);
        let expected = if mode == "restricted" {
            Errno::ACCESS
        } else {
            Errno::NOTTY
        };
        assert_eq!(result.err(), Some(expected), "mode {mode}");
    }

    #[test]
    fn kernel_restricts_threads_that_predate_the_lock() {
        for mode in ["control", "restricted"] {
            let root = tempfile::tempdir().unwrap();
            let granted = root.path().join("granted");
            let outside = root.path().join("outside");
            fs::create_dir(&granted).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("secret.txt"), b"secret").unwrap();

            run_child(
                "thread_child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                ],
            );

            let planted = outside.join(format!("{mode}.txt"));
            assert_eq!(planted.exists(), mode == "control", "{planted:?}");
            assert_eq!(fs::read(outside.join("secret.txt")).unwrap(), b"secret");
        }
    }

    #[test]
    fn thread_child() {
        let Some(mode) = child_mode("thread_child") else {
            return;
        };
        let outside = std::env::var("FSGATE_OUTSIDE").unwrap();
        let planted = format!("{outside}/{mode}.txt");

        // Started before the lock and parked until after it.
        let (go, wait) = mpsc::channel::<()>();
        let sibling = std::thread::spawn(move || {
            wait.recv().unwrap();
            let read = fs::read(format!("{outside}/secret.txt"));
            let write = fs::write(&planted, b"x");
            (read.map(|_| ()), write)
        });

        let mut gate = granted_gate();
        lock_for(&mut gate, Restrictions::ALL_THREADS, &mode);
        go.send(()).unwrap();
        let (read, write) = sibling.join().unwrap();

        if mode == "control" {
            read.expect("an unlocked sibling reads outside the grants");
            write.expect("an unlocked sibling writes outside the grants");
        } else {
            assert_eq!(read.unwrap_err().kind(), ErrorKind::PermissionDenied);
            assert_eq!(write.unwrap_err().kind(), ErrorKind::PermissionDenied);
        }
    }

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

    /// Parent half of the narrowing proof: the child narrows one grant
    /// before the lock and one after, then the parent, which is not locked,
    /// checks that nothing was written.
    #[test]
    fn kernel_enforces_rights_narrowed_before_the_lock() {
        let root = tempfile::tempdir().unwrap();
        let early = root.path().join("early");
        let late = root.path().join("late");
        fs::create_dir(&early).unwrap();
        fs::create_dir(&late).unwrap();
        fs::write(early.join("a.txt"), b"early").unwrap();
        fs::write(late.join("a.txt"), b"late").unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "kernel::narrowed_child_scenario", "--nocapture"])
            .env("FSGATE_NARROW_CHILD", "1")
            .env("FSGATE_EARLY", &early)
            .env("FSGATE_LATE", &late)
            .status()
            .expect("spawn locked child");
        assert!(status.success(), "locked child failed: {status}");

        assert!(!early.join("planted.txt").exists());
        assert_eq!(fs::read(early.join("a.txt")).unwrap(), b"early");
        assert!(late.join("before.txt").exists());
        assert!(!late.join("after.txt").exists());
    }

    /// Child half: a no-op unless `FSGATE_NARROW_CHILD` is set.
    #[test]
    fn narrowed_child_scenario() {
        if std::env::var_os("FSGATE_NARROW_CHILD").is_none() {
            return;
        }
        let early = std::env::var("FSGATE_EARLY").unwrap();
        let late = std::env::var("FSGATE_LATE").unwrap();
        let all = Rights::READ | Rights::WRITE | Rights::CREATE;

        let mut gate = Gate::new();
        let early_grant = gate.grant(&early, all).unwrap();
        gate.narrow(early_grant, Rights::READ).unwrap();
        let late_grant = gate.grant(&late, all).unwrap();
        let status = gate.lock().expect("strict lock on CI kernel");
        assert_eq!(status, LockStatus::FullyEnforced);

        // Narrowed before the lock: the kernel rules carry READ only, so raw
        // writes that bypass the gate fail at the kernel.
        let planted = format!("{early}/planted.txt");
        let err = fs::write(&planted, b"x").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert!(!std::path::Path::new(&planted).exists());
        let err = fs::OpenOptions::new()
            .write(true)
            .open(format!("{early}/a.txt"))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read(format!("{early}/a.txt")).unwrap(), b"early");
        assert!(gate.open(format!("{early}/a.txt")).is_ok());

        // Narrowed after the lock: the gate enforces the narrowed rights.
        assert!(gate.create(format!("{late}/before.txt")).is_ok());
        gate.narrow(late_grant, Rights::READ).unwrap();
        let after = format!("{late}/after.txt");
        let err = gate.create(&after).unwrap_err();
        assert!(
            matches!(err, GateError::RightsExceeded { .. }),
            "got {err:?}"
        );
        assert!(!std::path::Path::new(&after).exists());
        assert!(gate.open(format!("{late}/a.txt")).is_ok());
    }
}
