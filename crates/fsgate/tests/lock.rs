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
/// The RFC 0006 restriction tests read the kernel's Landlock ABI from a probe
/// child that uses the `landlock` crate directly, not fsgate. Where the kernel
/// provides a restriction, they prove it is enforced and run a control without
/// it. Where it does not, they prove that requiring it fails before anything is
/// applied and that a bare lock skips it. CI covers both: the runners boot
/// Linux 7.0 (ABI v8) and the `kernels` job boots Linux 6.6 (ABI v4) and
/// Linux 7.3 (ABI v9 or later).
#[cfg(target_os = "linux")]
mod kernel {
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{ErrorKind, Read, Write};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{OnceLock, mpsc};

    use fsgate::{Broker, BrokerGate};
    use rustix::io::Errno;
    use tempfile::TempDir;

    use super::*;

    /// A command that re-executes this test binary to run one child scenario.
    fn child_command(scenario: &str, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &format!("kernel::{scenario}"), "--nocapture"])
            .env("FSGATE_CHILD", scenario)
            .env("FSGATE_MODE", mode);
        command
    }

    /// Runs one child scenario in `mode` and requires it to succeed.
    fn run_child(scenario: &str, mode: &str, envs: &[(&str, &OsStr)]) {
        let status = child_command(scenario, mode)
            .envs(envs.iter().copied())
            .status()
            .expect("spawn locked child");
        assert!(status.success(), "{scenario} ({mode}) failed: {status}");
    }

    /// The mode a child scenario runs in, or `None` outside its child.
    fn child_mode(scenario: &str) -> Option<String> {
        if std::env::var_os("FSGATE_CHILD")? != scenario {
            return None;
        }
        let mode = std::env::var("FSGATE_MODE").expect("FSGATE_MODE");
        // Children run with --nocapture, so CI logs show which branch ran.
        eprintln!("{scenario}: mode {mode}");
        Some(mode)
    }

    /// The running kernel's Landlock ABI, as the `landlock` crate reports it
    /// after restricting a throwaway child. fsgate's own mapping from ABI to
    /// restrictions is not involved, so the tests can check it.
    fn kernel_abi() -> u8 {
        static ABI: OnceLock<u8> = OnceLock::new();
        *ABI.get_or_init(|| {
            let output = child_command("abi_probe_child", "probe")
                .output()
                .expect("spawn the ABI probe");
            assert!(output.status.success(), "ABI probe failed: {output:?}");
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| line.strip_prefix("FSGATE_LANDLOCK_ABI="))
                .expect("the probe prints its ABI")
                .parse()
                .expect("the ABI is a number")
        })
    }

    #[test]
    fn abi_probe_child() {
        use landlock::{ABI, Access, AccessFs, LandlockStatus, Ruleset, RulesetAttr};

        if child_mode("abi_probe_child").is_none() {
            return;
        }
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V1))
            .unwrap()
            .create()
            .unwrap()
            .restrict_self()
            .unwrap();
        let abi = match status.landlock {
            LandlockStatus::Available { effective_abi, .. } => [
                ABI::V1,
                ABI::V2,
                ABI::V3,
                ABI::V4,
                ABI::V5,
                ABI::V6,
                ABI::V7,
                ABI::V8,
                ABI::V9,
            ]
            .into_iter()
            .filter(|known| effective_abi >= *known)
            .count(),
            _ => 0,
        };
        println!("FSGATE_LANDLOCK_ABI={abi}");
    }

    /// The modes to run for a restriction that needs Landlock ABI `needed`:
    /// with and without it where the kernel provides it, `unsupported` where
    /// it does not.
    fn modes(needed: u8) -> Vec<&'static str> {
        if kernel_abi() >= needed {
            vec!["control", "restricted"]
        } else {
            vec!["unsupported"]
        }
    }

    /// A temporary `granted/` and `outside/secret.txt`.
    fn dirs() -> (TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let granted = root.path().join("granted");
        let outside = root.path().join("outside");
        fs::create_dir(&granted).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        (root, granted, outside)
    }

    /// Locks strictly for `mode`:
    /// - `control` leaves `member` out;
    /// - `unsupported` requires `member` on a kernel without it, proves the
    ///   lock fails before anything is applied, then locks without it;
    /// - every other mode requires `member`.
    ///
    /// In every mode the filesystem rules end up enforced.
    fn lock_for(gate: &mut Gate, member: Restrictions, mode: &str) {
        let secret = format!("{}/secret.txt", std::env::var("FSGATE_OUTSIDE").unwrap());
        let status = match mode {
            "control" => {
                gate.lock_with(LockOptions::default().restrict(Restrictions::all() - member))
            }
            "unsupported" => {
                let err = gate
                    .lock_with(LockOptions::default().require(member))
                    .expect_err("a required restriction the kernel lacks");
                assert!(
                    matches!(err, GateError::LockUnsupported { .. }),
                    "got {err:?}"
                );
                let name = format!("`Restrictions::{member:?}`");
                assert!(err.to_string().contains(&name), "{err}");
                // Nothing was applied: the gate is unlocked, and the kernel
                // still allows a raw read outside the grants.
                assert_eq!(gate.restrictions(), None);
                fs::read(&secret).expect("a failed lock applied nothing");
                gate.lock()
            }
            _ => gate.lock_with(LockOptions::default().require(member)),
        };
        assert_eq!(status.expect("strict lock"), LockStatus::FullyEnforced);
        let applied = gate.restrictions().expect("locked");
        assert_eq!(
            applied.contains(member),
            mode != "control" && mode != "unsupported",
            "mode {mode}, applied {applied:?}"
        );
        let err = fs::read(&secret).expect_err("read outside the grants after the lock");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
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
        for mode in modes(6) {
            let (_root, granted, outside) = dirs();
            let name = format!("fsgate-test-{}-{mode}", std::process::id());
            let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
            let listener = UnixListener::bind_addr(&address).unwrap();
            listener.set_nonblocking(true).unwrap();

            run_child(
                "abstract_socket_child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                    ("FSGATE_ABSTRACT", OsStr::new(&name)),
                ],
            );

            let accepted = listener.accept();
            if mode == "restricted" {
                let err = accepted.expect_err("a restricted child reached the listener");
                assert_eq!(err.kind(), ErrorKind::WouldBlock);
            } else {
                assert!(
                    accepted.is_ok(),
                    "{mode} child never connected: {accepted:?}"
                );
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
        if mode == "restricted" {
            let err = result.expect_err("connected outside the domain");
            assert_eq!(
                err.raw_os_error(),
                Some(Errno::PERM.raw_os_error()),
                "{err:?}"
            );
        } else {
            result.expect("connect without the scope");
        }
    }

    #[test]
    fn kernel_restricts_pathname_unix_sockets() {
        for mode in modes(9) {
            let (_root, granted, outside) = dirs();
            let stream = granted.join("stream.sock");
            let datagram = granted.join("datagram.sock");
            let listener = UnixListener::bind(&stream).unwrap();
            listener.set_nonblocking(true).unwrap();
            let receiver = UnixDatagram::bind(&datagram).unwrap();
            receiver.set_nonblocking(true).unwrap();

            run_child(
                "pathname_socket_child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                    ("FSGATE_STREAM", stream.as_os_str()),
                    ("FSGATE_DATAGRAM", datagram.as_os_str()),
                ],
            );

            // The child wrote one byte through the connection it made
            // before locking, whatever the mode.
            let (mut early, _) = listener.accept().expect("the connect before the lock");
            let mut byte = [0; 1];
            early.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"k", "{mode}");

            let later = listener.accept();
            let mut buffer = [0; 8];
            let received = receiver.recv(&mut buffer);
            if mode == "restricted" {
                let err = later.expect_err("a restricted child reached the listener");
                assert_eq!(err.kind(), ErrorKind::WouldBlock);
                let err = received.expect_err("a restricted child sent a datagram");
                assert_eq!(err.kind(), ErrorKind::WouldBlock);
            } else {
                assert!(later.is_ok(), "{mode} child never connected: {later:?}");
                assert_eq!(received.unwrap(), 1, "{mode}");
            }
        }
    }

    #[test]
    fn pathname_socket_child() {
        let Some(mode) = child_mode("pathname_socket_child") else {
            return;
        };
        let stream = std::env::var("FSGATE_STREAM").unwrap();
        let datagram = std::env::var("FSGATE_DATAGRAM").unwrap();
        let mut early = UnixStream::connect(&stream).expect("connect before the lock");

        // The sockets sit beneath this grant, and it holds every right: no
        // right permits a connect.
        let mut gate = Gate::new();
        gate.grant(
            std::env::var("FSGATE_GRANTED").unwrap(),
            Rights::READ | Rights::LIST | Rights::WRITE | Rights::CREATE,
        )
        .unwrap();
        lock_for(&mut gate, Restrictions::RESOLVE_UNIX, &mode);

        early.write_all(b"k").expect("the earlier connection");

        let connected = UnixStream::connect(&stream);
        let sent = UnixDatagram::unbound().unwrap().send_to(b"d", &datagram);
        if mode == "restricted" {
            let refused = [
                connected.expect_err("connected after the lock"),
                sent.expect_err("sent after the lock"),
            ];
            for err in refused {
                assert_eq!(
                    err.raw_os_error(),
                    Some(Errno::ACCESS.raw_os_error()),
                    "{err:?}"
                );
            }
        } else {
            connected.expect("connect without the restriction");
            sent.expect("send without the restriction");
        }
    }

    /// RFC 0006's order for a worker: connect to the broker, then lock.
    #[test]
    fn a_worker_keeps_the_broker_it_connected_to_before_locking() {
        for mode in modes(9) {
            let (_root, granted, outside) = dirs();
            fs::write(granted.join("a.txt"), b"inside").unwrap();
            let socket = granted.join("broker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let mut served = Gate::new();
            served.grant(&granted, Rights::READ).unwrap();
            // One connection is served. A later connect only needs the
            // listener to stay open, which it does until the worker hangs up.
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                Broker::new(served).serve_conn(stream)
            });

            run_child(
                "broker_order_child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                    ("FSGATE_SOCKET", socket.as_os_str()),
                ],
            );

            server.join().unwrap().unwrap();
        }
    }

    #[test]
    fn broker_order_child() {
        let Some(mode) = child_mode("broker_order_child") else {
            return;
        };
        let socket = std::env::var("FSGATE_SOCKET").unwrap();
        let file = format!("{}/a.txt", std::env::var("FSGATE_GRANTED").unwrap());
        let mut client = BrokerGate::connect(&socket).expect("connect before the lock");

        let mut gate = granted_gate();
        lock_for(&mut gate, Restrictions::RESOLVE_UNIX, &mode);

        let mut content = String::new();
        client
            .open(&file)
            .expect("the broker connected before the lock")
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "inside");

        match (mode.as_str(), BrokerGate::connect(&socket)) {
            ("restricted", Ok(_)) => panic!("connected to the broker after the lock"),
            ("restricted", Err(GateError::Broker { message })) => {
                assert!(
                    message.contains("connect before calling `lock`"),
                    "{message}"
                );
            }
            ("restricted", Err(other)) => panic!("got {other:?}"),
            (_, connected) => {
                connected.expect("connect without the restriction");
            }
        }
    }

    #[test]
    fn kernel_scopes_signals() {
        for mode in modes(6) {
            let (_root, granted, outside) = dirs();
            // Spawned by this unlocked process, so outside the child's domain.
            let mut victim = Command::new("sleep").arg("30").spawn().unwrap();
            let pid = victim.id().to_string();

            run_child(
                "signal_child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                    ("FSGATE_VICTIM", OsStr::new(&pid)),
                ],
            );

            if mode == "restricted" {
                let still = victim.try_wait().unwrap();
                victim.kill().unwrap();
                victim.wait().unwrap();
                assert!(
                    still.is_none(),
                    "a restricted child signalled outside its domain"
                );
            } else {
                let exit = victim.wait().unwrap();
                assert_eq!(exit.signal(), Some(rustix::process::Signal::TERM.as_raw()));
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
        if mode == "restricted" {
            assert_eq!(result, Err(Errno::PERM));
        } else {
            result.expect("signal without the scope");
        }
    }

    #[test]
    fn kernel_restricts_device_ioctls() {
        let mut modes = modes(5);
        if modes.contains(&"restricted") {
            modes.push("write");
        }
        for mode in modes {
            let (_root, _granted, outside) = dirs();
            run_child(
                "ioctl_child",
                mode,
                &[("FSGATE_OUTSIDE", outside.as_os_str())],
            );
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
        for mode in modes(8) {
            let (_root, granted, outside) = dirs();
            run_child(
                "thread_child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                ],
            );

            let planted = outside.join(format!("{mode}.txt"));
            assert_eq!(planted.exists(), mode != "restricted", "{planted:?}");
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

        if mode == "restricted" {
            assert_eq!(read.unwrap_err().kind(), ErrorKind::PermissionDenied);
            assert_eq!(write.unwrap_err().kind(), ErrorKind::PermissionDenied);
        } else {
            read.expect("a sibling outside the lock reads outside the grants");
            write.expect("a sibling outside the lock writes outside the grants");
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
