//! Tests for `lock()`: library-level locking on every platform, and the
//! kernel-enforcement proof on Linux.
//!
//! The Linux proof runs in a child process (re-executing this test binary
//! with `FSGATE_LOCK_CHILD=1`) because Landlock restrictions cannot be
//! removed once applied and would poison the rest of the suite.

use fsgate::{Gate, GateError, LockOptions, LockPolicy, LockStatus, Restrictions, Rights};

// Lock inspection requires stable threads and descriptors. Run the few
// formerly in-process lock tests apart from parallel test fixture I/O.
#[cfg(target_os = "linux")]
fn run_isolated(name: &str) -> bool {
    if std::env::var("FSGATE_ISOLATED_LOCK").as_deref() == Ok(name) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--include-ignored", "--nocapture"])
        .env("FSGATE_ISOLATED_LOCK", name)
        .output()
        .expect("run the isolated lock test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

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
    #[cfg(target_os = "linux")]
    if run_isolated("best_effort_lock_ends_the_granting_phase") {
        return;
    }
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

/// `restrict` and `require` take sets built with these operators, and a
/// set prints as its members.
#[test]
fn restrictions_combine_and_print_as_a_set() {
    let signal = Restrictions::SIGNAL;
    let devices_and_signal = Restrictions::IOCTL_DEV | signal;
    assert_eq!(devices_and_signal | signal, devices_and_signal);
    assert_eq!(
        Restrictions::all() - signal,
        Restrictions::IOCTL_DEV
            | Restrictions::ABSTRACT_UNIX_SOCKET
            | Restrictions::ALL_THREADS
            | Restrictions::RESOLVE_UNIX
    );
    assert_eq!(signal - Restrictions::all(), Restrictions::empty());
    assert_eq!(devices_and_signal & signal, signal);

    assert!(Restrictions::empty().is_empty());
    assert!(!signal.is_empty());
    assert!(devices_and_signal.contains(signal));
    assert!(!signal.contains(devices_and_signal));

    assert_eq!(format!("{devices_and_signal:?}"), "IOCTL_DEV | SIGNAL");
    assert_eq!(format!("{:?}", Restrictions::empty()), "(none)");
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

/// A Linux kernel without Landlock. CI's `kernels` job boots its kernels a
/// second time with `lsm=capability` and runs these with `--ignored`; on a
/// kernel with Landlock they fail, because the lock works there. None needs
/// a child, because without Landlock no lock restricts the test process.
#[cfg(target_os = "linux")]
mod without_landlock {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;

    /// A gate granting `granted/` read access, and a file outside the grant.
    fn granted_gate() -> (TempDir, Gate, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let granted = root.path().join("granted");
        fs::create_dir(&granted).unwrap();
        let secret = root.path().join("secret.txt");
        fs::write(&secret, b"secret").unwrap();
        let mut gate = Gate::new();
        gate.grant(&granted, Rights::READ).unwrap();
        (root, gate, secret)
    }

    #[test]
    #[ignore = "needs a kernel booted without Landlock; CI's kernels job runs it"]
    fn strict_lock_fails_closed() {
        if run_isolated("without_landlock::strict_lock_fails_closed") {
            return;
        }
        let (root, mut gate, _secret) = granted_gate();

        let err = gate.lock().unwrap_err();

        assert!(
            matches!(err, GateError::LockUnsupported { .. }),
            "got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("does not fully enforce Landlock ABI v3"),
            "{err}"
        );
        // A failed lock does not end the granting phase.
        assert_eq!(gate.restrictions(), None);
        gate.grant(root.path(), Rights::READ)
            .expect("the gate is still granting");
    }

    #[test]
    #[ignore = "needs a kernel booted without Landlock; CI's kernels job runs it"]
    fn best_effort_lock_reports_library_only() {
        if run_isolated("without_landlock::best_effort_lock_reports_library_only") {
            return;
        }
        let (root, mut gate, secret) = granted_gate();

        let status = gate.lock_with(LockPolicy::BestEffort).unwrap();

        assert_eq!(status, LockStatus::LibraryOnly);
        assert_eq!(gate.restrictions(), Some(Restrictions::empty()));
        let err = gate.grant(root.path(), Rights::READ).unwrap_err();
        assert!(matches!(err, GateError::Locked), "got {err:?}");
        // The gate still refuses, and the status is honest about the rest:
        // the kernel enforces nothing, so a raw read outside the grant works.
        let err = gate.open(&secret).unwrap_err();
        assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");
        assert_eq!(fs::read(&secret).unwrap(), b"secret");
    }

    #[test]
    #[ignore = "needs a kernel booted without Landlock; CI's kernels job runs it"]
    fn a_required_restriction_fails_even_under_best_effort() {
        if run_isolated("without_landlock::a_required_restriction_fails_even_under_best_effort") {
            return;
        }
        let (_root, mut gate, _secret) = granted_gate();

        let options = LockOptions::new(LockPolicy::BestEffort).require(Restrictions::SIGNAL);
        let err = gate.lock_with(options).unwrap_err();

        assert!(
            matches!(err, GateError::LockUnsupported { .. }),
            "got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("`Restrictions::SIGNAL` needs Landlock ABI v6 (Linux 6.12)"),
            "{err}"
        );
        // Nothing changed, so a lock without the requirement still succeeds.
        assert_eq!(gate.restrictions(), None);
        assert_eq!(
            gate.lock_with(LockPolicy::BestEffort).unwrap(),
            LockStatus::LibraryOnly
        );
    }
}

/// Linux kernel enforcement, each proof run in a locked child.
///
/// The RFC 0006 restriction tests read the kernel's Landlock ABI from a probe
/// child that uses the `landlock` crate directly, not fsgate. Where the kernel
/// provides a restriction, they prove it is enforced and run a control without
/// it. Where it does not, they prove that requiring it fails before anything is
/// applied and that a bare lock skips it. CI covers both: the runners boot
/// Linux 7.0 (ABI v8) and the `kernels` job boots Linux 6.6 (ABI v4), 6.12
/// (ABI v6), and 7.3 (ABI v9 or later).
#[cfg(target_os = "linux")]
mod kernel {
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{ErrorKind, Read, Write};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::{OnceLock, mpsc};

    use fsgate::{Broker, BrokerGate};
    use rustix::event::{PollFd, PollFlags};
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

    /// Runs the unlocked observer `scenario` in `mode`, started with
    /// `signal` blocked in every thread, so a signal the kernel sends it
    /// stays pending until the observer looks.
    fn run_observer(
        scenario: &str,
        mode: &str,
        signal: i32,
        granted: &std::path::Path,
        outside: &std::path::Path,
    ) {
        let mut command = child_command(scenario, mode);
        command
            .env("FSGATE_GRANTED", granted)
            .env("FSGATE_OUTSIDE", outside);
        raw_signals::block_in_child(&mut command, signal);
        let status = command.status().expect("spawn the observer");
        assert!(status.success(), "{scenario} ({mode}) failed: {status}");
    }

    /// The kernel sends `SIGCHLD` when a process exits, and the signal scope
    /// does not stop it (RFC 0006): the parent of a locked process still
    /// learns that it exited. The same child fails to signal that parent
    /// itself, so the scope was on.
    #[test]
    fn a_locked_process_still_signals_its_exit_to_its_parent() {
        for mode in modes(6) {
            let (_root, granted, outside) = dirs();
            run_observer(
                "exit_signal_observer",
                mode,
                libc::SIGCHLD,
                &granted,
                &outside,
            );
        }
    }

    #[test]
    fn exit_signal_observer() {
        let Some(mode) = child_mode("exit_signal_observer") else {
            return;
        };
        // This process is not locked, so it is outside the child's domain.
        let mut child = child_command("exit_signal_child", &mode)
            .spawn()
            .expect("spawn the locked child");
        let pid = i32::try_from(child.id()).unwrap();
        let status = child.wait().unwrap();
        assert!(
            status.success(),
            "exit_signal_child ({mode}) failed: {status}"
        );
        // The kernel queues `SIGCHLD` before the wait returns.
        assert_eq!(
            raw_signals::take(libc::SIGCHLD),
            Some(pid),
            "mode {mode}: no exit signal from the locked child"
        );
    }

    #[test]
    fn exit_signal_child() {
        let Some(mode) = child_mode("exit_signal_child") else {
            return;
        };
        let mut gate = granted_gate();
        lock_for(&mut gate, Restrictions::SIGNAL, &mode);

        // Signal 0 checks the permission and sends nothing.
        let parent = rustix::process::getppid().expect("a parent");
        let probe = rustix::process::test_kill_process(parent);
        if mode == "restricted" {
            assert_eq!(probe, Err(Errno::PERM));
        } else {
            probe.expect("may signal the parent without the scope");
        }
    }

    /// The signal scope covers `SIGIO` that a locked process asks for with
    /// `F_SETOWN` (RFC 0006): when its socket becomes readable, the kernel
    /// does not signal an owner outside its domain. Setting that owner is
    /// not refused. Without the scope, the same owner gets the signal.
    #[test]
    fn kernel_scopes_io_signals_a_locked_process_asks_for() {
        for mode in modes(6) {
            let (_root, granted, outside) = dirs();
            run_observer("io_signal_observer", mode, libc::SIGIO, &granted, &outside);
        }
    }

    /// Runs the locked `child` in `mode`, naming this process in
    /// `FSGATE_OWNER` for the child to make the owner of a socket, and
    /// requires `signal` to have arrived unless the scope is on. The kernel
    /// sends it during the child's system call, before the child exits.
    fn observe_owner_signal(child: &str, mode: &str, signal: i32) {
        // This process is not locked, so it is outside the child's domain.
        let status = child_command(child, mode)
            .env("FSGATE_OWNER", std::process::id().to_string())
            .status()
            .expect("spawn the locked child");
        assert!(status.success(), "{child} ({mode}) failed: {status}");
        let arrived = raw_signals::take(signal).is_some();
        assert_eq!(
            arrived,
            mode != "restricted",
            "mode {mode}: signal {signal} arrived: {arrived}"
        );
    }

    #[test]
    fn io_signal_observer() {
        let Some(mode) = child_mode("io_signal_observer") else {
            return;
        };
        observe_owner_signal("io_signal_child", &mode, libc::SIGIO);
    }

    #[test]
    fn io_signal_child() {
        let Some(mode) = child_mode("io_signal_child") else {
            return;
        };
        let mut gate = granted_gate();
        lock_for(&mut gate, Restrictions::SIGNAL, &mode);

        let owner: i32 = std::env::var("FSGATE_OWNER").unwrap().parse().unwrap();
        let (mut writer, reader) = UnixStream::pair().unwrap();
        raw_signals::signal_owner_on_input(&reader, owner).expect("F_SETOWN and O_ASYNC");
        writer.write_all(b"x").unwrap();
    }

    /// The signal scope also covers `SIGURG`, which the kernel sends the
    /// `F_SETOWN` owner of a socket when out-of-band data arrives on it,
    /// with or without `O_ASYNC` (RFC 0006). Without the scope, the same
    /// owner gets it.
    #[test]
    fn kernel_scopes_urgent_signals_a_locked_process_asks_for() {
        for mode in modes(6) {
            let (_root, granted, outside) = dirs();
            run_observer(
                "urgent_signal_observer",
                mode,
                libc::SIGURG,
                &granted,
                &outside,
            );
        }
    }

    #[test]
    fn urgent_signal_observer() {
        let Some(mode) = child_mode("urgent_signal_observer") else {
            return;
        };
        observe_owner_signal("urgent_signal_child", &mode, libc::SIGURG);
    }

    #[test]
    fn urgent_signal_child() {
        let Some(mode) = child_mode("urgent_signal_child") else {
            return;
        };
        let mut gate = granted_gate();
        lock_for(&mut gate, Restrictions::SIGNAL, &mode);

        let owner: i32 = std::env::var("FSGATE_OWNER").unwrap().parse().unwrap();
        let (writer, reader) = UnixStream::pair().unwrap();
        raw_signals::set_owner(&reader, owner).expect("F_SETOWN");
        let sent = rustix::net::send(&writer, b"x", rustix::net::SendFlags::OOB)
            .expect("send out-of-band data on a Unix stream socket");
        assert_eq!(sent, 1);
    }

    /// A process started before the lock is outside the locked process's
    /// domain, so when the locked process exits, the signal scope stops
    /// the death signal that process asked for with `PR_SET_PDEATHSIG`
    /// (RFC 0006). Without the scope, it arrives.
    #[test]
    fn kernel_scopes_the_death_signal_of_a_process_started_before_the_lock() {
        let mut modes = modes(6);
        // Before Linux 7.0 the lock covers only the thread that calls it,
        // and the kernel sends the death signal again as each thread of
        // the exiting process ends, so the result would depend on which
        // thread ends last. From 7.0 the lock covers every thread.
        if kernel_abi() < 8 {
            modes.retain(|mode| *mode != "restricted");
        }
        for mode in modes {
            let (_root, granted, outside) = dirs();
            // The observer inherits the parent's standard output, so this
            // reads to its end only once both have exited. Standard error
            // passes through, so CI logs show which mode each child ran.
            let output = child_command("death_signal_parent", mode)
                .env("FSGATE_GRANTED", &granted)
                .env("FSGATE_OUTSIDE", &outside)
                .stderr(Stdio::inherit())
                .output()
                .expect("spawn the locked parent");
            assert!(
                output.status.success(),
                "death_signal_parent ({mode}) failed: {output:?}"
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            let arrived: bool = stdout
                .lines()
                .find_map(|line| line.strip_prefix("FSGATE_DEATH_SIGNAL="))
                .unwrap_or_else(|| panic!("mode {mode}: no report from the observer: {output:?}"))
                .parse()
                .expect("the observer reports true or false");
            assert_eq!(
                arrived,
                mode != "restricted",
                "mode {mode}: the death signal arrived: {arrived}"
            );
        }
    }

    // Never waits for the observer on purpose: it must outlive this process.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn death_signal_parent() {
        let Some(mode) = child_mode("death_signal_parent") else {
            return;
        };
        let mut gate = granted_gate();

        // The observer gets a pidfd for this process as its standard input.
        let this = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .expect("pidfd_open");
        let mut observer = child_command("death_signal_observer", &mode);
        observer.stdin(Stdio::from(this));
        raw_signals::block_in_child(&mut observer, libc::SIGUSR1);
        raw_signals::death_signal_in_child(&mut observer, rustix::process::Signal::USR1);
        // Started before the lock, so outside this process's domain.
        let _observer = observer.spawn().expect("spawn the observer");

        lock_for(&mut gate, Restrictions::SIGNAL, &mode);
        if mode == "restricted" {
            let applied = gate.restrictions().expect("locked");
            assert!(applied.contains(Restrictions::ALL_THREADS), "{applied:?}");
        }
    }

    #[test]
    fn death_signal_observer() {
        if child_mode("death_signal_observer").is_none() {
            return;
        }
        // The pidfd becomes readable once every thread of the parent has
        // ended, after the kernel has sent or refused each death signal.
        let parent = std::io::stdin();
        let mut fds = [PollFd::new(&parent, PollFlags::IN)];
        rustix::event::poll(&mut fds, None).expect("poll the parent's pidfd");
        assert!(fds[0].revents().contains(PollFlags::IN));
        let arrived = raw_signals::take(libc::SIGUSR1).is_some();
        println!("FSGATE_DEATH_SIGNAL={arrived}");
    }

    /// Signal masks, pending signals, and `F_SETOWN`, which neither std nor
    /// this crate's `rustix` features wrap, and the death signal, which a
    /// child sets between fork and exec.
    ///
    /// Safety contract: each call passes only values initialized before it,
    /// or a descriptor borrowed for the call, and the code that runs between
    /// fork and exec makes only async-signal-safe calls.
    #[allow(unsafe_code)]
    mod raw_signals {
        use std::io;
        use std::mem::MaybeUninit;
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        /// A set that holds only `signal`.
        fn only(signal: i32) -> libc::sigset_t {
            let mut set = MaybeUninit::<libc::sigset_t>::uninit();
            // SAFETY: `sigemptyset` initializes the set, and `sigaddset`
            // then adds a valid signal number to it.
            unsafe {
                libc::sigemptyset(set.as_mut_ptr());
                libc::sigaddset(set.as_mut_ptr(), signal);
                set.assume_init()
            }
        }

        /// Starts `command` with `signal` blocked. A process keeps its mask
        /// across exec, and a thread starts with the mask of the thread that
        /// starts it, so no thread of the child acts on the signal.
        pub(super) fn block_in_child(command: &mut Command, signal: i32) {
            let set = only(signal);
            // SAFETY: the closure runs in the child between fork and exec.
            // It calls only `pthread_sigmask`, which is async-signal-safe,
            // with a set built before the fork, and allocates nothing.
            unsafe {
                command.pre_exec(move || {
                    match libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) {
                        0 => Ok(()),
                        err => Err(io::Error::from_raw_os_error(err)),
                    }
                });
            }
        }

        /// Starts `command` with `signal` as its death signal: the kernel
        /// sends it when the thread that starts the child ends. The child
        /// keeps the setting across exec.
        pub(super) fn death_signal_in_child(
            command: &mut Command,
            signal: rustix::process::Signal,
        ) {
            // SAFETY: the closure runs in the child between fork and exec.
            // It makes one `prctl` system call, which is async-signal-safe,
            // and allocates nothing.
            unsafe {
                command.pre_exec(move || {
                    rustix::process::set_parent_process_death_signal(Some(signal))
                        .map_err(io::Error::from)
                });
            }
        }

        /// Takes `signal` if it is pending for this thread or its process,
        /// and returns the sender's process ID, which is 0 for the kernel.
        /// The signal must be blocked. Returns `None` at once if it is not
        /// pending.
        pub(super) fn take(signal: i32) -> Option<i32> {
            let set = only(signal);
            let mut info = MaybeUninit::<libc::siginfo_t>::uninit();
            let now = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `set` and `now` are initialized and outlive the call,
            // and `info` has room for the `siginfo_t` the kernel writes.
            let got = unsafe { libc::sigtimedwait(&set, info.as_mut_ptr(), &now) };
            if got == -1 {
                let err = io::Error::last_os_error();
                assert_eq!(err.raw_os_error(), Some(libc::EAGAIN), "{err}");
                return None;
            }
            assert_eq!(got, signal);
            // SAFETY: `sigtimedwait` returned the signal, so the kernel
            // filled `info`.
            Some(unsafe { info.assume_init().si_pid() })
        }

        /// Makes the process `owner` the one the kernel signals for
        /// `socket`: `F_SETOWN`.
        pub(super) fn set_owner(socket: &impl AsRawFd, owner: i32) -> io::Result<()> {
            // SAFETY: the descriptor stays open while `socket` is borrowed,
            // and `F_SETOWN` takes a process ID.
            if unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETOWN, owner) } == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Makes the kernel send `SIGIO` to the process `owner` when
        /// `socket` becomes readable: `F_SETOWN`, then `O_ASYNC`.
        pub(super) fn signal_owner_on_input(socket: &impl AsRawFd, owner: i32) -> io::Result<()> {
            set_owner(socket, owner)?;
            let fd = socket.as_raw_fd();
            // SAFETY: `fd` stays open while `socket` is borrowed, and
            // `F_GETFL` takes no argument.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags == -1 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: as above, and `F_SETFL` takes the status flags.
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_ASYNC) } == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
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

    // The tests below show the gaps the threat model lists for a locked
    // process. Each one proves the lock is on, then that the gap is there.

    /// Runs one scenario in a locked child against `dirs()`.
    fn run_locked(scenario: &str, granted: &std::path::Path, outside: &std::path::Path) {
        run_child(
            scenario,
            "locked",
            &[
                ("FSGATE_GRANTED", granted.as_os_str()),
                ("FSGATE_OUTSIDE", outside.as_os_str()),
            ],
        );
    }

    /// Strictly locks `gate`, and proves a raw read of the secret is refused.
    /// Returns the granted directory and the secret's path.
    fn lock_and_prove(gate: &mut Gate) -> (String, String) {
        assert_eq!(gate.lock().expect("strict lock"), LockStatus::FullyEnforced);
        let secret = format!("{}/secret.txt", std::env::var("FSGATE_OUTSIDE").unwrap());
        let err = fs::read(&secret).expect_err("read outside the grants after the lock");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        (std::env::var("FSGATE_GRANTED").unwrap(), secret)
    }

    /// `lock()` requests every restriction and requires none, so it applies
    /// each one this kernel has and skips the rest. The tests above require
    /// the restriction they check, which applies it whatever is requested.
    #[test]
    fn a_bare_lock_applies_every_restriction_the_kernel_has() {
        let (_root, granted, outside) = dirs();
        run_locked("bare_lock_child", &granted, &outside);
    }

    #[test]
    fn bare_lock_child() {
        if child_mode("bare_lock_child").is_none() {
            return;
        }
        // The probe runs a program, so it goes before the lock. Each needed
        // ABI is the one `Restrictions` documents.
        let abi = kernel_abi();
        let expected = [
            (Restrictions::IOCTL_DEV, 5),
            (Restrictions::ABSTRACT_UNIX_SOCKET, 6),
            (Restrictions::SIGNAL, 6),
            (Restrictions::ALL_THREADS, 8),
            (Restrictions::RESOLVE_UNIX, 9),
        ]
        .into_iter()
        .filter(|(_, needed)| abi >= *needed)
        .fold(Restrictions::empty(), |set, (member, _)| set | member);
        let mut gate = granted_gate();

        lock_and_prove(&mut gate);
        assert_eq!(gate.restrictions(), Some(expected), "ABI v{abi}");
    }

    /// A grant with no rights, made that way or narrowed to nothing before
    /// the lock, must not stop the lock, and must reach nothing after it.
    #[test]
    fn a_grant_with_no_rights_locks_and_reaches_nothing() {
        let (_root, granted, outside) = dirs();
        fs::write(granted.join("a.txt"), b"inside").unwrap();

        run_locked("no_rights_child", &granted, &outside);
    }

    #[test]
    fn no_rights_child() {
        if child_mode("no_rights_child").is_none() {
            return;
        }
        let outside = std::env::var("FSGATE_OUTSIDE").unwrap();
        let none = Rights::READ.missing_from(Rights::READ);
        let mut gate = Gate::new();
        gate.grant(std::env::var("FSGATE_GRANTED").unwrap(), Rights::READ)
            .unwrap();
        // Narrowed first: a second grant on the same directory must hold the
        // same rights (RFC 0012).
        let narrowed = gate.grant(&outside, Rights::READ).unwrap();
        gate.narrow(narrowed, none).unwrap();
        gate.grant(&outside, Rights::from_bits_truncate(0)).unwrap();

        // The raw read of the secret beneath the empty grants is refused.
        let (granted, secret) = lock_and_prove(&mut gate);

        let err = gate.open(&secret).unwrap_err();
        assert!(
            matches!(err, GateError::RightsExceeded { .. }),
            "got {err:?}"
        );
        assert_eq!(fs::read(format!("{granted}/a.txt")).unwrap(), b"inside");
    }

    /// A hard link is an ordinary entry in the directory tree, which is what
    /// Landlock checks, so one made before the lock stays reachable. A locked
    /// process cannot make a new one to a file outside its rules.
    #[test]
    fn a_locked_process_keeps_hard_links_but_cannot_make_them() {
        let (_root, granted, outside) = dirs();
        fs::hard_link(outside.join("secret.txt"), granted.join("before.txt")).unwrap();

        run_locked("hard_link_child", &granted, &outside);

        assert!(!granted.join("after.txt").exists(), "a link was made");
    }

    #[test]
    fn hard_link_child() {
        if child_mode("hard_link_child").is_none() {
            return;
        }
        let mut gate = Gate::new();
        gate.grant(
            std::env::var("FSGATE_GRANTED").unwrap(),
            Rights::READ | Rights::WRITE | Rights::CREATE,
        )
        .unwrap();
        let (granted, secret) = lock_and_prove(&mut gate);

        assert_eq!(
            fs::read(format!("{granted}/before.txt")).unwrap(),
            b"secret"
        );

        let err = fs::hard_link(&secret, format!("{granted}/after.txt")).unwrap_err();
        let refused = [Errno::ACCESS, Errno::XDEV].map(Errno::raw_os_error);
        assert!(
            refused.contains(&err.raw_os_error().expect("an errno")),
            "got {err:?}"
        );
    }

    /// Landlock checks a path when it is opened, so a descriptor from before
    /// the lock keeps the access it was opened with.
    #[test]
    fn a_descriptor_opened_before_the_lock_keeps_its_access() {
        let (_root, granted, outside) = dirs();
        run_locked("early_descriptor_child", &granted, &outside);
    }

    #[test]
    fn early_descriptor_child() {
        if child_mode("early_descriptor_child").is_none() {
            return;
        }
        let secret = format!("{}/secret.txt", std::env::var("FSGATE_OUTSIDE").unwrap());
        let mut held = fs::File::open(&secret).unwrap();

        let mut gate = granted_gate();
        lock_and_prove(&mut gate);

        let mut content = String::new();
        held.read_to_string(&mut content).unwrap();
        assert_eq!(content, "secret");
    }

    /// A descriptor can also arrive after the lock, over `SCM_RIGHTS` from a
    /// process the lock does not cover. Here that is an unconfined broker
    /// the locked process connected to first.
    #[test]
    fn a_descriptor_received_after_the_lock_keeps_its_access() {
        let (_root, granted, outside) = dirs();
        let socket = granted.join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut served = Gate::new();
        served.grant(&outside, Rights::READ).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            Broker::new(served).serve_conn(stream)
        });

        run_child(
            "received_descriptor_child",
            "locked",
            &[
                ("FSGATE_GRANTED", granted.as_os_str()),
                ("FSGATE_OUTSIDE", outside.as_os_str()),
                ("FSGATE_SOCKET", socket.as_os_str()),
            ],
        );

        server.join().unwrap().unwrap();
    }

    #[test]
    fn received_descriptor_child() {
        if child_mode("received_descriptor_child").is_none() {
            return;
        }
        let socket = std::env::var("FSGATE_SOCKET").unwrap();
        let mut client = BrokerGate::connect(&socket).expect("connect before the lock");

        let mut gate = granted_gate();
        let (_, secret) = lock_and_prove(&mut gate);

        let mut content = String::new();
        client
            .open(&secret)
            .expect("the broker grants this path")
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "secret");
    }

    /// Landlock checks the credentials a file is opened with. `io_uring`
    /// opens a file with the submitter's credentials, unless the request
    /// names a personality, a set of credentials registered earlier, or
    /// the ring has an `SQPOLL` thread, which submits with the credentials
    /// of whoever set the ring up. A personality or `SQPOLL` ring from
    /// before the lock therefore opens files outside the grants after it.
    /// An open submitted with the locked process's own credentials is
    /// refused.
    #[test]
    fn an_io_uring_ring_set_up_before_the_lock_keeps_its_credentials() {
        let (_root, granted, outside) = dirs();
        run_locked("io_uring_child", &granted, &outside);
    }

    #[test]
    fn io_uring_child() {
        if child_mode("io_uring_child").is_none() {
            return;
        }
        let ring = match raw_uring::Ring::new(false) {
            Ok(ring) => ring,
            // `kernel.io_uring_disabled` refuses every ring, so there is no
            // ring to keep.
            Err(Errno::PERM) => {
                eprintln!("io_uring_child: io_uring is disabled here");
                return;
            }
            Err(err) => panic!("io_uring_setup: {err}"),
        };
        let personality = ring.register_personality().expect("a personality");
        let polled = raw_uring::Ring::new(true).expect("an SQPOLL ring");

        let mut gate = granted_gate();
        gate.lock_with(LockOptions::default().allow_existing_io_uring(true))
            .unwrap();
        let secret = format!("{}/secret.txt", std::env::var("FSGATE_OUTSIDE").unwrap());
        assert_eq!(
            fs::read(&secret).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        let secret = std::ffi::CString::new(secret).unwrap();

        assert_eq!(
            ring.open(&secret, None).map(drop),
            Err(Errno::ACCESS),
            "an open with the locked process's own credentials"
        );
        let through = [
            ("the personality", ring.open(&secret, Some(personality))),
            ("the SQPOLL thread", polled.open(&secret, None)),
        ];
        for (route, opened) in through {
            let opened = opened.unwrap_or_else(|err| panic!("open through {route}: {err}"));
            let mut content = String::new();
            fs::File::from(opened).read_to_string(&mut content).unwrap();
            assert_eq!(content, "secret", "read through {route}");
        }
        eprintln!("io_uring_child: opened the secret through both routes");
    }

    #[derive(Default)]
    struct RingAudit(std::sync::Mutex<Vec<fsgate::AuditEvent>>);

    impl fsgate::AuditSink for RingAudit {
        fn event(&self, event: &fsgate::AuditEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn visible_io_uring_resources_are_refused_before_locking() {
        for mode in ["plain", "personality", "sqpoll", "registered-sqpoll"] {
            let (_root, granted, outside) = dirs();
            run_child(
                "io_uring_refusal_child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                ],
            );
        }
    }

    #[test]
    fn io_uring_refusal_child() {
        let Some(mode) = child_mode("io_uring_refusal_child") else {
            return;
        };
        let sqpoll = mode.ends_with("sqpoll");
        let ring = raw_uring::Ring::new(sqpoll).expect("io_uring enabled for this test");
        if mode == "personality" {
            ring.register_personality().unwrap();
        }
        let secret = format!("{}/secret.txt", std::env::var("FSGATE_OUTSIDE").unwrap());
        let ring = if mode == "registered-sqpoll" {
            // Completion proves that the polling thread has started and
            // named itself before its descriptor disappears.
            drop(
                ring.open(&std::ffi::CString::new(secret.clone()).unwrap(), None)
                    .unwrap(),
            );
            ring.register_and_close().unwrap();
            None
        } else {
            Some(ring)
        };
        for policy in [LockPolicy::Strict, LockPolicy::BestEffort] {
            let mut gate = granted_gate();
            let audit = std::sync::Arc::new(RingAudit::default());
            gate.set_audit_sink(audit.clone());
            let err = gate
                .lock_with(policy)
                .expect_err("a visible ring must prevent locking");
            assert!(matches!(err, GateError::IoUringPresent { .. }), "{err:?}");
            assert!(err.to_string().contains("allow_existing_io_uring(true)"));
            assert_eq!(gate.restrictions(), None);
            assert_eq!(fs::read(&secret).unwrap(), b"secret");
            {
                let events = audit.0.lock().unwrap();
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].op, fsgate::AuditOp::Lock);
                assert_eq!(events[0].decision, fsgate::AuditDecision::Deny);
                assert_eq!(events[0].reason, fsgate::AuditReason::IoUring);
                assert!(events[0].status.is_none());
                assert!(events[0].restrictions.is_none());
            }
            gate.grant(std::env::var("FSGATE_GRANTED").unwrap(), Rights::READ)
                .expect("a refused check leaves the gate granting");
        }
        drop(ring);
        if !sqpoll {
            let mut gate = granted_gate();
            lock_and_prove(&mut gate);
        }
        eprintln!("io_uring_refusal_child: checked {mode}");
    }

    #[test]
    fn rings_created_after_locking_use_confined_credentials() {
        let (_root, granted, outside) = dirs();
        fs::write(granted.join("inside.txt"), b"inside").unwrap();
        run_locked("io_uring_after_lock_child", &granted, &outside);
    }

    #[test]
    fn io_uring_after_lock_child() {
        if child_mode("io_uring_after_lock_child").is_none() {
            return;
        }
        let mut gate = granted_gate();
        let (_, secret) = lock_and_prove(&mut gate);
        let secret = std::ffi::CString::new(secret).unwrap();
        let allowed = std::ffi::CString::new(format!(
            "{}/inside.txt",
            std::env::var("FSGATE_GRANTED").unwrap()
        ))
        .unwrap();
        // The parent creates the allowed control before confinement.
        for sqpoll in [false, true] {
            let ring = raw_uring::Ring::new(sqpoll).unwrap();
            let personality = ring.register_personality().unwrap();
            for identity in [None, Some(personality)] {
                assert_eq!(ring.open(&secret, identity).map(drop), Err(Errno::ACCESS));
                let file = ring
                    .open(&allowed, identity)
                    .expect("open inside the grant");
                let mut content = String::new();
                fs::File::from(file).read_to_string(&mut content).unwrap();
                assert_eq!(content, "inside");
            }
        }
    }

    #[test]
    fn unreadable_procfs_refuses_locking_without_partial_containment() {
        for mode in ["strict", "best-effort"] {
            let (_root, granted, outside) = dirs();
            run_child(
                "io_uring_inspection_child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                ],
            );
        }
    }

    #[test]
    fn io_uring_inspection_child() {
        let Some(mode) = child_mode("io_uring_inspection_child") else {
            return;
        };
        let granted = PathBuf::from(std::env::var("FSGATE_GRANTED").unwrap());
        let secret = PathBuf::from(std::env::var("FSGATE_OUTSIDE").unwrap()).join("secret.txt");
        let mut outer = Gate::new();
        outer
            .grant(granted.parent().unwrap(), Rights::READ | Rights::LIST)
            .unwrap();
        outer.lock().unwrap();
        assert_eq!(fs::read(&secret).unwrap(), b"secret");

        let mut gate = granted_gate();
        let audit = std::sync::Arc::new(RingAudit::default());
        gate.set_audit_sink(audit.clone());
        let policy = if mode == "strict" {
            LockPolicy::Strict
        } else {
            LockPolicy::BestEffort
        };
        let err = gate.lock_with(policy).unwrap_err();
        assert!(
            matches!(&err, GateError::IoUringInspection { source, .. }
            if source.kind() == ErrorKind::PermissionDenied),
            "{err:?}"
        );
        assert_eq!(gate.restrictions(), None);
        assert_eq!(fs::read(&secret).unwrap(), b"secret");
        {
            let events = audit.0.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].decision, fsgate::AuditDecision::Deny);
            assert_eq!(events[0].reason, fsgate::AuditReason::IoUring);
            assert_eq!(events[0].errno, Some(libc::EACCES));
            assert!(events[0].status.is_none());
        }
        gate.grant(&granted, Rights::READ).unwrap();
        gate.lock_with(LockOptions::new(policy).allow_existing_io_uring(true))
            .unwrap();
        assert_eq!(
            fs::read(&secret).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
    }

    /// A one-entry `io_uring` ring that opens files, which neither std nor
    /// `rustix` wraps safely.
    ///
    /// Safety contract:
    /// - Each mapping is a new shared mapping of the ring at the offset and
    ///   length the kernel reported in `io_uring_params`, and lives as long
    ///   as the `Ring`. Every pointer into it is checked to lie inside it.
    /// - Only this thread writes the submission tail and the completion
    ///   head. Each is stored with release ordering after the entry it
    ///   publishes or consumes, and the kernel's completion tail is loaded
    ///   with acquire ordering, as the `io_uring` ABI requires.
    /// - A submission names a path that outlives the `io_uring_enter` call
    ///   that waits for its completion, so the kernel never reads it after
    ///   it is freed.
    /// - A descriptor is taken from a completion only when the kernel
    ///   returned one, and only once.
    /// - Registering a ring uses an initialized, writable update. The
    ///   child thread owns that reference until kernel cleanup on exit;
    ///   no requests are pending when the descriptor and mappings close.
    #[allow(unsafe_code)]
    mod raw_uring {
        use std::ffi::{CStr, c_void};
        use std::mem::size_of;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::ptr;
        use std::sync::atomic::{AtomicU32, Ordering};

        use rustix::fs::OFlags;
        use rustix::io::Errno;
        use rustix::io_uring::{
            IORING_OFF_CQ_RING, IORING_OFF_SQ_RING, IORING_OFF_SQES, IoringEnterFlags, IoringOp,
            IoringRegisterOp, IoringSetupFlags, addr_or_splice_off_in_union, io_uring_cqe,
            io_uring_enter, io_uring_params, io_uring_ptr, io_uring_register, io_uring_setup,
            io_uring_sqe, op_flags_union,
        };
        use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};

        /// One shared mapping of a ring.
        struct Map {
            ptr: *mut c_void,
            len: usize,
        }

        impl Map {
            fn new(ring: &OwnedFd, offset: u64, len: usize) -> Result<Map, Errno> {
                // SAFETY: a new mapping at an address the kernel picks, so no
                // existing memory changes.
                let ptr = unsafe {
                    mmap(
                        ptr::null_mut(),
                        len,
                        ProtFlags::READ | ProtFlags::WRITE,
                        MapFlags::SHARED | MapFlags::POPULATE,
                        ring,
                        offset,
                    )?
                };
                Ok(Map { ptr, len })
            }

            /// A pointer to a `T` at `offset` bytes into the mapping.
            fn at<T>(&self, offset: usize) -> *mut T {
                assert!(offset + size_of::<T>() <= self.len, "outside the mapping");
                // SAFETY: inside the mapping, as checked above.
                unsafe { self.ptr.byte_add(offset).cast() }
            }

            /// The ring's `u32` at `offset`, shared with the kernel.
            fn atomic(&self, offset: u32) -> &AtomicU32 {
                let field = self.at::<u32>(offset as usize);
                assert!(field.is_aligned(), "a misaligned ring field");
                // SAFETY: an aligned `u32` inside the mapping, which outlives
                // the borrow of `self`, and which the kernel accesses
                // atomically.
                unsafe { AtomicU32::from_ptr(field) }
            }
        }

        impl Drop for Map {
            fn drop(&mut self) {
                // SAFETY: unmaps only this mapping, and no pointer into it
                // outlives the `Ring` that owns it.
                let _ = unsafe { munmap(self.ptr, self.len) };
            }
        }

        pub(super) struct Ring {
            fd: OwnedFd,
            params: io_uring_params,
            sq: Map,
            cq: Map,
            sqes: Map,
        }

        impl Ring {
            /// Sets up a ring, with an `SQPOLL` thread if `sqpoll`.
            pub(super) fn new(sqpoll: bool) -> Result<Ring, Errno> {
                let mut params = io_uring_params::default();
                if sqpoll {
                    params.flags = IoringSetupFlags::SQPOLL;
                }
                // SAFETY: `params` is initialized, and the kernel writes only
                // into it.
                let fd = unsafe { io_uring_setup(1, &mut params)? };
                let sq_len =
                    params.sq_off.array as usize + params.sq_entries as usize * size_of::<u32>();
                let cq_len = params.cq_off.cqes as usize
                    + params.cq_entries as usize * size_of::<io_uring_cqe>();
                let sqes_len = params.sq_entries as usize * size_of::<io_uring_sqe>();
                let sq = Map::new(&fd, IORING_OFF_SQ_RING, sq_len)?;
                let cq = Map::new(&fd, IORING_OFF_CQ_RING, cq_len)?;
                let sqes = Map::new(&fd, IORING_OFF_SQES, sqes_len)?;
                Ok(Ring {
                    fd,
                    params,
                    sq,
                    cq,
                    sqes,
                })
            }

            /// Registers the calling thread's credentials as a personality.
            pub(super) fn register_personality(&self) -> Result<u16, Errno> {
                // SAFETY: this opcode takes no argument.
                let id = unsafe {
                    io_uring_register(
                        &self.fd,
                        IoringRegisterOp::RegisterPersonality,
                        ptr::null(),
                        0,
                    )?
                };
                Ok(u16::try_from(id).expect("a personality ID fits in a u16"))
            }

            /// The child thread owns the registration until it exits; the
            /// kernel then releases it. No requests are pending when the
            /// descriptor and mappings are dropped.
            pub(super) fn register_and_close(self) -> Result<(), Errno> {
                let mut update = rustix::io_uring::io_uring_rsrc_update::default();
                update.offset = u32::MAX;
                update.data = io_uring_ptr::new(self.fd.as_raw_fd() as usize as *mut c_void);
                // SAFETY: this opcode interprets data as a live descriptor
                // number, not a pointer. The initialized update remains
                // writable until registration returns. The child thread
                // owns the registered reference through its exit.
                let count = unsafe {
                    io_uring_register(
                        &self.fd,
                        IoringRegisterOp::RegisterRingFds,
                        ptr::from_mut(&mut update).cast(),
                        1,
                    )?
                };
                assert_eq!(count, 1);
                Ok(())
            }

            /// Opens `path` read-only through the ring, with `personality`'s
            /// credentials if one is given, and waits for the result.
            pub(super) fn open(
                &self,
                path: &CStr,
                personality: Option<u16>,
            ) -> Result<OwnedFd, Errno> {
                let sq_off = &self.params.sq_off;
                let cq_off = &self.params.cq_off;

                let sqe = io_uring_sqe {
                    opcode: IoringOp::Openat,
                    fd: libc::AT_FDCWD,
                    addr_or_splice_off_in: addr_or_splice_off_in_union {
                        addr: io_uring_ptr::new(path.as_ptr().cast_mut().cast()),
                    },
                    op_flags: op_flags_union {
                        open_flags: OFlags::RDONLY | OFlags::CLOEXEC,
                    },
                    personality: personality.unwrap_or(0),
                    ..Default::default()
                };

                let tail = self.sq.atomic(sq_off.tail);
                let position = tail.load(Ordering::Relaxed);
                let slot = position & self.sq.atomic(sq_off.ring_mask).load(Ordering::Relaxed);
                let entry = self
                    .sqes
                    .at::<io_uring_sqe>(slot as usize * size_of::<io_uring_sqe>());
                let index = self
                    .sq
                    .at::<u32>(sq_off.array as usize + slot as usize * size_of::<u32>());
                // SAFETY: both are inside their mappings, as `at` checked, and
                // the kernel reads them only after the tail below publishes
                // them.
                unsafe {
                    entry.write(sqe);
                    index.write(slot);
                }
                tail.store(position.wrapping_add(1), Ordering::Release);

                let mut flags = IoringEnterFlags::GETEVENTS;
                if self.params.flags.contains(IoringSetupFlags::SQPOLL) {
                    flags |= IoringEnterFlags::SQ_WAKEUP;
                }
                // SAFETY: the submission's path outlives this call, which
                // returns only once its completion is posted.
                unsafe { io_uring_enter(&self.fd, 1, 1, flags)? };

                let head = self.cq.atomic(cq_off.head);
                let seen = head.load(Ordering::Relaxed);
                assert_ne!(
                    seen,
                    self.cq.atomic(cq_off.tail).load(Ordering::Acquire),
                    "a completion is posted"
                );
                let slot = seen & self.cq.atomic(cq_off.ring_mask).load(Ordering::Relaxed);
                let cqe = self.cq.at::<io_uring_cqe>(
                    cq_off.cqes as usize + slot as usize * size_of::<io_uring_cqe>(),
                );
                // SAFETY: inside the mapping, as `at` checked, and the acquire
                // load above makes the kernel's write visible.
                let res = unsafe { ptr::addr_of!((*cqe).res).read() };
                head.store(seen.wrapping_add(1), Ordering::Release);
                match res {
                    // SAFETY: the kernel returned a new descriptor, and nothing
                    // else takes it.
                    fd if fd >= 0 => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
                    errno => Err(Errno::from_raw_os_error(-errno)),
                }
            }
        }
    }

    /// Landlock has no rights for these call families.
    #[test]
    fn metadata_and_modes_outside_the_grants_are_not_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let (_root, granted, outside) = dirs();
        let secret = outside.join("secret.txt");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();

        run_locked("metadata_child", &granted, &outside);

        let mode = fs::metadata(&secret).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the locked process changed no mode");
    }

    #[test]
    fn metadata_child() {
        use std::os::unix::fs::PermissionsExt;

        if child_mode("metadata_child").is_none() {
            return;
        }
        let mut gate = granted_gate();
        let (_, secret) = lock_and_prove(&mut gate);

        assert_eq!(fs::metadata(&secret).unwrap().len(), b"secret".len() as u64);
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Landlock's `IOCTL_DEV` covers character and block devices only. The
    /// filesystem alone checks an ioctl on a regular file, against the
    /// file's owner rather than the grant's rights, so the owner can change
    /// its attribute flags through a descriptor opened read-only beneath a
    /// `READ` grant.
    #[test]
    fn ioctls_on_files_beneath_a_grant_are_not_restricted() {
        use rustix::fs::{IFlags, ioctl_getflags};

        let (_root, granted, outside) = dirs();
        let file = granted.join("a.txt");
        fs::write(&file, b"a").unwrap();
        let before = ioctl_getflags(fs::File::open(&file).unwrap())
            .expect("FS_IOC_GETFLAGS on the temporary directory's file system");
        assert!(!before.contains(IFlags::NODUMP));

        run_locked("file_ioctl_child", &granted, &outside);

        let after = ioctl_getflags(fs::File::open(&file).unwrap()).unwrap();
        assert_eq!(
            after,
            before | IFlags::NODUMP,
            "the locked child set NODUMP"
        );
        assert_eq!(fs::read(&file).unwrap(), b"a");
    }

    #[test]
    fn file_ioctl_child() {
        use rustix::fs::{IFlags, ioctl_getflags, ioctl_setflags};

        if child_mode("file_ioctl_child").is_none() {
            return;
        }
        let mut gate = granted_gate();
        let (granted, _) = lock_and_prove(&mut gate);
        eprintln!("file_ioctl_child: applied {:?}", gate.restrictions());
        let path = format!("{granted}/a.txt");
        let err = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect_err("a write beneath a READ grant");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);

        let file = fs::File::open(&path).unwrap();
        let flags = ioctl_getflags(&file).unwrap();
        ioctl_setflags(&file, flags | IFlags::NODUMP).expect("FS_IOC_SETFLAGS after the lock");
    }

    /// Mounts beneath a grant, which the threat model lists among the gaps:
    /// - A file system mounted beneath a grant after `grant()` is reached
    ///   through the gate, which does not refuse crossing a mount point, and
    ///   after `lock()` through the kernel rules, which follow a path up
    ///   through the mount.
    /// - A directory bind-mounted into a grant is reached with that grant's
    ///   rights, even though it has its own grant with fewer. `grant` reads
    ///   nesting up through `..`, which leads to where the directory really
    ///   is (RFC 0012's limits). A real subdirectory granted with fewer
    ///   rights is refused.
    ///
    /// Mounting needs root, so the child runs as root in a mount namespace
    /// of its own, where its mounts end with it.
    #[test]
    #[ignore = "needs passwordless `sudo` and util-linux `unshare`; CI's check job runs it"]
    fn mounts_beneath_a_grant_are_reached_through_it() {
        let (_root, granted, outside) = dirs();
        let apart = outside.join("apart");
        for dir in [granted.join("mnt"), granted.join("bound"), apart.clone()] {
            fs::create_dir(dir).unwrap();
        }

        // `sudo` resets the environment, so `env` sets it inside.
        let output = Command::new("sudo")
            .args(["--non-interactive", "env", "FSGATE_CHILD=mount_child"])
            .arg("FSGATE_MODE=root")
            .arg(format!("FSGATE_GRANTED={}", granted.display()))
            .arg(format!("FSGATE_OUTSIDE={}", outside.display()))
            .args(["unshare", "--mount", "--propagation", "private", "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "kernel::mount_child", "--nocapture"])
            .output()
            .expect("run `sudo`");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the child failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        // The mounts ended with the child's namespace. What it wrote
        // through the bind mount is in the directory itself.
        assert_eq!(fs::read_dir(granted.join("mnt")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(granted.join("bound")).unwrap().count(), 0);
        assert!(apart.join("through_gate.txt").exists());
        assert!(apart.join("through_kernel.txt").exists());
        assert!(!apart.join("direct.txt").exists());
    }

    #[test]
    fn mount_child() {
        use std::os::unix::fs::MetadataExt;

        if child_mode("mount_child").is_none() {
            return;
        }
        let granted = PathBuf::from(std::env::var("FSGATE_GRANTED").unwrap());
        let outside = PathBuf::from(std::env::var("FSGATE_OUTSIDE").unwrap());
        let (mnt, bound, apart) = (
            granted.join("mnt"),
            granted.join("bound"),
            outside.join("apart"),
        );
        let mount = |args: &[&std::ffi::OsStr]| {
            let status = Command::new("mount")
                .args(args)
                .status()
                .expect("run `mount`");
            assert!(status.success(), "mount {args:?}: {status}");
        };

        let mut gate = Gate::new();
        gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
            .unwrap();

        // A file system mounted after the grant.
        mount(&[
            "-t".as_ref(),
            "tmpfs".as_ref(),
            "tmpfs".as_ref(),
            mnt.as_os_str(),
        ]);
        fs::write(mnt.join("file.txt"), b"mounted").unwrap();
        assert_ne!(
            fs::metadata(&mnt).unwrap().dev(),
            fs::metadata(&granted).unwrap().dev(),
            "the mount is another file system"
        );
        let mut content = String::new();
        gate.open(mnt.join("file.txt"))
            .expect("open across the mount point")
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "mounted");

        // A real subdirectory with fewer rights is refused, but a directory
        // bind-mounted in is not, and the outer grant's rights reach it.
        fs::create_dir(granted.join("sub")).unwrap();
        let err = gate.grant(granted.join("sub"), Rights::READ).unwrap_err();
        assert!(matches!(err, GateError::NestedGrant { .. }), "got {err:?}");
        mount(&["--bind".as_ref(), apart.as_os_str(), bound.as_os_str()]);
        gate.grant(&apart, Rights::READ)
            .expect("the bind mount hides the nesting");
        gate.create(bound.join("through_gate.txt"))
            .expect("create through the outer grant");
        let err = gate.create(apart.join("direct.txt")).unwrap_err();
        assert!(
            matches!(err, GateError::RightsExceeded { .. }),
            "got {err:?}"
        );

        // The kernel rules after the lock: the same, by each path.
        assert_eq!(gate.lock().expect("strict lock"), LockStatus::FullyEnforced);
        let err = fs::read(outside.join("secret.txt")).expect_err("read outside the grants");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert_eq!(fs::read_to_string(mnt.join("file.txt")).unwrap(), "mounted");
        fs::write(bound.join("through_kernel.txt"), b"")
            .expect("write through the outer grant's rule");
        let err = fs::write(apart.join("direct.txt"), b"").expect_err("write by the real path");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    /// The installed ruleset never changes, so only operations through the
    /// gate see a later narrow or revoke.
    #[test]
    fn narrowing_or_revoking_after_the_lock_changes_only_the_gate() {
        let (_root, granted, outside) = dirs();
        fs::write(granted.join("a.txt"), b"inside").unwrap();

        run_locked("late_change_child", &granted, &outside);

        assert!(!granted.join("through_gate.txt").exists());
        assert!(
            granted.join("raw.txt").exists(),
            "the raw write was refused"
        );
    }

    #[test]
    fn late_change_child() {
        if child_mode("late_change_child").is_none() {
            return;
        }
        let mut gate = Gate::new();
        let grant = gate
            .grant(
                std::env::var("FSGATE_GRANTED").unwrap(),
                Rights::READ | Rights::WRITE | Rights::CREATE,
            )
            .unwrap();
        let (granted, _) = lock_and_prove(&mut gate);

        gate.narrow(grant, Rights::READ).unwrap();
        let err = gate
            .create(format!("{granted}/through_gate.txt"))
            .unwrap_err();
        assert!(
            matches!(err, GateError::RightsExceeded { .. }),
            "got {err:?}"
        );
        fs::write(format!("{granted}/raw.txt"), b"x").unwrap();

        gate.revoke(grant).unwrap();
        let err = gate.open(format!("{granted}/a.txt")).unwrap_err();
        assert!(matches!(err, GateError::NoGrant { .. }), "got {err:?}");
        assert_eq!(fs::read(format!("{granted}/a.txt")).unwrap(), b"inside");
    }

    /// Linux 6.1, whose Landlock ABI v2 lacks the truncation right that the
    /// v3 floor adds. CI's `kernels` job boots it and runs these with
    /// `--ignored`. Each first checks that the kernel is v2, so on any other
    /// kernel they fail.
    mod below_landlock_v3 {
        use super::*;

        fn run(mode: &str, granted: &std::path::Path, outside: &std::path::Path) {
            assert_eq!(kernel_abi(), 2, "needs Landlock ABI v2 (Linux 6.1)");
            run_child(
                "below_landlock_v3::child",
                mode,
                &[
                    ("FSGATE_GRANTED", granted.as_os_str()),
                    ("FSGATE_OUTSIDE", outside.as_os_str()),
                ],
            );
        }

        #[test]
        #[ignore = "needs Landlock ABI v2 (Linux 6.1); CI's kernels job runs it"]
        fn strict_lock_fails_closed() {
            let (_root, granted, outside) = dirs();
            run("strict", &granted, &outside);
        }

        /// The kernel refuses reads and creates outside the grants, but not
        /// truncation, so a file beneath a read-only grant can be emptied.
        #[test]
        #[ignore = "needs Landlock ABI v2 (Linux 6.1); CI's kernels job runs it"]
        fn best_effort_lock_enforces_only_the_abi_v2_rules() {
            let (_root, granted, outside) = dirs();
            fs::write(granted.join("a.txt"), b"inside").unwrap();

            run("best-effort", &granted, &outside);

            assert!(!outside.join("created.txt").exists());
            assert_eq!(fs::read(granted.join("a.txt")).unwrap(), b"");
        }

        #[test]
        fn child() {
            let Some(mode) = child_mode("below_landlock_v3::child") else {
                return;
            };
            let mut gate = granted_gate();
            let granted = std::env::var("FSGATE_GRANTED").unwrap();
            let outside = std::env::var("FSGATE_OUTSIDE").unwrap();
            let secret = format!("{outside}/secret.txt");
            match mode.as_str() {
                "strict" => {
                    let err = gate.lock().expect_err("a strict lock below ABI v3");
                    assert!(
                        matches!(err, GateError::LockUnsupported { .. }),
                        "got {err:?}"
                    );
                    assert!(
                        err.to_string()
                            .contains("does not fully enforce Landlock ABI v3"),
                        "{err}"
                    );
                    // Nothing was applied: the kernel still allows a raw read
                    // outside the grants, and the gate is still granting.
                    fs::read(&secret).expect("a failed lock applied nothing");
                    assert_eq!(gate.restrictions(), None);
                    gate.grant(&outside, Rights::READ)
                        .expect("the gate is still granting");
                }
                "best-effort" => {
                    let status = gate.lock_with(LockPolicy::BestEffort).unwrap();
                    assert_eq!(status, LockStatus::PartiallyEnforced);
                    assert_eq!(gate.restrictions(), Some(Restrictions::empty()));
                    let err = fs::read(&secret).expect_err("read outside the grants");
                    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
                    let err = fs::File::create(format!("{outside}/created.txt"))
                        .expect_err("create outside the grants");
                    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
                    raw::truncate(format!("{granted}/a.txt"))
                        .expect("truncating needs ABI v3, so the kernel allows it");
                }
                other => panic!("unknown mode {other}"),
            }
        }

        /// `truncate(2)` by path, which neither std nor rustix wraps.
        ///
        /// Safety contract: the call reads a NUL-terminated path that
        /// outlives it, and writes no memory of this process.
        #[allow(unsafe_code)]
        mod raw {
            use std::ffi::CString;
            use std::io;
            use std::os::unix::ffi::OsStrExt;
            use std::path::Path;

            /// Empties the file at `path` without opening it.
            pub(super) fn truncate(path: impl AsRef<Path>) -> io::Result<()> {
                let path = CString::new(path.as_ref().as_os_str().as_bytes())?;
                // SAFETY: `path` is NUL-terminated and lives until the call
                // returns, and `truncate` only reads it.
                if unsafe { libc::truncate(path.as_ptr(), 0) } == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }
}
