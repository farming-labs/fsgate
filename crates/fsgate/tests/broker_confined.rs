//! The worker the real `fsgate-broker` starts (RFC 0008). Each case runs a
//! scenario from this test binary as the broker's command, confined, and
//! where it can a control run with `--unconfined` shows the test would notice
//! the difference. The test binary is dynamically linked, so a confined
//! scenario passing also shows the default paths are enough to start one.

#![cfg(unix)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn in_child(scenario: &str) -> bool {
    env::var_os("FSGATE_CHILD").is_some_and(|child| child == scenario)
}

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    granted: PathBuf,
    outside: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    // The confined worker gets an absolute path, and macOS's temporary
    // directory is a symlink.
    let root = dir.path().canonicalize().unwrap();
    let granted = root.join("granted");
    let outside = root.join("outside");
    fs::create_dir(&granted).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(granted.join("a.txt"), b"inside").unwrap();
    fs::write(outside.join("secret.txt"), b"secret").unwrap();
    Fixture {
        _root: dir,
        root,
        granted,
        outside,
    }
}

/// The real broker, granting `granted/` and running `scenario` with `flags`.
fn broker(fixture: &Fixture, flags: &[String], scenario: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fsgate-broker"));
    command
        .args(["--grant", &format!("{}:r", fixture.granted.display())])
        .args(flags)
        .arg("--")
        .arg(env::current_exe().unwrap())
        .args(["--exact", scenario, "--nocapture"])
        .env("FSGATE_CHILD", scenario)
        .env("FSGATE_GRANTED", &fixture.granted)
        .env("FSGATE_OUTSIDE", &fixture.outside)
        .current_dir(&fixture.root);
    command
}

fn assert_ran(output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "the worker did not pass: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn unconfined() -> Vec<String> {
    vec!["--unconfined".to_string()]
}

/// The variables every scenario reads, plus `extra`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn confined(extra: &[&str]) -> Vec<String> {
    ["FSGATE_CHILD", "FSGATE_GRANTED", "FSGATE_OUTSIDE"]
        .iter()
        .chain(extra)
        .flat_map(|name| ["--env".to_string(), (*name).to_string()])
        .collect()
}

/// A scenario that leaves a marker behind if it runs at all.
#[test]
fn marker_scenario() {
    if !in_child("marker_scenario") {
        return;
    }
    fs::File::create(env::var("FSGATE_MARKER").unwrap()).unwrap();
}

/// Without confinement available, the worker does not start, unless the
/// command line says to run it unconfined.
fn assert_refused_until_unconfined() {
    let fixture = fixture();
    let marker = fixture.outside.join("marker");

    let refused = broker(&fixture, &[], "marker_scenario")
        .env("FSGATE_MARKER", &marker)
        .output()
        .expect("run fsgate-broker");
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("--unconfined"), "no remedy in: {stderr}");
    assert!(!marker.exists(), "the worker ran without confinement");

    let allowed = broker(&fixture, &unconfined(), "marker_scenario")
        .env("FSGATE_MARKER", &marker)
        .output()
        .expect("run fsgate-broker");
    assert_ran(&allowed);
    assert!(marker.exists(), "the control run left no marker");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn a_platform_that_cannot_confine_refuses_to_start_the_worker() {
    assert_refused_until_unconfined();
}

/// Runs only on a kernel booted without Landlock.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a kernel without Landlock; CI boots one with lsm=capability"]
fn the_broker_refuses_to_start_a_worker_without_landlock() {
    assert_refused_until_unconfined();
}

fn usage_error(flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fsgate-broker"))
        .args(flags)
        .output()
        .expect("run fsgate-broker")
}

#[test]
fn a_socket_needs_an_unconfined_worker() {
    let fixture = fixture();
    let socket = fixture.root.join("broker.sock");
    let marker = fixture.root.join("marker");
    let output = usage_error(&[
        "--grant",
        &format!("{}:r", fixture.granted.display()),
        "--socket",
        &socket.display().to_string(),
        "--",
        "touch",
        &marker.display().to_string(),
    ]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--unconfined"), "no remedy in: {stderr}");
    assert!(!socket.exists(), "a socket was created anyway");
    assert!(!marker.exists(), "the worker ran");
}

#[test]
fn a_direct_path_cannot_be_written() {
    for letter in ["w", "c"] {
        let spec = format!("/tmp:{letter}");
        let output = usage_error(&["--grant", "/tmp:r", "--direct", &spec, "--", "true"]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--grant"), "no remedy in: {stderr}");
    }
}

/// A relative `--direct` path would resolve against the broker's working
/// directory, so `.:r` under a service started in `/` would open everything.
/// `--grant` already refuses one.
#[test]
fn a_direct_path_must_be_absolute() {
    for spec in [".:r", "usr:r", ":r"] {
        let output = usage_error(&["--grant", "/tmp:r", "--direct", spec, "--", "true"]);
        assert_eq!(output.status.code(), Some(2), "{spec}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("absolute"),
            "{spec}: no remedy in: {stderr}"
        );
    }
}

#[test]
fn confinement_flags_need_a_confined_worker() {
    for flags in [
        ["--unconfined", "--direct", "/usr:r"],
        ["--unconfined", "--env", "PATH"],
        ["--experimental-intercept", "--direct", "/usr:r"],
        ["--experimental-intercept", "--env", "PATH"],
    ] {
        let mut args = vec!["--grant", "/tmp:r"];
        args.extend(flags);
        args.extend(["--", "true"]);
        let output = usage_error(&args);
        assert_eq!(output.status.code(), Some(2), "{flags:?}: {output:?}");
    }
}

#[test]
fn an_environment_name_is_only_a_name() {
    for name in ["", "A=b"] {
        let output = usage_error(&["--grant", "/tmp:r", "--env", name, "--", "true"]);
        assert_eq!(output.status.code(), Some(2), "{name:?}: {output:?}");
    }
}

#[cfg(target_os = "linux")]
mod kernel {
    use std::env;
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::parent_id;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    use fsgate::BrokerGate;
    use rustix::io::FdFlags;

    use super::{assert_ran, broker, confined, fixture, in_child, unconfined};

    fn expect_denied() -> bool {
        env::var("FSGATE_EXPECT").unwrap() == "denied"
    }

    /// Reaching outside the grants directly, from the worker and from a
    /// program it starts, fails, and creating a file leaves none.
    #[test]
    fn a_confined_worker_cannot_reach_files_on_its_own() {
        let fixture = fixture();
        let marker = fixture.outside.join("marker");

        let output = broker(
            &fixture,
            &confined(&["FSGATE_EXPECT"]),
            "kernel::reach_scenario",
        )
        .env("FSGATE_EXPECT", "denied")
        .output()
        .expect("run fsgate-broker");
        assert_ran(&output);
        assert!(!marker.exists(), "the worker created a file");

        let output = broker(&fixture, &unconfined(), "kernel::reach_scenario")
            .env("FSGATE_EXPECT", "allowed")
            .output()
            .expect("run fsgate-broker");
        assert_ran(&output);
        assert!(marker.exists(), "the control run left no marker");
    }

    #[test]
    fn reach_scenario() {
        if !in_child("kernel::reach_scenario") {
            return;
        }
        let outside = env::var("FSGATE_OUTSIDE").unwrap();
        let secret = format!("{outside}/secret.txt");
        let marker = format!("{outside}/marker");
        if expect_denied() {
            assert_eq!(
                fs::read(&secret).unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
            assert_eq!(
                File::create(&marker).unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
            let cat = Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("cat '{secret}'"))
                .output()
                .expect("a confined worker can still start programs");
            assert!(!cat.status.success(), "a child read the file: {cat:?}");
            assert!(cat.stdout.is_empty(), "a child read the file: {cat:?}");
        } else {
            assert_eq!(fs::read(&secret).unwrap(), b"secret");
            File::create(&marker).unwrap();
        }
    }

    /// The grants did not become worker rules: the same file is served by
    /// the broker and refused when opened directly.
    #[test]
    fn a_granted_file_comes_only_through_the_broker() {
        let fixture = fixture();
        let output = broker(&fixture, &confined(&[]), "kernel::broker_only_scenario")
            .output()
            .expect("run fsgate-broker");
        assert_ran(&output);
    }

    #[test]
    fn broker_only_scenario() {
        if !in_child("kernel::broker_only_scenario") {
            return;
        }
        let path = format!("{}/a.txt", env::var("FSGATE_GRANTED").unwrap());
        let mut gate = BrokerGate::from_inherited().expect("adopt the connection");
        let mut content = String::new();
        gate.open(&path)
            .expect("the broker serves its grant")
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "inside");
        assert_eq!(
            fs::read(&path).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
    }

    /// A grant the confined worker could read without the broker is refused,
    /// whichever of the two paths contains the other: those reads would not
    /// be audited, and revoking the grant would not stop them. A grant that
    /// gives no right the worker has there is fine.
    #[test]
    fn a_grant_the_worker_could_read_directly_is_refused() {
        let fixture = fixture();
        let sub = fixture.granted.join("sub");
        fs::create_dir(&sub).unwrap();
        let root = fixture.root.display().to_string();
        let sub = sub.display().to_string();
        let cases = [
            (
                ["--grant".to_string(), "/usr/bin:r".to_string()],
                "`/usr`".to_string(),
            ),
            (
                ["--direct".to_string(), format!("{root}:r")],
                format!("`--direct {root}:r`"),
            ),
            (
                ["--direct".to_string(), format!("{sub}:l")],
                format!("`--direct {sub}:l`"),
            ),
        ];
        for (extra, named) in cases {
            let mut flags = confined(&[]);
            flags.extend(extra);
            let output = broker(&fixture, &flags, "kernel::nothing_scenario")
                .output()
                .expect("run fsgate-broker");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(1), "{named}: {stderr}");
            assert!(stderr.contains(&named), "{named}: {stderr}");
            assert!(output.stdout.is_empty(), "{named}: the worker ran");
        }

        let drop = fixture.outside.join("drop");
        fs::create_dir(&drop).unwrap();
        let mut flags = confined(&[]);
        flags.extend([
            "--grant".to_string(),
            format!("{}:wc", drop.display()),
            "--direct".to_string(),
            format!("{}:r", fixture.outside.display()),
        ]);
        let output = broker(&fixture, &flags, "kernel::nothing_scenario")
            .output()
            .expect("run fsgate-broker");
        assert_ran(&output);
    }

    #[test]
    fn nothing_scenario() {}

    #[test]
    fn a_direct_path_can_be_read_and_nothing_beside_it() {
        let fixture = fixture();
        let open = fixture.outside.join("open");
        fs::create_dir(&open).unwrap();
        fs::write(open.join("runtime.txt"), b"runtime").unwrap();

        let mut flags = confined(&[]);
        flags.extend(["--direct".to_string(), format!("{}:r", open.display())]);
        let output = broker(&fixture, &flags, "kernel::direct_scenario")
            .output()
            .expect("run fsgate-broker");
        assert_ran(&output);
    }

    #[test]
    fn direct_scenario() {
        if !in_child("kernel::direct_scenario") {
            return;
        }
        let outside = env::var("FSGATE_OUTSIDE").unwrap();
        assert_eq!(
            fs::read(format!("{outside}/open/runtime.txt")).unwrap(),
            b"runtime"
        );
        assert_eq!(
            fs::read(format!("{outside}/secret.txt"))
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    /// A descriptor the broker's parent left open would outlive the sandbox,
    /// because Landlock does not restrict what was opened before it applied.
    #[test]
    fn a_descriptor_the_parent_left_open_is_closed_in_the_worker() {
        let fixture = fixture();
        let stray = File::open(fixture.outside.join("secret.txt")).unwrap();
        rustix::io::fcntl_setfd(stray.as_fd(), FdFlags::empty()).unwrap();
        let number = stray.as_raw_fd().to_string();
        let inode = stray.metadata().unwrap().ino().to_string();

        let extra = ["FSGATE_EXPECT", "FSGATE_STRAY", "FSGATE_STRAY_INODE"];
        for (flags, expect) in [(confined(&extra), "denied"), (unconfined(), "allowed")] {
            let output = broker(&fixture, &flags, "kernel::stray_scenario")
                .env("FSGATE_EXPECT", expect)
                .env("FSGATE_STRAY", &number)
                .env("FSGATE_STRAY_INODE", &inode)
                .output()
                .expect("run fsgate-broker");
            assert_ran(&output);
        }
        drop(stray);
    }

    #[test]
    fn stray_scenario() {
        if !in_child("kernel::stray_scenario") {
            return;
        }
        let number = env::var("FSGATE_STRAY").unwrap();
        let inode: u64 = env::var("FSGATE_STRAY_INODE").unwrap().parse().unwrap();
        // `stat` works under Landlock. The inode tells this descriptor from
        // something else that took its number.
        let open =
            fs::metadata(format!("/proc/self/fd/{number}")).is_ok_and(|meta| meta.ino() == inode);
        assert_eq!(open, !expect_denied());
    }

    #[test]
    fn a_confined_worker_inherits_only_the_named_variables() {
        let fixture = fixture();
        let extra = ["FSGATE_EXPECT", "FSGATE_NAMED", "FSGATE_ABSENT"];
        for (flags, expect) in [(confined(&extra), "denied"), (unconfined(), "allowed")] {
            let output = broker(&fixture, &flags, "kernel::environment_scenario")
                .env("FSGATE_EXPECT", expect)
                .env("FSGATE_NAMED", "kept")
                .env("FSGATE_TOKEN", "secret")
                .env_remove("FSGATE_ABSENT")
                .output()
                .expect("run fsgate-broker");
            assert_ran(&output);
        }
    }

    #[test]
    fn environment_scenario() {
        if !in_child("kernel::environment_scenario") {
            return;
        }
        assert_eq!(env::var("FSGATE_NAMED").unwrap(), "kept");
        assert!(env::var_os("FSGATE_ABSENT").is_none());
        assert!(env::var_os("FSGATE_BROKER_FD").is_some());
        assert_eq!(env::var_os("FSGATE_TOKEN").is_some(), !expect_denied());
    }

    /// A session leader has no controlling terminal, so `TIOCSTI` cannot type
    /// into the user's shell. Calling that ioctl from a test would need
    /// `unsafe`, and whether a control could succeed depends on
    /// `dev.tty.legacy_tiocsti`, so this checks the session.
    #[test]
    fn a_confined_worker_leads_its_own_session() {
        let fixture = fixture();
        for (flags, expect) in [
            (confined(&["FSGATE_EXPECT"]), "denied"),
            (unconfined(), "allowed"),
        ] {
            let output = broker(&fixture, &flags, "kernel::session_scenario")
                .env("FSGATE_EXPECT", expect)
                .output()
                .expect("run fsgate-broker");
            assert_ran(&output);
        }
    }

    #[test]
    fn session_scenario() {
        if !in_child("kernel::session_scenario") {
            return;
        }
        let leader = rustix::process::getsid(None).unwrap() == rustix::process::getpid();
        assert_eq!(leader, expect_denied());
    }

    /// `/proc/<pid>/environ` is guarded by the same kernel check as ptrace,
    /// and unlike attaching it needs no `unsafe` and Yama does not block the
    /// control. `--direct /proc:r` takes the path rule out of the way, so
    /// only that check can refuse it.
    #[test]
    fn a_confined_worker_cannot_inspect_its_broker() {
        let fixture = fixture();
        let mut flags = confined(&["FSGATE_EXPECT"]);
        flags.extend(["--direct".to_string(), "/proc:r".to_string()]);
        for (flags, expect) in [(flags, "denied"), (unconfined(), "allowed")] {
            let output = broker(&fixture, &flags, "kernel::inspect_scenario")
                .env("FSGATE_EXPECT", expect)
                .output()
                .expect("run fsgate-broker");
            assert_ran(&output);
        }
    }

    #[test]
    fn inspect_scenario() {
        if !in_child("kernel::inspect_scenario") {
            return;
        }
        let environ = fs::read(format!("/proc/{}/environ", parent_id()));
        if expect_denied() {
            assert_eq!(environ.unwrap_err().kind(), ErrorKind::PermissionDenied);
            // `no_new_privs` keeps a set-ID program from gaining privileges.
            let status = fs::read_to_string("/proc/self/status").unwrap();
            assert!(
                status.lines().any(|line| line == "NoNewPrivs:\t1"),
                "{status}"
            );
        } else {
            let environ = String::from_utf8_lossy(&environ.unwrap()).into_owned();
            assert!(environ.contains("FSGATE_CHILD="), "{environ}");
        }
    }

    /// Reads the worker's output up to its readiness line.
    fn wait_until_ready(stdout: &mut impl BufRead) {
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                stdout.read_line(&mut line).expect("read the worker"),
                0,
                "the worker exited before it was ready"
            );
            if line.contains("worker ready") {
                return;
            }
        }
    }

    #[test]
    fn killing_the_broker_kills_a_confined_worker() {
        let fixture = fixture();
        let mut broker = broker(&fixture, &confined(&[]), "kernel::waiting_scenario")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn fsgate-broker");
        let stdin = broker.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(broker.stdout.take().expect("piped stdout"));
        wait_until_ready(&mut stdout);

        broker.kill().expect("kill the broker");
        broker.wait().expect("reap the broker");

        // The worker holds the last writer of this pipe. The timeout only
        // turns a regression into a failure instead of a hang; `stdin` stays
        // open until then, so a surviving worker cannot exit on its own.
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = stdout.read_to_end(&mut rest);
            let _ = done.send(());
        });
        finished
            .recv_timeout(Duration::from_secs(30))
            .expect("the worker outlived its broker");
        drop(stdin);
    }

    /// The control: an unconfined worker keeps running after its broker dies,
    /// which is what the case above would see if the death signal were lost.
    #[test]
    fn killing_the_broker_leaves_an_unconfined_worker_running() {
        let fixture = fixture();
        let mut broker = broker(&fixture, &unconfined(), "kernel::waiting_scenario")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn fsgate-broker");
        let mut stdin = broker.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(broker.stdout.take().expect("piped stdout"));
        wait_until_ready(&mut stdout);

        broker.kill().expect("kill the broker");
        broker.wait().expect("reap the broker");

        stdin.write_all(b"ping\n").expect("the worker is gone");
        let mut reply = String::new();
        stdout.read_line(&mut reply).expect("read the worker");
        assert!(reply.contains("alive"), "got {reply:?}");
    }

    /// The gap: the death signal binds only the worker. A program it starts
    /// never has one, so it outlives a killed broker, still confined. The
    /// worker could also clear its own, but on its main thread, and libtest
    /// runs each scenario on another.
    #[test]
    fn a_program_a_confined_worker_starts_outlives_its_broker() {
        let fixture = fixture();
        let mut broker = broker(
            &fixture,
            &confined(&[]),
            "kernel::starts_a_program_scenario",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn fsgate-broker");
        let mut stdin = broker.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(broker.stdout.take().expect("piped stdout"));
        wait_until_ready(&mut stdout);

        broker.kill().expect("kill the broker");
        broker.wait().expect("reap the broker");

        stdin.write_all(b"ping\n").expect("the program is gone");
        let mut reply = String::new();
        stdout.read_line(&mut reply).expect("read the program");
        assert!(reply.contains("alive"), "got {reply:?}");
    }

    #[test]
    fn starts_a_program_scenario() {
        if !in_child("kernel::starts_a_program_scenario") {
            return;
        }
        // The program shares this worker's standard streams, and the
        // broker's death kills only this worker.
        Command::new(env::current_exe().unwrap())
            .args(["--exact", "kernel::outlives_scenario", "--nocapture"])
            .env("FSGATE_CHILD", "kernel::outlives_scenario")
            .status()
            .unwrap();
    }

    #[test]
    fn outlives_scenario() {
        if !in_child("kernel::outlives_scenario") {
            return;
        }
        println!("worker ready");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        // It outlived the broker and is still confined.
        let secret = format!("{}/secret.txt", env::var("FSGATE_OUTSIDE").unwrap());
        let err = fs::read(secret).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        println!("alive");
    }

    #[test]
    fn waiting_scenario() {
        if !in_child("kernel::waiting_scenario") {
            return;
        }
        println!("worker ready");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        println!("alive");
    }
}
