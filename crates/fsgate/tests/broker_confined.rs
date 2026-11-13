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

/// Runs only on Linux 6.1, whose Landlock ABI v2 lacks the truncation right
/// the worker's rules need. CI's `kernels` job boots it.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs Landlock ABI v2 (Linux 6.1); CI's kernels job runs it"]
fn the_broker_refuses_to_start_a_worker_below_landlock_v3() {
    use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};

    let handles = |abi| {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .is_ok()
    };
    assert!(
        handles(ABI::V2) && !handles(ABI::V3),
        "needs Landlock ABI v2 (Linux 6.1)"
    );
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

/// An argument that is not UTF-8 is a usage error, not a panic.
#[test]
fn an_argument_that_is_not_utf8_is_a_usage_error() {
    use std::os::unix::ffi::OsStrExt;

    let output = Command::new(env!("CARGO_BIN_EXE_fsgate-broker"))
        .args(["--grant", "/tmp:r", "--unconfined", "--", "true"])
        .arg(std::ffi::OsStr::from_bytes(b"\xff"))
        .output()
        .expect("run fsgate-broker");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("UTF-8"), "no reason in: {stderr}");
}

#[cfg(target_os = "linux")]
mod kernel {
    use std::env;
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
    use std::os::unix::process::parent_id;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStderr, Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    use fsgate::BrokerGate;
    use rustix::io::FdFlags;
    use rustix::process::{Pid, Signal};

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
        let listed = fixture.outside.join("listed");
        fs::create_dir_all(listed.join("sub")).unwrap();
        let root = fixture.root.display().to_string();
        let sub = sub.display().to_string();
        let listed = listed.display().to_string();
        let flag = |name: &str, value: String| [name.to_string(), value];
        let cases = [
            (
                vec![flag("--grant", "/usr/bin:r".into())],
                "`/usr`".to_string(),
            ),
            (
                vec![flag("--direct", format!("{root}:r"))],
                format!("`--direct {root}:r`"),
            ),
            (
                vec![flag("--direct", format!("{sub}:r"))],
                format!("`--direct {sub}:r`"),
            ),
            (
                vec![
                    flag("--grant", format!("{listed}:l")),
                    flag("--direct", format!("{listed}/sub:l")),
                ],
                format!("`--direct {listed}/sub:l`"),
            ),
        ];
        for (extra, named) in cases {
            let extra = extra.concat();
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

        // Neither grant gives a right the worker has at the `--direct` path:
        // a write-only grant beneath a readable one, and a listable path
        // beneath a grant that can only read.
        let drop = fixture.outside.join("drop");
        fs::create_dir(&drop).unwrap();
        let controls = [
            [
                flag("--grant", format!("{}:wc", drop.display())),
                flag("--direct", format!("{}:r", fixture.outside.display())),
            ]
            .concat(),
            flag("--direct", format!("{sub}:l")).to_vec(),
        ];
        for extra in controls {
            let mut flags = confined(&[]);
            flags.extend(extra);
            let output = broker(&fixture, &flags, "kernel::nothing_scenario")
                .output()
                .expect("run fsgate-broker");
            assert_ran(&output);
        }
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

    /// OpenSSL's configuration on Debian and its derivatives, Arch, and
    /// Alpine, and on Fedora.
    const OPENSSL_CONFIGURATION: [&str; 2] = ["/etc/ssl/openssl.cnf", "/etc/pki/tls/openssl3.cnf"];

    /// A confined worker can read OpenSSL's configuration where the system
    /// has it, because Node.js does not start without it (RFC 0008). The
    /// rules name only those files: `/etc/passwd` and a listing of
    /// `/etc/ssl` stay refused where they are in `/etc`. In the `nixos/nix`
    /// image `/etc/passwd` links into `/nix/store`, which the worker may
    /// read.
    #[test]
    fn a_confined_worker_can_read_openssl_configuration() {
        let present: Vec<&str> = OPENSSL_CONFIGURATION
            .into_iter()
            .filter(|path| Path::new(path).exists())
            .collect();
        let fixture = fixture();
        let output = broker(
            &fixture,
            &confined(&["FSGATE_PRESENT"]),
            "kernel::openssl_scenario",
        )
        .env("FSGATE_PRESENT", present.join(":"))
        .output()
        .expect("run fsgate-broker");
        assert_ran(&output);
    }

    #[test]
    fn openssl_scenario() {
        if !in_child("kernel::openssl_scenario") {
            return;
        }
        let present = env::var("FSGATE_PRESENT").unwrap();
        for path in present.split(':').filter(|path| !path.is_empty()) {
            if let Err(err) = fs::read(path) {
                panic!("reading `{path}` failed: {err}");
            }
        }
        let in_etc = |path: &str| fs::canonicalize(path).is_ok_and(|real| real.starts_with("/etc"));
        if in_etc("/etc/passwd") {
            assert_eq!(
                fs::read("/etc/passwd").unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
        }
        if in_etc("/etc/ssl") && Path::new("/etc/ssl").is_dir() {
            assert_eq!(
                fs::read_dir("/etc/ssl").unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
        }
    }

    /// A descriptor the broker's parent left open would outlive the sandbox,
    /// because Landlock does not restrict what was opened before it applied.
    /// The worker closes two, one on each side of its connection's number:
    /// 3, which `sh` opens before it becomes the broker, and one numbered 900
    /// or more. A stray at whatever number the test process had free could
    /// land on either side, and then only that side was checked.
    #[test]
    fn a_descriptor_the_parent_left_open_is_closed_in_the_worker() {
        let fixture = fixture();
        let secret = fixture.outside.join("secret.txt");
        let stray = File::open(&secret).unwrap();
        let high = rustix::io::fcntl_dupfd_cloexec(&stray, 900).unwrap();
        rustix::io::fcntl_setfd(&high, FdFlags::empty()).unwrap();
        let numbers = format!("3,{}", high.as_raw_fd());
        let inode = stray.metadata().unwrap().ino().to_string();

        let extra = ["FSGATE_EXPECT", "FSGATE_STRAYS", "FSGATE_STRAY_INODE"];
        for (flags, expect) in [(confined(&extra), "denied"), (unconfined(), "allowed")] {
            let command = broker(&fixture, &flags, "kernel::stray_scenario");
            let mut through_sh = Command::new("sh");
            through_sh
                .args(["-c", "exec 3<\"$0\" && exec \"$@\""])
                .arg(&secret)
                .arg(command.get_program())
                .args(command.get_args())
                .env("FSGATE_EXPECT", expect)
                .env("FSGATE_STRAYS", &numbers)
                .env("FSGATE_STRAY_INODE", &inode);
            for (key, value) in command.get_envs() {
                if let Some(value) = value {
                    through_sh.env(key, value);
                }
            }
            if let Some(dir) = command.get_current_dir() {
                through_sh.current_dir(dir);
            }
            let output = through_sh.output().expect("run fsgate-broker through sh");
            assert_ran(&output);
        }
        drop(high);
    }

    #[test]
    fn stray_scenario() {
        if !in_child("kernel::stray_scenario") {
            return;
        }
        let inode: u64 = env::var("FSGATE_STRAY_INODE").unwrap().parse().unwrap();
        for number in env::var("FSGATE_STRAYS").unwrap().split(',') {
            // `stat` works under Landlock. The inode tells this descriptor
            // from something else that took its number.
            let open = fs::metadata(format!("/proc/self/fd/{number}"))
                .is_ok_and(|meta| meta.ino() == inode);
            assert_eq!(open, !expect_denied(), "descriptor {number}");
        }
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

    /// Reads the line a worker prints once it and its program run:
    /// `worker ready <worker pid> <program pid>`.
    fn ready_pids(stdout: &mut impl BufRead) -> (Pid, Pid) {
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                stdout.read_line(&mut line).expect("read the worker"),
                0,
                "the worker exited before it was ready"
            );
            if let Some(pids) = line.trim().strip_prefix("worker ready ") {
                let (worker, program) = pids.split_once(' ').expect("two pids");
                let pid = |raw: &str| Pid::from_raw(raw.parse().unwrap()).unwrap();
                return (pid(worker), pid(program));
            }
        }
    }

    /// Fails unless every process holding the other end of `stderr` exits.
    /// The worker and its program inherit it and never close it, so its end
    /// shows they are gone. The timeout only turns a regression into a
    /// failure instead of a hang.
    fn assert_all_exit(mut stderr: ChildStderr, what: &str) {
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = stderr.read_to_end(&mut rest);
            let _ = done.send(());
        });
        if finished.recv_timeout(Duration::from_secs(30)).is_err() {
            panic!("{what}");
        }
    }

    /// Whether `pid` exists and has not exited.
    fn is_running(pid: Pid) -> bool {
        fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero())).is_ok_and(|stat| {
            stat.rsplit_once(')')
                .is_some_and(|(_, rest)| !rest.trim_start().starts_with(['Z', 'X']))
        })
    }

    /// The broker running `scenario`, with all three streams piped. Its
    /// standard input stays open until the test drops it, so a worker or
    /// program reading it waits.
    fn spawn_piped(flags: &[String], fixture: &super::Fixture, scenario: &str) -> Child {
        broker(fixture, flags, scenario)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fsgate-broker")
    }

    /// RFC 0010: when a confined worker exits, a program it left running in
    /// its process group is killed before the broker exits, and the broker
    /// still exits with the worker's code.
    #[test]
    fn a_program_a_confined_worker_leaves_running_ends_with_it() {
        let fixture = fixture();
        let mut broker = spawn_piped(
            &confined(&[]),
            &fixture,
            "kernel::leaves_a_program_scenario",
        );
        let stdin = broker.stdin.take();
        let stderr = broker.stderr.take().expect("piped stderr");
        // The worker reports only after its program says it is ready, so the
        // program ran. Do not check that it is still running: the worker
        // exits as soon as it reports, and the broker may already have
        // killed the group.
        ready_pids(&mut BufReader::new(broker.stdout.take().unwrap()));

        let status = broker.wait().expect("reap the broker");
        assert_eq!(status.code(), Some(3));
        assert_all_exit(stderr, "a program outlived its confined worker");
        drop(stdin);
    }

    /// The documented limit, and the control for the case above: a program
    /// that leaves the group with `setsid` survives its worker, so that test
    /// would see a survivor.
    #[test]
    fn a_program_that_leaves_the_group_outlives_its_worker() {
        let fixture = fixture();
        let mut broker = broker(
            &fixture,
            &confined(&["FSGATE_ESCAPE"]),
            "kernel::leaves_a_program_scenario",
        )
        .env("FSGATE_ESCAPE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fsgate-broker");
        let stdin = broker.stdin.take();
        let stderr = broker.stderr.take().expect("piped stderr");
        let (_, program) = ready_pids(&mut BufReader::new(broker.stdout.take().unwrap()));

        let status = broker.wait().expect("reap the broker");
        assert_eq!(status.code(), Some(3));
        // The broker killed the group before it exited, and this program
        // was not in it.
        assert!(
            is_running(program),
            "the program did not outlive its worker"
        );
        rustix::process::kill_process(program, Signal::KILL).unwrap();
        assert_all_exit(stderr, "the program survived SIGKILL");
        drop(stdin);
    }

    /// `--unconfined` is unchanged: its worker shares the broker's process
    /// group, so nothing is killed when it exits.
    #[test]
    fn an_unconfined_worker_leaves_its_program_running() {
        let fixture = fixture();
        let mut broker = spawn_piped(&unconfined(), &fixture, "kernel::leaves_a_program_scenario");
        let stdin = broker.stdin.take();
        let stderr = broker.stderr.take().expect("piped stderr");
        let (_, program) = ready_pids(&mut BufReader::new(broker.stdout.take().unwrap()));

        let status = broker.wait().expect("reap the broker");
        assert_eq!(status.code(), Some(3));
        assert!(
            is_running(program),
            "the broker killed an unconfined program"
        );
        rustix::process::kill_process(program, Signal::KILL).unwrap();
        assert_all_exit(stderr, "the program survived SIGKILL");
        drop(stdin);
    }

    /// RFC 0010: a broker stopped by `SIGTERM`, `SIGINT`, or `SIGHUP` kills
    /// its confined worker and the worker's programs, then dies by the same
    /// signal.
    #[test]
    fn stopping_the_broker_ends_a_confined_worker_and_its_programs() {
        use std::os::unix::process::ExitStatusExt;

        for signal in [Signal::TERM, Signal::INT, Signal::HUP] {
            let fixture = fixture();
            let mut broker =
                spawn_piped(&confined(&[]), &fixture, "kernel::keeps_a_program_scenario");
            let stdin = broker.stdin.take();
            let stderr = broker.stderr.take().expect("piped stderr");
            let (worker, program) = ready_pids(&mut BufReader::new(broker.stdout.take().unwrap()));
            assert!(is_running(worker) && is_running(program));

            rustix::process::kill_process(Pid::from_child(&broker), signal).unwrap();
            let status = broker.wait().expect("reap the broker");
            assert_eq!(status.signal(), Some(signal.as_raw()), "{signal:?}");
            assert_all_exit(
                stderr,
                "the worker or its program outlived a stopped broker",
            );
            drop(stdin);
        }
    }

    /// The broker blocks its stop signals for the thread that waits for
    /// them, and a mask survives `exec`. The worker must still be stoppable.
    /// It starts no program, so only its own exit closes the pipe.
    #[test]
    fn a_confined_worker_can_still_be_stopped_by_a_signal() {
        let fixture = fixture();
        let mut broker = spawn_piped(&confined(&[]), &fixture, "kernel::stoppable_scenario");
        let stdin = broker.stdin.take();
        let stderr = broker.stderr.take().expect("piped stderr");
        let (worker, _) = ready_pids(&mut BufReader::new(broker.stdout.take().unwrap()));

        rustix::process::kill_process(worker, Signal::TERM).unwrap();
        assert_all_exit(stderr, "SIGTERM did not stop the confined worker");
        // A worker ended by a signal has no exit code to pass on.
        assert_eq!(broker.wait().expect("reap the broker").code(), Some(1));
        drop(stdin);
    }

    /// Starts a program sharing this worker's standard input and error,
    /// waits until it runs, and returns its pid. It then waits on standard
    /// input, so it runs until the test closes that or it is killed.
    // Never waited for on purpose: the program is meant to outlive this
    // worker, and whoever ends it reaps it.
    #[allow(clippy::zombie_processes)]
    fn start_lingering_program() -> u32 {
        let mut program = Command::new(env::current_exe().unwrap())
            .args(["--exact", "kernel::lingering_scenario", "--nocapture"])
            .env("FSGATE_CHILD", "kernel::lingering_scenario")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(program.stdout.take().unwrap());
        let mut line = String::new();
        while !line.contains("program ready") {
            line.clear();
            assert_ne!(
                stdout.read_line(&mut line).unwrap(),
                0,
                "the program exited"
            );
        }
        // Dropping a `Child` leaves the process running.
        program.id()
    }

    #[test]
    fn lingering_scenario() {
        if !in_child("kernel::lingering_scenario") {
            return;
        }
        if env::var_os("FSGATE_ESCAPE").is_some() {
            rustix::process::setsid().unwrap();
        }
        println!("program ready");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }

    #[test]
    fn leaves_a_program_scenario() {
        if !in_child("kernel::leaves_a_program_scenario") {
            return;
        }
        let program = start_lingering_program();
        println!("worker ready {} {program}", std::process::id());
        std::process::exit(3);
    }

    #[test]
    fn stoppable_scenario() {
        if !in_child("kernel::stoppable_scenario") {
            return;
        }
        let worker = std::process::id();
        println!("worker ready {worker} {worker}");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }

    #[test]
    fn keeps_a_program_scenario() {
        if !in_child("kernel::keeps_a_program_scenario") {
            return;
        }
        let program = start_lingering_program();
        println!("worker ready {} {program}", std::process::id());
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
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

    /// `l` lets the worker list a `--direct` directory, and nothing more: its
    /// files stay unread.
    #[test]
    fn a_direct_path_can_be_listed_and_not_read() {
        let fixture = fixture();
        let open = fixture.outside.join("open");
        fs::create_dir(&open).unwrap();
        fs::write(open.join("runtime.txt"), b"runtime").unwrap();

        let mut flags = confined(&[]);
        flags.extend(["--direct".to_string(), format!("{}:l", open.display())]);
        let output = broker(&fixture, &flags, "kernel::listed_scenario")
            .output()
            .expect("run fsgate-broker");
        assert_ran(&output);
    }

    #[test]
    fn listed_scenario() {
        if !in_child("kernel::listed_scenario") {
            return;
        }
        let open = format!("{}/open", env::var("FSGATE_OUTSIDE").unwrap());
        let names: Vec<_> = fs::read_dir(&open)
            .expect("list the direct path")
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["runtime.txt"]);
        assert_eq!(
            fs::read(format!("{open}/runtime.txt")).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
    }

    /// A worker named without a `/` is looked up on `PATH` the way `execvp`
    /// would, past an entry where it is missing and one where it is not
    /// executable, and the image found is the one allowed to run.
    #[test]
    fn a_worker_named_without_a_path_is_found_on_path() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let fixture = fixture();
        let empty = fixture.root.join("empty");
        let plain = fixture.root.join("plain");
        let bin = fixture.root.join("bin");
        for dir in [&empty, &plain, &bin] {
            fs::create_dir(dir).unwrap();
        }
        let name = "fsgate-test-worker";
        fs::write(plain.join(name), b"not a program").unwrap();
        fs::set_permissions(plain.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        symlink(env::current_exe().unwrap(), bin.join(name)).unwrap();
        let path = env::join_paths([&empty, &plain, &bin]).unwrap();

        let command = broker(&fixture, &confined(&[]), "kernel::found_scenario");
        let args: Vec<_> = command.get_args().map(ToOwned::to_owned).collect();
        let worker = args.iter().position(|arg| arg == "--").unwrap() + 1;
        let mut named = Command::new(command.get_program());
        named
            .args(&args[..worker])
            .arg(name)
            .args(&args[worker + 1..])
            .env("PATH", path);
        for (key, value) in command.get_envs() {
            if let Some(value) = value {
                named.env(key, value);
            }
        }
        named.current_dir(&fixture.root);
        let output = named.output().expect("run fsgate-broker");
        assert_ran(&output);
    }

    #[test]
    fn found_scenario() {
        if !in_child("kernel::found_scenario") {
            return;
        }
        let mut gate = BrokerGate::from_inherited().expect("adopt the connection");
        assert!(
            gate.metadata(format!("{}/a.txt", env::var("FSGATE_GRANTED").unwrap()))
                .unwrap()
                .is_file
        );
    }

    /// Whether this kernel's Landlock refuses connects to pathname Unix
    /// sockets, which needs ABI 9 (Linux 7.1). Below that, RFC 0009's filter
    /// keeps a confined worker off them. This only asks; it confines nothing.
    fn landlock_refuses_unix_connects() -> bool {
        use landlock::{AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};

        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::ResolveUnix)
            .is_ok()
    }

    /// Runs the scenario this process is running again, as a program it
    /// starts, and fails unless that passes too. Confinement survives `exec`,
    /// so the program must see what its worker saw.
    fn assert_a_program_sees_the_same(scenario: &str) {
        if env::var_os("FSGATE_PROGRAM").is_some() {
            return;
        }
        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", scenario, "--nocapture"])
            .env("FSGATE_PROGRAM", "1")
            .output()
            .unwrap();
        assert_ran(&output);
    }

    /// Drains `listener` without waiting and counts the connections it had.
    fn accepted(listener: &UnixListener) -> usize {
        let mut count = 0;
        loop {
            match listener.accept() {
                Ok(_) => count += 1,
                Err(err) if err.kind() == ErrorKind::WouldBlock => return count,
                Err(err) => panic!("accept failed: {err}"),
            }
        }
    }

    /// Drains `socket` without waiting and counts the datagrams it had.
    fn received(socket: &UnixDatagram) -> usize {
        let mut count = 0;
        let mut buffer = [0; 8];
        loop {
            match socket.recv(&mut buffer) {
                Ok(_) => count += 1,
                Err(err) if err.kind() == ErrorKind::WouldBlock => return count,
                Err(err) => panic!("recv failed: {err}"),
            }
        }
    }

    /// RFC 0009: on every kernel, a confined worker and a program it starts
    /// reach no Unix socket outside the worker's confinement: not a stream
    /// socket by path or by abstract name, and not a datagram socket by
    /// path, from a socket of its own or from half of a datagram or raw
    /// pair. Below Linux
    /// 7.1 the filter refuses those sockets, and from 7.1 Landlock refuses
    /// the connects and sends. Nothing reaches the test's sockets. The
    /// unconfined control reaches all of them, so the test would notice.
    #[test]
    fn a_confined_worker_cannot_reach_a_unix_socket() {
        let denied = confined(&["FSGATE_EXPECT", "FSGATE_ABSTRACT"]);
        for (flags, expect) in [(denied, "denied"), (unconfined(), "allowed")] {
            let fixture = fixture();
            let stream = UnixListener::bind(fixture.outside.join("stream.sock")).unwrap();
            let name = format!("fsgate-test-{}-{expect}", std::process::id());
            let address = SocketAddr::from_abstract_name(&name).unwrap();
            let abstract_stream = UnixListener::bind_addr(&address).unwrap();
            let datagram = UnixDatagram::bind(fixture.outside.join("datagram.sock")).unwrap();
            for listener in [&stream, &abstract_stream] {
                listener.set_nonblocking(true).unwrap();
            }
            datagram.set_nonblocking(true).unwrap();

            let output = broker(&fixture, &flags, "kernel::unix_reach_scenario")
                .env("FSGATE_EXPECT", expect)
                .env("FSGATE_ABSTRACT", &name)
                .output()
                .expect("run fsgate-broker");
            assert_ran(&output);

            // The worker and its program each try once, and each tries a
            // datagram three ways.
            let (connections, datagrams) = if expect == "allowed" { (2, 6) } else { (0, 0) };
            assert_eq!(accepted(&stream), connections, "{expect}: by path");
            assert_eq!(
                accepted(&abstract_stream),
                connections,
                "{expect}: by abstract name"
            );
            assert_eq!(received(&datagram), datagrams, "{expect}: datagrams");
        }
    }

    #[test]
    fn unix_reach_scenario() {
        if !in_child("kernel::unix_reach_scenario") {
            return;
        }
        let outside = PathBuf::from(env::var("FSGATE_OUTSIDE").unwrap());
        let datagram = outside.join("datagram.sock");
        let address = SocketAddr::from_abstract_name(env::var("FSGATE_ABSTRACT").unwrap()).unwrap();
        // The kernel makes a Unix `SOCK_RAW` socket a datagram one.
        let raw_pair = || {
            use rustix::net::{AddressFamily, SocketFlags, SocketType};
            rustix::net::socketpair(
                AddressFamily::UNIX,
                SocketType::RAW,
                SocketFlags::CLOEXEC,
                None,
            )
            .map(|(end, _)| UnixDatagram::from(end))
            .map_err(std::io::Error::from)
        };
        let attempts = [
            (
                "a connect by path",
                UnixStream::connect(outside.join("stream.sock")).map(drop),
            ),
            (
                "a connect by abstract name",
                UnixStream::connect_addr(&address).map(drop),
            ),
            (
                "a datagram from a socket of its own",
                UnixDatagram::unbound()
                    .and_then(|socket| socket.send_to(b"x", &datagram).map(drop)),
            ),
            (
                "a datagram from half of a pair",
                UnixDatagram::pair()
                    .and_then(|(socket, _)| socket.send_to(b"x", &datagram).map(drop)),
            ),
            (
                "a datagram from half of a raw pair",
                raw_pair().and_then(|socket| socket.send_to(b"x", &datagram).map(drop)),
            ),
        ];
        for (what, result) in attempts {
            if expect_denied() {
                // `EACCES` from the filter or from Landlock's path rules,
                // `EPERM` from Landlock's abstract socket scope.
                let err = result.expect_err(what);
                assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{what}: {err}");
            } else {
                result.expect(what);
            }
        }
        assert_a_program_sees_the_same("kernel::unix_reach_scenario");
    }

    /// RFC 0009: below Linux 7.1 a confined worker and a program it starts
    /// cannot create a Unix socket or a datagram pair, `io_uring` answers as
    /// if it were missing, and an x32 call kills the process. Stream and
    /// seqpacket pairs, network sockets, and the broker connection still
    /// work. From 7.1 Landlock refuses connects instead, so the filter is not
    /// installed and all of these work, as they do for the unconfined
    /// control.
    #[test]
    fn below_linux_7_1_a_confined_worker_cannot_create_a_unix_socket() {
        let filtered = if landlock_refuses_unix_connects() {
            "unfiltered"
        } else {
            "filtered"
        };
        for (flags, expect) in [
            (confined(&["FSGATE_EXPECT"]), filtered),
            (unconfined(), "unfiltered"),
        ] {
            let fixture = fixture();
            let output = broker(&fixture, &flags, "kernel::unix_create_scenario")
                .env("FSGATE_EXPECT", expect)
                .output()
                .expect("run fsgate-broker");
            assert_ran(&output);
        }
    }

    #[test]
    fn unix_create_scenario() {
        use rustix::io::Errno;
        use rustix::net::{AddressFamily, SocketFlags, SocketType};

        if !in_child("kernel::unix_create_scenario") {
            return;
        }
        let filtered = env::var("FSGATE_EXPECT").unwrap() == "filtered";
        let socket = |kind, flags| {
            rustix::net::socket_with(AddressFamily::UNIX, kind, flags, None).map(drop)
        };
        let pair = |kind| {
            let flags = SocketFlags::CLOEXEC | SocketFlags::NONBLOCK;
            rustix::net::socketpair(AddressFamily::UNIX, kind, flags, None).map(drop)
        };
        // The flags ride in the type argument, which the filter masks.
        let refused = [
            (
                "a stream socket",
                socket(SocketType::STREAM, SocketFlags::empty()),
            ),
            (
                "a datagram socket",
                socket(SocketType::DGRAM, SocketFlags::CLOEXEC),
            ),
            (
                "a seqpacket socket",
                socket(SocketType::SEQPACKET, SocketFlags::NONBLOCK),
            ),
            ("a datagram pair", pair(SocketType::DGRAM)),
            // The kernel makes a Unix `SOCK_RAW` socket a datagram one.
            ("a raw pair", pair(SocketType::RAW)),
        ];
        for (what, result) in refused {
            let expected = if filtered { Err(Errno::ACCESS) } else { Ok(()) };
            assert_eq!(result, expected, "{what}");
        }
        if !filtered {
            let (end, _) = rustix::net::socketpair(
                AddressFamily::UNIX,
                SocketType::RAW,
                SocketFlags::CLOEXEC,
                None,
            )
            .expect("a raw pair");
            assert_eq!(
                rustix::net::sockopt::socket_type(&end),
                Ok(SocketType::DGRAM),
                "a raw pair is a datagram pair"
            );
        }
        pair(SocketType::STREAM).expect("a stream pair");
        pair(SocketType::SEQPACKET).expect("a seqpacket pair");
        rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).expect("a TCP socket");

        for (call, errno) in raw_calls::io_uring_errnos() {
            if filtered {
                assert_eq!(errno, libc::ENOSYS, "{call}");
            } else {
                assert_ne!(errno, libc::ENOSYS, "{call}: this kernel has no io_uring");
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            use std::os::unix::process::ExitStatusExt;

            let status = Command::new(env::current_exe().unwrap())
                .args(["--exact", "kernel::x32_call_scenario", "--nocapture"])
                .env("FSGATE_CHILD", "kernel::x32_call_scenario")
                .stdout(Stdio::null())
                .status()
                .unwrap();
            if filtered {
                assert_eq!(status.signal(), Some(libc::SIGSYS), "{status:?}");
            } else {
                assert!(status.success(), "{status:?}");
            }
        }

        if env::var_os("FSGATE_PROGRAM").is_none() {
            let path = format!("{}/a.txt", env::var("FSGATE_GRANTED").unwrap());
            let mut gate = BrokerGate::from_inherited().expect("adopt the connection");
            let mut content = String::new();
            gate.open(&path)
                .expect("the broker serves its grant")
                .read_to_string(&mut content)
                .unwrap();
            assert_eq!(content, "inside");
        }
        assert_a_program_sees_the_same("kernel::unix_create_scenario");
    }

    /// Makes one x32 call. The filter kills a process for it; without the
    /// filter it returns, with a process ID or `ENOSYS`.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_call_scenario() {
        if !in_child("kernel::x32_call_scenario") {
            return;
        }
        raw_calls::x32_getpid();
    }

    /// The system calls RFC 0009's tests make that neither `std` nor
    /// `rustix` offers safely (RFC 0009, decision 2).
    ///
    /// # Safety contract
    ///
    /// - Each `io_uring` call gets arguments a kernel refuses before it reads
    ///   or writes this process's memory or creates anything:
    ///   `io_uring_setup` gets a null `params`, so it fails copying it with
    ///   `EFAULT`, or earlier with `EPERM` where `io_uring` is disabled.
    ///   `io_uring_enter` gets flags and `io_uring_register` an opcode that
    ///   no kernel defines, so each fails with `EINVAL` first. Under the
    ///   filter, none reaches the kernel's implementation at all.
    /// - The x32 `getpid` takes no arguments, and reads and writes no memory.
    #[allow(unsafe_code)]
    mod raw_calls {
        use std::io;
        use std::ptr;

        fn errno(result: libc::c_long) -> i32 {
            assert_eq!(result, -1, "the call succeeded");
            io::Error::last_os_error().raw_os_error().unwrap()
        }

        /// The errno each `io_uring` call fails with.
        pub(super) fn io_uring_errnos() -> [(&'static str, i32); 3] {
            let fd: libc::c_int = -1;
            let entries: libc::c_uint = 1;
            let none: libc::c_uint = 0;
            let no_size: libc::size_t = 0;
            let undefined = libc::c_uint::MAX;
            let null = ptr::null_mut::<libc::c_void>();
            // SAFETY: a null `params`. See the module contract.
            let setup = unsafe { libc::syscall(libc::SYS_io_uring_setup, entries, null) };
            // SAFETY: undefined flags and a null argument. See the module
            // contract.
            let enter = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_enter,
                    fd,
                    none,
                    none,
                    undefined,
                    null,
                    no_size,
                )
            };
            // SAFETY: an undefined opcode and a null argument. See the module
            // contract.
            let register =
                unsafe { libc::syscall(libc::SYS_io_uring_register, fd, undefined, null, none) };
            [
                ("io_uring_setup", errno(setup)),
                ("io_uring_enter", errno(enter)),
                ("io_uring_register", errno(register)),
            ]
        }

        /// `getpid` through the x32 call table.
        #[cfg(target_arch = "x86_64")]
        pub(super) fn x32_getpid() -> libc::c_long {
            const X32_SYSCALL_BIT: libc::c_long = 0x4000_0000;
            // SAFETY: no arguments. See the module contract.
            unsafe { libc::syscall(X32_SYSCALL_BIT | libc::SYS_getpid) }
        }
    }
}
