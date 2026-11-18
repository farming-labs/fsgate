//! RFC 0015: real glibc programs, explicit runtime grants, and denied effects.
#![cfg(all(
    feature = "experimental-intercept",
    target_os = "linux",
    target_arch = "x86_64"
))]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use fsgate::intercept::Launch;
use fsgate::{AuditEvent, AuditOp, AuditSink, Gate, Rights};

struct Fixture {
    root: tempfile::TempDir,
    data: PathBuf,
    worker: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("input"), b"hello runtime\n").unwrap();
        let worker = root.path().join("dynamic-worker");
        let status = Command::new("cc")
            .args(["-O2", "-Wall", "-Werror", "-o"])
            .arg(&worker)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dynamic-worker.c"))
            .status()
            .expect("compile the glibc fixture");
        assert!(status.success());
        let interpreter = Launch::new(&worker)
            .interpreter()
            .unwrap()
            .expect("dynamic fixture");
        assert!(
            interpreter.ends_with("ld-linux-x86-64.so.2"),
            "the dynamic tests require glibc: {interpreter:?}"
        );
        Self { root, data, worker }
    }

    fn gate(&self) -> Gate {
        let mut gate = Gate::new();
        gate.grant(&self.data, Rights::READ).unwrap();
        gate
    }

    fn launch(&self, op: &str, path: &Path) -> Launch {
        let mut launch = configured(&self.worker);
        launch.arg(op).arg(path);
        launch
    }
}

fn gnu_command(name: &str) -> PathBuf {
    for path in [format!("/usr/bin/{name}"), format!("/usr/bin/gnu{name}")] {
        let is_gnu = Command::new(&path)
            .env_clear()
            .arg("--version")
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("(GNU coreutils)")
            });
        if is_gnu {
            return PathBuf::from(path);
        }
    }
    panic!(
        "GNU {name} is required; install coreutils (gnu-coreutils on Ubuntu with uutils) in /usr/bin"
    );
}

fn runtime_paths(executable: &Path) -> Vec<PathBuf> {
    let loader = Launch::new(executable)
        .interpreter()
        .unwrap()
        .expect("a dynamic glibc executable");
    let mut paths = vec![loader];
    // Explicit test authority for Debian/Ubuntu layouts used by the kernel jobs.
    paths.extend(
        [
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/etc/ld.so.cache",
        ]
        .into_iter()
        .map(PathBuf::from)
        .filter(|path| path.exists()),
    );
    paths
}

fn configured(executable: &Path) -> Launch {
    let mut launch = Launch::new(executable);
    for path in runtime_paths(executable) {
        launch.runtime(path);
    }
    launch
}

#[test]
fn ordinary_glibc_commands_match_their_unconfined_output() {
    let fixture = Fixture::new();
    let input = fixture.data.join("input");
    for name in ["cat", "wc", "sha256sum"] {
        let executable = gnu_command(name);
        let control = Command::new(&executable)
            .env_clear()
            .arg(&input)
            .output()
            .unwrap();
        assert!(
            control.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&control.stderr)
        );
        let outcome = configured(&executable)
            .arg(&input)
            .run(fixture.gate())
            .unwrap();
        assert!(
            outcome.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        assert_eq!(outcome.stdout, control.stdout, "{name}");
        let mut cli = Command::new(env!("CARGO_BIN_EXE_fsgate-broker"));
        cli.args([
            "--experimental-intercept",
            "--grant",
            &format!("{}:r", fixture.data.display()),
        ]);
        for path in runtime_paths(&executable) {
            cli.arg("--runtime").arg(path);
        }
        let outcome = cli
            .args(["--apply", "--"])
            .arg(&executable)
            .arg(&input)
            .output()
            .unwrap();
        assert!(
            outcome.status.success(),
            "CLI {name}: {}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        assert_eq!(outcome.stdout, control.stdout, "CLI {name}");
    }
}

#[test]
fn metadata_obeys_descriptor_identity_and_destination_permissions() {
    let fixture = Fixture::new();
    let (sender, events) = mpsc::channel();
    let mut gate = fixture.gate();
    gate.set_audit_sink(Arc::new(Notify(Mutex::new(sender))));
    let outcome = fixture
        .launch("metadata", &fixture.data.join("input"))
        .run(gate)
        .unwrap();
    assert!(
        outcome.status.success(),
        "{:?}: {:?}",
        outcome.status,
        outcome.stderr
    );
    assert_eq!(outcome.stdout, b"ok\n");
    let events: Vec<_> = events.try_iter().collect();
    assert!(events.iter().any(|event| event.op == AuditOp::Metadata
        && event.path.as_deref() == Some(&fixture.data.join("input"))
        && event.syscall == Some("newfstatat")
        && event.notification.is_some()));
    assert!(
        events
            .iter()
            .any(|event| event.op == AuditOp::Metadata && event.errno == Some(libc::EFAULT))
    );
    let mut ids: Vec<_> = events
        .iter()
        .filter_map(|event| event.notification)
        .collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count, "each request is audited once");
}

#[test]
fn runtime_profile_refuses_descendants_and_write_side_effects() {
    let fixture = Fixture::new();
    let input = fixture.data.join("input");
    let outcome = fixture
        .launch("descendants", &input)
        .run(fixture.gate())
        .unwrap();
    assert!(outcome.status.success(), "{:?}", outcome.stderr);
    assert_eq!(outcome.stdout, b"ok\n");
    for path in [
        &input,
        &fixture.data.join("new"),
        &fixture.root.path().join("outside"),
    ] {
        let outcome = fixture.launch("write", path).run(fixture.gate()).unwrap();
        assert!(outcome.status.success(), "{:?}", outcome.stderr);
    }
    assert_eq!(fs::read(&input).unwrap(), b"hello runtime\n");
    assert!(!fixture.data.join("new").exists());
    assert!(!fixture.root.path().join("outside").exists());
}

#[test]
fn loader_grants_are_required_and_data_overlap_is_refused_before_start() {
    let fixture = Fixture::new();
    assert!(
        Launch::new(&fixture.worker)
            .check()
            .unwrap_err()
            .to_string()
            .contains("runtime grant")
    );
    let mut launch = configured(&fixture.worker);
    launch.runtime(&fixture.data);
    assert!(
        launch
            .check_with(&fixture.gate())
            .unwrap_err()
            .to_string()
            .contains("overlaps")
    );
    assert!(launch.spawn(fixture.gate()).is_err());
}

struct Notify(Mutex<mpsc::Sender<AuditEvent>>);
impl AuditSink for Notify {
    fn event(&self, event: &AuditEvent) {
        let _ = self.0.lock().unwrap().send(event.clone());
    }
}

#[test]
fn runtime_revoke_preserves_delivered_files_and_denies_later_opens() {
    let fixture = Fixture::new();
    let file = fixture.root.path().join("runtime-file");
    fs::write(&file, b"hello runtime\n").unwrap();
    let (sender, events) = mpsc::channel();
    let mut gate = fixture.gate();
    gate.set_audit_sink(Arc::new(Notify(Mutex::new(sender))));
    let mut running = fixture
        .launch("revoke", &file)
        .runtime(&file)
        .spawn(gate)
        .unwrap();
    let mut stdin = running.take_stdin().unwrap();
    loop {
        let event = events
            .recv_timeout(Duration::from_secs(10))
            .expect("runtime open event");
        if event.op == AuditOp::RuntimeOpen && event.path.as_deref() == Some(&file) {
            assert!(event.notification.is_some());
            assert_eq!(event.syscall, Some("openat"));
            break;
        }
    }
    running.revoke_runtime(&file).unwrap();
    stdin.write_all(b"x").unwrap();
    drop(stdin);
    let outcome = running.wait().unwrap();
    assert!(outcome.status.success(), "{:?}", outcome.stderr);
    assert_eq!(outcome.stdout, b"ok\n");
    assert!(
        events
            .try_iter()
            .any(|event| event.op == AuditOp::RuntimeRevoke)
    );
    assert_eq!(fs::read(&file).unwrap(), b"hello runtime\n");
}

#[test]
fn dropping_a_runtime_worker_kills_and_reaps_it() {
    let fixture = Fixture::new();
    let input = fixture.data.join("input");
    let (sender, events) = mpsc::channel();
    let mut gate = fixture.gate();
    gate.set_audit_sink(Arc::new(Notify(Mutex::new(sender))));
    let running = fixture.launch("revoke", &input).spawn(gate).unwrap();
    let pid = running.id();
    loop {
        let event = events.recv_timeout(Duration::from_secs(10)).unwrap();
        if event.op == AuditOp::Open && event.path.as_deref() == Some(&input) {
            break;
        }
    }
    drop(running);
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[test]
fn ungranted_data_is_not_delivered_to_a_dynamic_command() {
    let fixture = Fixture::new();
    let outside = fixture.root.path().join("secret");
    fs::write(&outside, b"private content").unwrap();
    let outcome = configured(&gnu_command("cat"))
        .arg(&outside)
        .run(fixture.gate())
        .unwrap();
    assert!(!outcome.status.success());
    assert!(outcome.stdout.is_empty());
    assert_eq!(fs::read(&outside).unwrap(), b"private content");
}

#[test]
fn a_parent_that_discards_children_cannot_start_the_runtime_profile() {
    let fixture = Fixture::new();
    let executable = gnu_command("cat");
    let mut command = Command::new(&fixture.worker);
    command
        .arg("ignore-sigchld")
        .arg(env!("CARGO_BIN_EXE_fsgate-broker"))
        .args([
            "--experimental-intercept",
            "--grant",
            &format!("{}:r", fixture.data.display()),
        ]);
    for path in runtime_paths(&executable) {
        command.arg("--runtime").arg(path);
    }
    let outcome = command
        .args(["--apply", "--"])
        .arg(executable)
        .arg(fixture.data.join("input"))
        .output()
        .unwrap();
    assert_eq!(outcome.status.code(), Some(3));
    assert!(outcome.stdout.is_empty());
    assert!(String::from_utf8_lossy(&outcome.stderr).contains("SIGCHLD"));
}
