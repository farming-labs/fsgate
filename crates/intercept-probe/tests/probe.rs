//! RFC 0004 step 1 on a real kernel: a static worker that does not link
//! fsgate opens files with ordinary libc calls and raw syscalls, and only
//! the supervisor's answers decide what it gets. Denials assert the errno
//! the worker saw and the absence of the side effect on the real
//! filesystem.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use fsgate::{AuditDecision, AuditEvent, AuditOp, AuditReason, AuditSink, Gate, Rights};
use intercept_probe::{Decision, Fault, Outcome, run};
use tempfile::TempDir;

const EACCES: i32 = 13;
const ENOSYS: i32 = 38;
const EISDIR: i32 = 21;
const ELOOP: i32 = 40;
const EOPNOTSUPP: i32 = 95;
const ECANCELED: i32 = 125;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// The worker fixture, compiled once per test run with `cc -static`.
fn worker() -> &'static Path {
    static WORKER: OnceLock<PathBuf> = OnceLock::new();
    WORKER.get_or_init(|| {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/worker.c");
        let output = Path::new(env!("CARGO_TARGET_TMPDIR")).join("intercept-probe-worker");
        let status = Command::new("cc")
            .args(["-static", "-O2", "-Wall", "-Werror", "-o"])
            .arg(&output)
            .arg(&source)
            .status()
            .expect("run cc; the probe tests need a C compiler and static libc (libc6-dev)");
        assert!(
            status.success(),
            "cc -static failed for {}",
            source.display()
        );
        output
    })
}

struct Dirs {
    _root: TempDir,
    granted: PathBuf,
    outside: PathBuf,
}

impl Dirs {
    fn new() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let granted = root.path().join("granted");
        let outside = root.path().join("outside");
        fs::create_dir(&granted).unwrap();
        fs::create_dir(granted.join("sub")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(granted.join("a.txt"), b"inside").unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        Dirs {
            _root: root,
            granted,
            outside,
        }
    }

    fn granted(&self, name: &str) -> String {
        self.granted.join(name).to_str().unwrap().to_owned()
    }

    fn outside(&self, name: &str) -> String {
        self.outside.join(name).to_str().unwrap().to_owned()
    }

    fn gate(&self, rights: Rights) -> Gate {
        let mut gate = Gate::new();
        gate.grant(&self.granted, rights).unwrap();
        gate
    }
}

fn probe(gate: Gate, args: &[&str]) -> Outcome {
    run(worker(), args, gate, Fault::None).expect("probe run")
}

fn stdout(outcome: &Outcome) -> String {
    String::from_utf8_lossy(&outcome.stdout).into_owned()
}

fn decision(syscall: i64, path: &str, errno: Option<i32>) -> Decision {
    Decision {
        syscall,
        path: Some(path.to_owned()),
        errno,
    }
}

#[derive(Default)]
struct Capture(Mutex<Vec<AuditEvent>>);

impl AuditSink for Capture {
    fn event(&self, event: &AuditEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[test]
fn granted_file_is_delivered_through_the_supervisor() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");

    let outcome = probe(dirs.gate(Rights::READ), &["read", &path]);

    assert_eq!(stdout(&outcome), "inside");
    assert!(outcome.status.success());
    assert_eq!(outcome.decisions, [decision(libc::SYS_openat, &path, None)]);
}

#[test]
fn ungranted_path_is_denied_and_audited_by_the_gate() {
    let dirs = Dirs::new();
    let secret = dirs.outside("secret.txt");
    let sink = Arc::new(Capture::default());
    let mut gate = dirs.gate(Rights::READ);
    gate.set_audit_sink(sink.clone());

    let outcome = probe(gate, &["read", &secret]);

    assert_eq!(stdout(&outcome), format!("errno={EACCES}\n"));
    assert_eq!(
        outcome.decisions,
        [decision(libc::SYS_openat, &secret, Some(EACCES))]
    );
    let events = sink.0.lock().unwrap();
    assert!(
        events.iter().any(|event| event.op == AuditOp::Open
            && event.decision == AuditDecision::Deny
            && event.reason == AuditReason::NoGrant
            && event.path.as_deref() == Some(Path::new(&secret))),
        "no open/deny/no_grant event for {secret}: {events:?}"
    );
}

#[test]
fn write_and_create_requests_are_refused_and_change_nothing() {
    let dirs = Dirs::new();
    let existing = dirs.granted("a.txt");
    let fresh = dirs.granted("new.txt");
    // The profile is read-only even when the gate would allow writes.
    let rights = Rights::READ | Rights::WRITE | Rights::CREATE;

    let truncate = probe(dirs.gate(rights), &["write", &existing]);
    let create = probe(dirs.gate(rights), &["write", &fresh]);

    assert_eq!(stdout(&truncate), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(stdout(&create), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(fs::read(&existing).unwrap(), b"inside");
    assert!(!Path::new(&fresh).exists());
}

#[test]
fn unmediated_creat_is_stopped_by_landlock() {
    let dirs = Dirs::new();
    let fresh = dirs.granted("new.txt");
    let rights = Rights::READ | Rights::WRITE | Rights::CREATE;

    let outcome = probe(dirs.gate(rights), &["creat", &fresh]);

    // `creat` is not a notified syscall, so the supervisor never sees it;
    // the worker's Landlock ruleset refuses it in the kernel.
    assert_eq!(stdout(&outcome), format!("errno={EACCES}\n"));
    assert!(outcome.decisions.is_empty());
    assert!(!Path::new(&fresh).exists());
}

#[test]
fn relative_and_dot_dot_paths_are_refused_before_authorization() {
    let dirs = Dirs::new();
    let escape = format!("{}/../outside/secret.txt", dirs.granted.display());

    let relative = probe(dirs.gate(Rights::READ), &["read", "a.txt"]);
    let dotdot = probe(dirs.gate(Rights::READ), &["read", &escape]);

    assert_eq!(stdout(&relative), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(stdout(&dotdot), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(
        dotdot.decisions,
        [decision(libc::SYS_openat, &escape, Some(EOPNOTSUPP))]
    );
}

#[test]
fn directories_are_refused_with_eisdir() {
    let dirs = Dirs::new();
    let sub = dirs.granted("sub");

    let outcome = probe(dirs.gate(Rights::READ | Rights::LIST), &["read", &sub]);

    assert_eq!(stdout(&outcome), format!("errno={EISDIR}\n"));
}

#[test]
fn openat2_accepts_only_the_resolve_flags_the_strict_open_enforces() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");
    let enforced = (RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS).to_string();
    let beneath = RESOLVE_BENEATH.to_string();

    let plain = probe(dirs.gate(Rights::READ), &["openat2", &path, "0"]);
    let strict = probe(dirs.gate(Rights::READ), &["openat2", &path, &enforced]);
    let other = probe(dirs.gate(Rights::READ), &["openat2", &path, &beneath]);

    assert_eq!(stdout(&plain), "inside");
    assert_eq!(plain.decisions, [decision(libc::SYS_openat2, &path, None)]);
    assert_eq!(stdout(&strict), "inside");
    // Not dropped: a flag the supervisor does not enforce is refused.
    assert_eq!(stdout(&other), format!("errno={EOPNOTSUPP}\n"));
}

#[test]
fn symlinks_are_refused_with_eloop_even_inside_the_grant() {
    let dirs = Dirs::new();
    let link = dirs.granted("link");
    std::os::unix::fs::symlink("a.txt", &link).unwrap();

    let outcome = probe(dirs.gate(Rights::READ), &["read", &link]);

    assert_eq!(stdout(&outcome), format!("errno={ELOOP}\n"));
    assert_eq!(
        outcome.decisions,
        [decision(libc::SYS_openat, &link, Some(ELOOP))]
    );
}

#[test]
fn a_fifo_is_refused_without_blocking_the_supervisor() {
    let dirs = Dirs::new();
    let fifo = dirs.granted("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();

    // A plain read-only open of a FIFO with no writer would hang here.
    let outcome = probe(dirs.gate(Rights::READ), &["read", &fifo]);

    assert_eq!(stdout(&outcome), format!("errno={EOPNOTSUPP}\n"));
}

#[test]
fn delivered_descriptors_keep_the_callers_cloexec_choice() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");

    let outcome = probe(dirs.gate(Rights::READ), &["cloexec", &path]);

    assert_eq!(stdout(&outcome), "plain=0 marked=1\n");
}

#[test]
fn worker_starts_with_only_stdio_open() {
    let dirs = Dirs::new();

    let outcome = probe(dirs.gate(Rights::READ), &["fds"]);

    assert_eq!(stdout(&outcome), "done\n");
}

#[test]
fn a_closed_listener_fails_later_opens_with_enosys() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");

    let outcome = run(
        worker(),
        &["read", &path],
        dirs.gate(Rights::READ),
        Fault::CloseListener,
    )
    .expect("probe run");

    // No supervisor, no open: the kernel fails the notified call.
    assert_eq!(stdout(&outcome), format!("errno={ENOSYS}\n"));
    assert!(outcome.decisions.is_empty());
}

#[test]
fn an_aborted_startup_never_executes_the_worker() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");

    let err = run(
        worker(),
        &["read", &path],
        dirs.gate(Rights::READ),
        Fault::AbortStartup,
    )
    .expect_err("startup must fail before exec");

    assert_eq!(err.raw_os_error(), Some(ECANCELED), "{err}");
}

#[test]
fn an_image_that_needs_an_interpreter_cannot_start() {
    let dirs = Dirs::new();
    // A dynamically linked system binary: exec needs the loader, which the
    // worker's Landlock ruleset does not allow it to execute.
    let dynamic = Path::new("/bin/true");
    assert!(
        dynamic.exists(),
        "the test needs a dynamically linked /bin/true"
    );

    let err = run(dynamic, &[], dirs.gate(Rights::READ), Fault::None)
        .expect_err("a dynamic image must not start");

    assert_eq!(err.raw_os_error(), Some(EACCES), "{err}");
}
