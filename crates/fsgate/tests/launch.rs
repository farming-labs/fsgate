//! `intercept::Launch` on a real kernel: a static worker that does not link
//! fsgate opens files with ordinary libc calls and raw syscalls, and only
//! the supervisor's answers decide what it gets. Denials assert the errno
//! the worker saw, the audit events the gate emitted, and the absence of
//! the side effect on the real filesystem.

#![cfg(all(
    feature = "experimental-intercept",
    target_os = "linux",
    target_arch = "x86_64"
))]

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use fsgate::intercept::{Launch, Outcome};
use fsgate::{AuditDecision, AuditEvent, AuditOp, AuditReason, AuditSink, Gate, Rights};
use tempfile::TempDir;

const EACCES: i32 = 13;
const EISDIR: i32 = 21;
const ELOOP: i32 = 40;
const EOPNOTSUPP: i32 = 95;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// The worker fixture, compiled once per test run with `cc -static`.
fn worker() -> &'static Path {
    static WORKER: OnceLock<PathBuf> = OnceLock::new();
    WORKER.get_or_init(|| {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/worker.c");
        let output = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fsgate-intercept-worker");
        let status = Command::new("cc")
            .args(["-static", "-pthread", "-O2", "-Wall", "-Werror", "-o"])
            .arg(&output)
            .arg(&source)
            .status()
            .expect("run cc; the launcher tests need a C compiler and static libc (libc6-dev)");
        assert!(
            status.success(),
            "cc -static failed for {}",
            source.display()
        );
        output
    })
}

struct Dirs {
    root: TempDir,
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
            root,
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

#[derive(Default)]
struct Capture(Mutex<Vec<AuditEvent>>);

impl AuditSink for Capture {
    fn event(&self, event: &AuditEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

/// The worker's output and every audit event the gate emitted while it
/// ran. The sink is installed after the grant, so only decisions appear.
struct Run {
    outcome: Outcome,
    events: Vec<AuditEvent>,
}

fn run_worker(mut gate: Gate, args: &[&str]) -> Run {
    let sink = Arc::new(Capture::default());
    gate.set_audit_sink(sink.clone());
    let outcome = Launch::new(worker()).args(args).run(gate).expect("launch");
    let events = sink.0.lock().unwrap().clone();
    Run { outcome, events }
}

fn stdout(run: &Run) -> String {
    String::from_utf8_lossy(&run.outcome.stdout).into_owned()
}

/// One audit event, reduced to what these tests compare.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    syscall: Option<&'static str>,
    path: Option<PathBuf>,
    decision: AuditDecision,
    reason: AuditReason,
    errno: Option<i32>,
}

fn seen(run: &Run) -> Vec<Seen> {
    run.events
        .iter()
        .map(|event| Seen {
            syscall: event.syscall,
            path: event.path.clone(),
            decision: event.decision,
            reason: event.reason,
            errno: event.errno,
        })
        .collect()
}

fn allowed(syscall: &'static str, path: &str, errno: Option<i32>) -> Seen {
    Seen {
        syscall: Some(syscall),
        path: Some(PathBuf::from(path)),
        decision: AuditDecision::Allow,
        reason: AuditReason::Ok,
        errno,
    }
}

fn denied(syscall: &'static str, path: &str, reason: AuditReason) -> Seen {
    Seen {
        syscall: Some(syscall),
        path: Some(PathBuf::from(path)),
        decision: AuditDecision::Deny,
        reason,
        errno: None,
    }
}

#[test]
fn granted_file_is_delivered_through_the_supervisor() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");

    let outcome = run_worker(dirs.gate(Rights::READ), &["read", &path]);

    assert_eq!(stdout(&outcome), "inside");
    assert!(outcome.outcome.status.success());
    assert_eq!(seen(&outcome), [allowed("openat", &path, None)]);
}

#[test]
fn ungranted_path_is_denied_and_audited_by_the_gate() {
    let dirs = Dirs::new();
    let secret = dirs.outside("secret.txt");
    let outcome = run_worker(dirs.gate(Rights::READ), &["read", &secret]);

    assert_eq!(stdout(&outcome), format!("errno={EACCES}\n"));
    assert_eq!(
        seen(&outcome),
        [denied("openat", &secret, AuditReason::NoGrant)]
    );
    let events = &outcome.events;
    // The sink is installed after the grant: exactly one decision, for the
    // notified request.
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(
        (event.op, event.decision, event.reason),
        (AuditOp::Open, AuditDecision::Deny, AuditReason::NoGrant)
    );
    assert_eq!(event.path.as_deref(), Some(Path::new(&secret)));
    assert_eq!(event.syscall, Some("openat"));
    assert!(event.notification.is_some());
}

#[test]
fn a_request_refused_before_grant_selection_is_audited() {
    let dirs = Dirs::new();
    let existing = dirs.granted("a.txt");
    let gate = dirs.gate(Rights::READ | Rights::WRITE | Rights::CREATE);
    let outcome = run_worker(gate, &["write", &existing]);

    assert_eq!(stdout(&outcome), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(fs::read(&existing).unwrap(), b"inside");
    let events = &outcome.events;
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(
        (event.op, event.decision, event.reason),
        (
            AuditOp::Open,
            AuditDecision::Deny,
            AuditReason::UnsupportedInput
        )
    );
    assert_eq!(event.path.as_deref(), Some(Path::new(&existing)));
    assert_eq!((event.grant, event.syscall), (None, Some("openat")));
}

#[test]
fn write_and_create_requests_are_refused_and_change_nothing() {
    let dirs = Dirs::new();
    let existing = dirs.granted("a.txt");
    let fresh = dirs.granted("new.txt");
    // The profile is read-only even when the gate would allow writes.
    let rights = Rights::READ | Rights::WRITE | Rights::CREATE;

    let truncate = run_worker(dirs.gate(rights), &["write", &existing]);
    let create = run_worker(dirs.gate(rights), &["write", &fresh]);

    assert_eq!(stdout(&truncate), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(stdout(&create), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(fs::read(&existing).unwrap(), b"inside");
    assert!(!Path::new(&fresh).exists());
}

#[test]
fn unmediated_creat_is_refused_by_the_allowlist() {
    let dirs = Dirs::new();
    let fresh = dirs.granted("new.txt");
    let rights = Rights::READ | Rights::WRITE | Rights::CREATE;

    let outcome = run_worker(dirs.gate(rights), &["creat", &fresh]);

    // `creat` is not a notified syscall, so the supervisor never sees it;
    // the allowlist refuses it, with Landlock behind it.
    assert_eq!(stdout(&outcome), format!("errno={EOPNOTSUPP}\n"));
    assert!(outcome.events.is_empty());
    assert!(!Path::new(&fresh).exists());
}

#[test]
fn execve_io_uring_sockets_prctl_and_namespaces_are_refused() {
    let dirs = Dirs::new();
    let tool = dirs.granted("a.txt");

    for args in [
        vec!["exec", "/bin/true"],
        vec!["uring"],
        vec!["socket"],
        vec!["prctl"],
        vec!["clone-ns"],
        vec!["creat", tool.as_str()],
    ] {
        let outcome = run_worker(dirs.gate(Rights::READ), &args);
        assert_eq!(
            stdout(&outcome),
            format!("errno={EOPNOTSUPP}\n"),
            "{args:?}"
        );
        assert!(outcome.events.is_empty(), "{args:?}");
    }
    assert_eq!(fs::read(&tool).unwrap(), b"inside");
}

/// An executable copy of the worker inside the grant, so that only Landlock,
/// not file permissions, can refuse to execute it.
fn executable_in_grant(dirs: &Dirs) -> String {
    let tool = dirs.granted("tool");
    let copied = Command::new("cp")
        .arg(worker())
        .arg(&tool)
        .status()
        .unwrap();
    assert!(copied.success());
    tool
}

#[test]
fn a_delivered_file_moved_to_the_reserved_number_cannot_be_executed() {
    let dirs = Dirs::new();
    let tool = executable_in_grant(&dirs);

    let outcome = run_worker(dirs.gate(Rights::READ), &["execfd", &tool]);

    // The allowlist passes `execveat(1000, "", AT_EMPTY_PATH)`; Landlock
    // refuses because the descriptor is not the checked image.
    assert_eq!(stdout(&outcome), format!("errno={EACCES}\n"));
    assert_eq!(seen(&outcome), [allowed("openat", &tool, None)]);
}

#[test]
fn an_absolute_path_cannot_be_executed_through_the_reserved_number() {
    let dirs = Dirs::new();
    let tool = executable_in_grant(&dirs);

    let outcome = run_worker(dirs.gate(Rights::READ), &["execat", &tool]);

    assert_eq!(stdout(&outcome), format!("errno={EACCES}\n"));
    assert!(outcome.events.is_empty());
}

#[test]
fn forked_children_stay_mediated() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");
    let secret = dirs.outside("secret.txt");

    let granted = run_worker(dirs.gate(Rights::READ), &["fork-read", &path]);
    let denied = run_worker(dirs.gate(Rights::READ), &["fork-read", &secret]);

    assert_eq!(stdout(&granted), "inside");
    assert_eq!(seen(&granted), [allowed("openat", &path, None)]);
    assert_eq!(stdout(&denied), format!("errno={EACCES}\n"));
}

#[test]
fn threads_stay_mediated() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");

    // glibc tries clone3 first; the allowlist answers ENOSYS so it falls
    // back to clone, whose thread flags are allowed.
    let outcome = run_worker(dirs.gate(Rights::READ), &["thread-read", &path]);

    assert_eq!(stdout(&outcome), "inside");
    assert_eq!(seen(&outcome), [allowed("openat", &path, None)]);
}

#[test]
fn relative_and_dot_dot_paths_are_refused_before_authorization() {
    let dirs = Dirs::new();
    let escape = format!("{}/../outside/secret.txt", dirs.granted.display());

    let relative = run_worker(dirs.gate(Rights::READ), &["read", "a.txt"]);
    let dotdot = run_worker(dirs.gate(Rights::READ), &["read", &escape]);

    assert_eq!(stdout(&relative), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(stdout(&dotdot), format!("errno={EOPNOTSUPP}\n"));
    assert_eq!(
        seen(&dotdot),
        [denied("openat", &escape, AuditReason::UnsupportedInput)]
    );
}

#[test]
fn directories_are_refused_with_eisdir() {
    let dirs = Dirs::new();
    let sub = dirs.granted("sub");

    let outcome = run_worker(dirs.gate(Rights::READ | Rights::LIST), &["read", &sub]);

    assert_eq!(stdout(&outcome), format!("errno={EISDIR}\n"));
}

#[test]
fn openat2_accepts_only_the_resolve_flags_the_strict_open_enforces() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");
    let enforced = (RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS).to_string();
    let beneath = RESOLVE_BENEATH.to_string();

    let plain = run_worker(dirs.gate(Rights::READ), &["openat2", &path, "0"]);
    let strict = run_worker(dirs.gate(Rights::READ), &["openat2", &path, &enforced]);
    let other = run_worker(dirs.gate(Rights::READ), &["openat2", &path, &beneath]);

    assert_eq!(stdout(&plain), "inside");
    assert_eq!(seen(&plain), [allowed("openat2", &path, None)]);
    assert_eq!(stdout(&strict), "inside");
    // Not dropped: a flag the supervisor does not enforce is refused.
    assert_eq!(stdout(&other), format!("errno={EOPNOTSUPP}\n"));
}

#[test]
fn symlinks_are_refused_with_eloop_even_inside_the_grant() {
    let dirs = Dirs::new();
    let link = dirs.granted("link");
    std::os::unix::fs::symlink("a.txt", &link).unwrap();

    let outcome = run_worker(dirs.gate(Rights::READ), &["read", &link]);

    assert_eq!(stdout(&outcome), format!("errno={ELOOP}\n"));
    assert_eq!(seen(&outcome), [allowed("openat", &link, Some(ELOOP))]);
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
    let outcome = run_worker(dirs.gate(Rights::READ), &["read", &fifo]);

    assert_eq!(stdout(&outcome), format!("errno={EOPNOTSUPP}\n"));
}

#[test]
fn delivered_descriptors_keep_the_callers_cloexec_choice() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");

    let outcome = run_worker(dirs.gate(Rights::READ), &["cloexec", &path]);

    assert_eq!(stdout(&outcome), "plain=0 marked=1\n");
}

#[test]
fn worker_starts_with_only_stdio_open() {
    let dirs = Dirs::new();

    let outcome = run_worker(dirs.gate(Rights::READ), &["fds"]);

    assert_eq!(stdout(&outcome), "done\n");
}

/// Asserts `run` refused `image` before launching it, with `problem` in the
/// message.
fn refused_before_launch(dirs: &Dirs, image: &Path, problem: &str) {
    let launch = Launch::new(image);
    let checked = launch.check().expect_err("the image must be refused");
    assert_eq!(checked.kind(), ErrorKind::InvalidInput, "{checked}");
    let err = launch
        .run(dirs.gate(Rights::READ))
        .expect_err("the image must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
    assert!(err.to_string().contains(problem), "{err}");
}

#[test]
fn an_image_that_needs_an_interpreter_is_refused_before_launch() {
    let dirs = Dirs::new();
    // A dynamically linked system binary: it would need the loader.
    let dynamic = Path::new("/bin/true");
    assert!(
        dynamic.exists(),
        "the test needs a dynamically linked /bin/true"
    );

    refused_before_launch(&dirs, dynamic, "needs an ELF interpreter");
}

#[test]
fn scripts_are_refused_before_launch() {
    let dirs = Dirs::new();
    let script = dirs.root.path().join("script");
    fs::write(&script, "#!/bin/sh\necho ran\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    refused_before_launch(&dirs, &script, "is not an ELF executable");
}

#[test]
fn set_id_images_are_refused_before_launch() {
    let dirs = Dirs::new();
    let image = dirs.root.path().join("setuid-worker");
    fs::copy(worker(), &image).unwrap();
    fs::set_permissions(&image, fs::Permissions::from_mode(0o4755)).unwrap();

    refused_before_launch(&dirs, &image, "set-user-ID or set-group-ID");
}

#[test]
fn a_static_worker_passes_the_check() {
    Launch::new(worker())
        .check()
        .expect("the fixture is a static x86_64 ELF");
}

/// `fsgate-broker --experimental-intercept` with `args`, granting `granted`
/// read-only.
fn broker(dirs: &Dirs, args: &[&str]) -> std::process::Output {
    let grant = format!("{}:r", dirs.granted.display());
    Command::new(env!("CARGO_BIN_EXE_fsgate-broker"))
        .args(["--experimental-intercept", "--grant", &grant])
        .args(args)
        .output()
        .expect("run fsgate-broker")
}

#[test]
fn the_broker_plans_without_starting_anything() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");
    let worker = worker().to_str().unwrap();

    let output = broker(&dirs, &["--", worker, "read", &path]);

    let plan = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{plan}");
    assert!(plan.contains("check:   ok"), "{plan}");
    assert!(
        plan.contains(&format!("grant:   {} READ", dirs.granted.display())),
        "{plan}"
    );
    assert!(plan.contains("Nothing was started"), "{plan}");
    // The worker would have printed the file.
    assert!(!plan.contains("inside"), "{plan}");
    assert!(!plan.contains("WRITE and CREATE are unused"), "{plan}");
}

/// The profile only reads, so the plan says when a grant gives `WRITE` or
/// `CREATE`, either one alone.
#[test]
fn the_plan_names_rights_the_profile_leaves_unused() {
    let dirs = Dirs::new();
    let worker = worker().to_str().unwrap();
    for letters in ["w", "c"] {
        let grant = format!("{}:{letters}", dirs.outside.display());
        let output = broker(&dirs, &["--grant", &grant, "--", worker, "read", "/"]);

        let plan = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{letters}: {plan}");
        assert!(
            plan.contains("the profile only reads; WRITE and CREATE are unused"),
            "{letters}: {plan}"
        );
    }
}

#[test]
fn the_broker_applies_and_audits_the_worker() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");
    let worker = worker().to_str().unwrap();

    let output = broker(&dirs, &["--audit", "--apply", "--", worker, "read", &path]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"inside");
    let audit = String::from_utf8_lossy(&output.stderr);
    assert!(
        audit.contains(r#""op":"open""#) && audit.contains(r#""syscall":"openat""#),
        "{audit}"
    );
}

#[test]
fn the_broker_relays_the_workers_stderr_and_exit_code() {
    let dirs = Dirs::new();
    let worker = worker().to_str().unwrap();

    let output = broker(&dirs, &["--apply", "--", worker, "no-such-op"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown op: no-such-op"));
}

#[test]
fn the_broker_refuses_an_image_the_profile_rejects_in_plan_and_apply() {
    let dirs = Dirs::new();

    let plan = broker(&dirs, &["--", "/bin/true"]);
    let apply = broker(&dirs, &["--apply", "--", "/bin/true"]);

    assert_eq!(plan.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&plan.stdout).contains("refused"));
    assert_eq!(apply.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&apply.stderr).contains("needs an ELF interpreter"));
    assert!(apply.stdout.is_empty());
}

// The two tests below need a kernel booted without Landlock. CI's `kernels`
// job boots its Linux 6.6 guest a second time with `lsm=capability` and runs
// them with `--ignored`; on a kernel with Landlock they fail, because the
// worker starts there. The worker is asked to create a marker file, which it
// could do unconfined, so the marker's absence shows it never ran.

#[test]
#[ignore = "needs a kernel booted without Landlock; CI's kernels job runs it"]
fn the_launcher_refuses_to_start_without_landlock() {
    let dirs = Dirs::new();
    let marker = dirs.granted("marker");
    let rights = Rights::READ | Rights::WRITE | Rights::CREATE;
    let mut launch = Launch::new(worker());
    launch.args(["creat", &marker]);

    let checked = launch.check().expect_err("check must refuse the kernel");
    let mut gate = dirs.gate(rights);
    let sink = Arc::new(Capture::default());
    gate.set_audit_sink(sink.clone());
    let err = launch.run(gate).expect_err("the worker must not start");

    for err in [&checked, &err] {
        assert_eq!(err.kind(), ErrorKind::Unsupported, "{err}");
        assert!(err.to_string().contains("landlock is unavailable"), "{err}");
    }
    assert!(sink.0.lock().unwrap().is_empty());
    assert!(!Path::new(&marker).exists());
}

#[test]
#[ignore = "needs a kernel booted without Landlock; CI's kernels job runs it"]
fn the_broker_refuses_to_start_without_landlock() {
    let dirs = Dirs::new();
    let marker = dirs.granted("marker");
    let worker = worker().to_str().unwrap();

    let plan = broker(&dirs, &["--", worker, "creat", &marker]);
    let apply = broker(&dirs, &["--apply", "--", worker, "creat", &marker]);

    let planned = String::from_utf8_lossy(&plan.stdout);
    assert_eq!(plan.status.code(), Some(1), "{planned}");
    assert!(
        planned.contains("check:   refused: landlock is unavailable"),
        "{planned}"
    );
    let refused = String::from_utf8_lossy(&apply.stderr);
    assert_eq!(apply.status.code(), Some(1), "{refused}");
    assert!(refused.contains("landlock is unavailable"), "{refused}");
    assert!(apply.stdout.is_empty());
    assert!(!Path::new(&marker).exists());
}

#[test]
fn the_raw_open_syscall_is_mediated_too() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");
    let secret = dirs.outside("secret.txt");

    let granted = run_worker(dirs.gate(Rights::READ), &["raw-open", &path]);
    let refused = run_worker(dirs.gate(Rights::READ), &["raw-open", &secret]);

    assert_eq!(stdout(&granted), "inside");
    assert_eq!(seen(&granted), [allowed("open", &path, None)]);
    assert_eq!(stdout(&refused), format!("errno={EACCES}\n"));
    assert_eq!(
        seen(&refused),
        [denied("open", &secret, AuditReason::NoGrant)]
    );
}

#[test]
fn a_path_rewritten_during_its_request_never_reaches_an_ungranted_file() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");
    let secret = dirs.outside("secret.txt");

    // One worker thread flips the path buffer between the granted file and
    // the secret while another opens it. The supervisor copies the path once
    // and authorizes only that copy, so a torn or swapped path can fail, but
    // can never deliver the secret.
    let outcome = run_worker(dirs.gate(Rights::READ), &["race", &path, &secret, "2000"]);

    let out = stdout(&outcome);
    assert!(!out.contains("LEAK"), "{out}");
    let counts: Vec<u32> = out
        .trim()
        .strip_prefix("ok ")
        .unwrap_or_else(|| panic!("unexpected output {out:?}"))
        .split(' ')
        .map(|field| field.split_once('=').unwrap().1.parse().unwrap())
        .collect();
    assert!(
        counts[0] > 0 && counts[1] > 0,
        "the race never ran both ways: {out}"
    );
    let secret_path = Path::new(&secret);
    assert!(
        outcome
            .events
            .iter()
            .filter(|event| event.path.as_deref() == Some(secret_path))
            .all(|event| event.decision == AuditDecision::Deny),
        "an event allowed the secret"
    );
    assert_eq!(fs::read(&secret).unwrap(), b"secret");
}

/// Sends every audit event on a channel, so a test can wait for a decision.
struct Notify(Mutex<std::sync::mpsc::Sender<AuditEvent>>);

impl AuditSink for Notify {
    fn event(&self, event: &AuditEvent) {
        let _ = self.0.lock().unwrap().send(event.clone());
    }
}

#[test]
fn a_revoked_grant_denies_later_opens_but_delivered_files_stay_usable() {
    use std::io::Write;
    use std::sync::mpsc;
    use std::time::Duration;

    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");
    let (sender, decisions) = mpsc::channel();
    let mut gate = Gate::new();
    let grant = gate.grant(&dirs.granted, Rights::READ).unwrap();
    gate.set_audit_sink(Arc::new(Notify(Mutex::new(sender))));

    let mut running = Launch::new(worker())
        .args(["revoke-cycle", path.as_str()])
        .spawn(gate)
        .expect("spawn");
    let mut stdin = running.take_stdin().expect("stdin pipe");

    // The worker's first open has been decided and delivered.
    let first = decisions
        .recv_timeout(Duration::from_secs(10))
        .expect("first decision");
    assert_eq!(
        (first.decision, first.reason),
        (AuditDecision::Allow, AuditReason::Ok)
    );

    running.revoke(grant).expect("revoke while running");
    stdin.write_all(b"x").unwrap();
    drop(stdin);
    let outcome = running.wait().expect("wait");

    let out = String::from_utf8_lossy(&outcome.stdout);
    assert_eq!(
        out,
        format!("first=inside\nsecond=errno={EACCES}\nkept=inside\n")
    );
    // The revoke is audited too, between the two opens.
    let revoked = decisions
        .recv_timeout(Duration::from_secs(10))
        .expect("revoke event");
    assert_eq!(
        (revoked.op, revoked.decision, revoked.path),
        (
            AuditOp::Revoke,
            AuditDecision::Allow,
            Some(dirs.granted.clone())
        )
    );
    let second = decisions
        .recv_timeout(Duration::from_secs(10))
        .expect("second decision");
    assert_eq!(
        (second.op, second.decision, second.reason, second.path),
        (
            AuditOp::Open,
            AuditDecision::Deny,
            AuditReason::NoGrant,
            Some(PathBuf::from(&path))
        )
    );
}

#[test]
fn a_killed_worker_is_reaped_by_wait() {
    let dirs = Dirs::new();
    let path = dirs.granted("a.txt");

    // `revoke-cycle` blocks on standard input after its first open.
    let mut running = Launch::new(worker())
        .args(["revoke-cycle", path.as_str()])
        .spawn(dirs.gate(Rights::READ))
        .expect("spawn");
    running.kill().expect("kill");
    let outcome = running.wait().expect("wait");

    use std::os::unix::process::ExitStatusExt;
    assert_eq!(outcome.status.signal(), Some(9));
}
