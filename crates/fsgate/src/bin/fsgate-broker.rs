//! Serve granted directories to a child command over a Unix socket.
//!
//! ```text
//! fsgate-broker --grant <path>:<rights> [--grant ...] [--direct <path>:<rights> ...] \
//!     [--env <name> ...] -- <command> [args...]
//! fsgate-broker --unconfined --grant <path>:<rights> [--grant ...] [--socket <path>] \
//!     -- <command> [args...]
//! ```
//!
//! Rights letters: `r` read, `w` write, `c` create, `l` list.
//! The child inherits a connection with no name in the filesystem, finds it
//! in `FSGATE_BROKER_FD`, and adopts it with
//! `fsgate::BrokerGate::from_inherited`. The broker exits with the child's
//! exit code; when the broker dies, every child filesystem operation fails
//! closed.
//!
//! On Linux the child is confined (RFC 0008): it can reach data only through
//! the broker, it can still open the files an ordinary program needs to
//! start, and it inherits no environment beyond the names given with `--env`.
//! `--direct` adds a path the child may open itself, with the letters `r`,
//! `l`, and `x` (execute); those opens are not audited. If confinement cannot
//! be applied, on macOS or on a kernel without Landlock ABI v3, the child
//! does not start.
//!
//! `--unconfined` starts the child with this process's own environment and
//! filesystem access. `--socket`, which needs it, creates an owner-only
//! socket at that path and passes the path in `FSGATE_BROKER_SOCKET`.
//!
//! Experimental interception mode (RFC 0004; built with the
//! `experimental-intercept` feature, Linux x86_64 only, unsupported):
//!
//! ```text
//! fsgate-broker --experimental-intercept --grant <path>:<rights> [--grant ...] \
//!     [--audit] [--apply] -- <static-binary> [args...]
//! ```
//!
//! Without `--apply` it prints the plan (the worker check, the grants, and
//! the profile) and starts nothing. With `--apply` it launches the worker
//! under `fsgate::intercept::Launch`, relays its output once it exits, and
//! exits with its code. `--audit` writes each decision to standard error
//! as an RFC 0002 JSON line. It never falls back to running the worker
//! unconfined.
//!
//! Exit codes: the child's code on success, 1 for operational failure,
//! 2 for usage errors, 3 when the interception profile refuses the worker
//! image.

use std::fs::{self, Permissions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use fsgate::{Broker, Gate, Rights};

#[cfg(target_os = "linux")]
#[path = "fsgate-broker/confine.rs"]
mod confine;

#[cfg(not(target_os = "linux"))]
mod confine {
    use std::os::fd::RawFd;
    use std::process::Command;

    pub(super) fn command(
        _: RawFd,
        _: &[String],
        _: &[String],
        _: &[String],
    ) -> Result<Command, String> {
        Err(
            "this platform has no way for `fsgate-broker` to confine a worker; \
             pass `--unconfined` to run it without confinement"
                .into(),
        )
    }
}

struct Args {
    grants: Vec<(PathBuf, Rights)>,
    mode: Mode,
    command: Vec<String>,
}

enum Mode {
    /// Serve the grants to the command over a connection it inherits.
    Inherited(Start),
    /// Serve the grants over a Unix socket at this path.
    Socket(PathBuf),
    /// Experimental: intercept the worker's file opens (RFC 0004).
    Intercept { apply: bool, audit: bool },
}

/// How the command of [`Mode::Inherited`] starts.
enum Start {
    /// Confined (RFC 0008), with these validated `--direct` specs and
    /// `--env` names.
    Confined {
        direct: Vec<String>,
        env: Vec<String>,
    },
    /// With this process's own environment and filesystem access.
    Unconfined,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(target_os = "linux")]
    if argv.first().is_some_and(|first| first == confine::ENTRY) {
        return confine::main(argv.into_iter().skip(1));
    }

    let args = match parse_args(argv.into_iter()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("fsgate-broker: {message}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let Args {
        grants,
        mode,
        command,
    } = args;
    let result = match mode {
        Mode::Inherited(start) => run_inherited(&grants, &command, start),
        Mode::Socket(socket) => run(SocketArgs {
            grants,
            socket,
            command,
        }),
        Mode::Intercept { apply, audit } => {
            return intercept::run(&grants, &command, apply, audit);
        }
    };
    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("fsgate-broker: {message}");
            ExitCode::from(1)
        }
    }
}

fn gate_from(grants: &[(PathBuf, Rights)]) -> Result<Gate, String> {
    let mut gate = Gate::new();
    for (path, rights) in grants {
        gate.grant(path, *rights)
            .map_err(|err| format!("granting `{}` failed: {err}", path.display()))?;
    }
    Ok(gate)
}

/// Serves the command over a socketpair it inherits. The connection has no
/// name, so no other process can connect to it.
fn run_inherited(
    grants: &[(PathBuf, Rights)],
    command: &[String],
    start: Start,
) -> Result<ExitCode, String> {
    let broker = Broker::new(gate_from(grants)?);
    let (broker_end, worker_end) = UnixStream::pair()
        .map_err(|err| format!("creating the worker's connection failed: {err}"))?;
    // std makes both ends close-on-exec. Clearing that on the worker's end
    // lets the command inherit it, and this process starts nothing else.
    rustix::io::fcntl_setfd(&worker_end, rustix::io::FdFlags::empty())
        .map_err(|err| format!("preparing the worker's connection failed: {err}"))?;

    let mut worker = match start {
        Start::Confined { direct, env } => {
            confine::command(worker_end.as_raw_fd(), &direct, &env, command)?
        }
        Start::Unconfined => {
            let mut worker = Command::new(&command[0]);
            worker
                .args(&command[1..])
                .env("FSGATE_BROKER_FD", worker_end.as_raw_fd().to_string());
            worker
        }
    };
    let mut child = worker
        .spawn()
        .map_err(|err| format!("spawning `{}` failed: {err}", command[0]))?;
    // Held open here, the broker would never see the worker hang up.
    drop(worker_end);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            // A failed connection fails the worker closed; it does not end
            // the broker, which waits for the worker's exit code.
            let _ = broker.serve_conn(broker_end);
        });
        let status = child
            .wait()
            .map_err(|err| format!("waiting for `{}` failed: {err}", command[0]))?;
        std::process::exit(status.code().unwrap_or(1))
    })
}

/// Creates an owner-only socket at `path`. A connect before `listen` is
/// refused, so setting the mode between `bind` and `listen` means the
/// socket is never reachable while the umask's looser mode applies.
fn bind_owner_only(path: &Path) -> io::Result<UnixListener> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};

    let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
    rustix::net::bind(&socket, &SocketAddrUnix::new(path)?)?;
    let ready = fs::set_permissions(path, Permissions::from_mode(0o600))
        .and_then(|()| Ok(rustix::net::listen(&socket, 128)?));
    if let Err(err) = ready {
        let _ = fs::remove_file(path);
        return Err(err);
    }
    Ok(UnixListener::from(socket))
}

fn run(args: SocketArgs) -> Result<ExitCode, String> {
    let gate = gate_from(&args.grants)?;

    let listener = bind_owner_only(&args.socket).map_err(|err| {
        format!(
            "binding socket `{}` failed: {err}; remove a stale socket file first",
            args.socket.display()
        )
    })?;

    let broker = Broker::new(gate);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            // A broker that stopped accepting would leave workers hanging.
            // Exiting fails them closed instead.
            if let Err(err) = broker.serve(&listener) {
                eprintln!(
                    "fsgate-broker: serving `{}` failed: {err}; workers now fail closed",
                    args.socket.display()
                );
                let _ = fs::remove_file(&args.socket);
                std::process::exit(1);
            }
        });

        let status = Command::new(&args.command[0])
            .args(&args.command[1..])
            .env("FSGATE_BROKER_SOCKET", &args.socket)
            .status()
            .map_err(|err| format!("spawning `{}` failed: {err}", args.command[0]));

        let _ = std::fs::remove_file(&args.socket);
        match status {
            // The serve thread still blocks in accept(); exit now that the
            // child is done, taking its code.
            Ok(status) => {
                let code = status.code().unwrap_or(1);
                std::process::exit(code)
            }
            Err(message) => Err(message),
        }
    })
}

struct SocketArgs {
    grants: Vec<(PathBuf, Rights)>,
    socket: PathBuf,
    command: Vec<String>,
}

const USAGE: &str = "usage: fsgate-broker --grant <path>:<rights> [--grant ...] \
                     [--direct <path>:<rights> ...] [--env <name> ...] -- <command> [args...]\n\
                     \x20      fsgate-broker --unconfined --grant <path>:<rights> [--grant ...] \
                     [--socket <path>] -- <command> [args...]\n\
                     \x20      fsgate-broker --experimental-intercept --grant <path>:<rights> [--grant ...] \
                     [--audit] [--apply] -- <static-binary> [args...]\n\
                     rights letters: r read, w write, c create, l list; \
                     for --direct: r read, l list, x execute";

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut grants = Vec::new();
    let mut socket = None;
    let mut intercept = false;
    let mut apply = false;
    let mut audit = false;
    let mut unconfined = false;
    let mut direct = Vec::new();
    let mut env = Vec::new();
    let mut command = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--grant" => {
                let spec = args.next().ok_or("`--grant` needs `<path>:<rights>`")?;
                grants.push(parse_grant(&spec)?);
            }
            "--socket" => {
                let path = args.next().ok_or("`--socket` needs a path")?;
                socket = Some(PathBuf::from(path));
            }
            "--unconfined" => unconfined = true,
            "--direct" => {
                let spec = args.next().ok_or("`--direct` needs `<path>:<rights>`")?;
                parse_direct(&spec)?;
                direct.push(spec);
            }
            "--env" => {
                let name = args.next().ok_or("`--env` needs a variable name")?;
                if name.is_empty() || name.contains('=') {
                    return Err(format!(
                        "`--env` takes a variable name, not `{name}`; \
                         set the variable in the broker's environment"
                    ));
                }
                env.push(name);
            }
            "--experimental-intercept" => intercept = true,
            "--apply" => apply = true,
            "--audit" => audit = true,
            "--" => {
                command.extend(args);
                break;
            }
            "--help" | "-h" => return Err("help requested".into()),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }

    if grants.is_empty() {
        return Err("at least one `--grant` is required".into());
    }
    if command.is_empty() {
        return Err("a command after `--` is required".into());
    }
    let shapes_confinement = !direct.is_empty() || !env.is_empty();
    if unconfined && shapes_confinement {
        return Err(
            "`--direct` and `--env` describe a confined worker; drop them or drop `--unconfined`"
                .into(),
        );
    }
    let mode = match (intercept, socket) {
        (true, Some(_)) => {
            return Err(
                "`--socket` and `--experimental-intercept` are separate modes; pass one".into(),
            );
        }
        (true, None) if unconfined || shapes_confinement => {
            return Err(
                "`--experimental-intercept` has its own worker profile; drop `--unconfined`, \
                 `--direct`, and `--env`"
                    .into(),
            );
        }
        (true, None) => Mode::Intercept { apply, audit },
        (false, _) if apply || audit => {
            return Err("`--apply` and `--audit` need `--experimental-intercept`".into());
        }
        (false, Some(_)) if !unconfined => {
            return Err(
                "a worker that connects to `--socket` cannot be confined, because a confined \
                 worker makes no new connections; drop `--socket` or pass `--unconfined`"
                    .into(),
            );
        }
        (false, Some(socket)) => Mode::Socket(socket),
        (false, None) if unconfined => Mode::Inherited(Start::Unconfined),
        (false, None) => Mode::Inherited(Start::Confined { direct, env }),
    };
    Ok(Args {
        grants,
        mode,
        command,
    })
}

fn parse_grant(spec: &str) -> Result<(PathBuf, Rights), String> {
    let (path, letters) = spec
        .rsplit_once(':')
        .ok_or_else(|| format!("grant `{spec}` is not `<path>:<rights>`"))?;
    let mut rights = Rights::from_bits_truncate(0);
    for letter in letters.chars() {
        rights = rights
            | match letter {
                'r' => Rights::READ,
                'w' => Rights::WRITE,
                'c' => Rights::CREATE,
                'l' => Rights::LIST,
                other => {
                    return Err(format!(
                        "unknown rights letter `{other}` in `{spec}`; use r, w, c, l"
                    ));
                }
            };
    }
    if rights == Rights::from_bits_truncate(0) {
        return Err(format!("grant `{spec}` names no rights"));
    }
    Ok((PathBuf::from(path), rights))
}

/// Splits a `--direct` spec into its path and its letters, which are `r`,
/// `l`, and `x`. A write the worker makes directly is one the broker never
/// sees, so there is no `w` or `c`.
fn parse_direct(spec: &str) -> Result<(PathBuf, &str), String> {
    let (path, letters) = spec
        .rsplit_once(':')
        .ok_or_else(|| format!("`--direct {spec}` is not `<path>:<rights>`"))?;
    if letters.is_empty() {
        return Err(format!("`--direct {spec}` names no rights"));
    }
    if let Some(other) = letters.chars().find(|letter| !"rlx".contains(*letter)) {
        return Err(format!(
            "unknown rights letter `{other}` in `--direct {spec}`; use r, l, x, \
             and `--grant` for anything the worker writes"
        ));
    }
    Ok((PathBuf::from(path), letters))
}

#[cfg(all(
    feature = "experimental-intercept",
    target_os = "linux",
    target_arch = "x86_64"
))]
mod intercept {
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::Arc;

    use fsgate::intercept::Launch;
    use fsgate::{AuditEvent, AuditSink, Gate, Rights};

    /// Writes each decision to standard error as an RFC 0002 JSON line.
    struct StderrSink;

    impl AuditSink for StderrSink {
        fn event(&self, event: &AuditEvent) {
            let _ = writeln!(io::stderr().lock(), "{}", event.to_json_line());
        }
    }

    /// 3 when the profile refuses the image, 1 for anything else.
    fn exit_for(err: &io::Error) -> ExitCode {
        ExitCode::from(if err.kind() == io::ErrorKind::InvalidInput {
            3
        } else {
            1
        })
    }

    pub(super) fn run(
        grants: &[(PathBuf, Rights)],
        command: &[String],
        apply: bool,
        audit: bool,
    ) -> ExitCode {
        let mut launch = Launch::new(&command[0]);
        launch.args(&command[1..]);
        let check = launch.check();
        if !apply {
            print_plan(grants, command, &check);
            return check.map_or_else(|err| exit_for(&err), |()| ExitCode::SUCCESS);
        }
        if let Err(err) = check {
            eprintln!("fsgate-broker: {err}");
            return exit_for(&err);
        }

        let mut gate = Gate::new();
        for (path, rights) in grants {
            if let Err(err) = gate.grant(path, *rights) {
                eprintln!("fsgate-broker: granting `{}` failed: {err}", path.display());
                return ExitCode::from(1);
            }
        }
        if audit {
            gate.set_audit_sink(Arc::new(StderrSink));
        }
        match launch.run(gate) {
            Ok(outcome) => {
                let _ = io::stdout().lock().write_all(&outcome.stdout);
                let _ = io::stderr().lock().write_all(&outcome.stderr);
                let code = outcome.status.code().unwrap_or(1);
                ExitCode::from(u8::try_from(code).unwrap_or(1))
            }
            Err(err) => {
                eprintln!("fsgate-broker: the worker did not start: {err}");
                exit_for(&err)
            }
        }
    }

    fn print_plan(grants: &[(PathBuf, Rights)], command: &[String], check: &io::Result<()>) {
        let mut out = io::stdout().lock();
        let _ = writeln!(
            out,
            "fsgate-broker: experimental interception plan (RFC 0004, unsupported)"
        );
        let _ = writeln!(out, "  worker:  {}", command.join(" "));
        match check {
            Ok(()) => {
                let _ = writeln!(
                    out,
                    "  check:   ok (kernel support, static x86_64 ELF image)"
                );
            }
            Err(err) => {
                let _ = writeln!(out, "  check:   refused: {err}");
            }
        }
        for (path, rights) in grants {
            let _ = writeln!(out, "  grant:   {} {rights:?}", path.display());
        }
        if grants
            .iter()
            .any(|(_, rights)| rights.contains(Rights::WRITE) || rights.contains(Rights::CREATE))
        {
            let _ = writeln!(
                out,
                "           the profile only reads; WRITE and CREATE are unused"
            );
        }
        for line in [
            "  profile: read-only opens of absolute paths through open, openat, and openat2;",
            "           symlinks, directories, special files, writes, and creation are refused;",
            "           execve, sockets, io_uring, namespaces, and ptrace are refused by the",
            "           syscall allowlist; the worker gets only stdio and an empty environment",
        ] {
            let _ = writeln!(out, "{line}");
        }
        let _ = writeln!(
            out,
            "Nothing was started. Rerun with --apply to launch the worker."
        );
    }
}

#[cfg(not(all(
    feature = "experimental-intercept",
    target_os = "linux",
    target_arch = "x86_64"
)))]
mod intercept {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use fsgate::Rights;

    pub(super) fn run(_: &[(PathBuf, Rights)], _: &[String], _: bool, _: bool) -> ExitCode {
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            eprintln!(
                "fsgate-broker: this build has no interception mode; rebuild with \
                 `cargo install fsgate --features experimental-intercept`"
            );
        } else {
            eprintln!("fsgate-broker: interception mode needs Linux x86_64");
        }
        ExitCode::from(2)
    }
}
