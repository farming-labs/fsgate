//! Serve granted directories to a child command over a Unix socket.
//!
//! ```text
//! fsgate-broker --grant <path>:<rights> [--grant ...] --socket <path> -- <command> [args...]
//! ```
//!
//! Rights letters: `r` read, `w` write, `c` create, `l` list.
//! The child receives the socket path in `FSGATE_BROKER_SOCKET` and talks
//! to it with `fsgate::BrokerGate`. The broker exits with the child's
//! exit code; when the broker dies, every child filesystem operation
//! fails closed.
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

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use fsgate::{Broker, Gate, Rights};

struct Args {
    grants: Vec<(PathBuf, Rights)>,
    mode: Mode,
    command: Vec<String>,
}

enum Mode {
    /// Serve the grants over a Unix socket at this path.
    Socket(PathBuf),
    /// Experimental: intercept the worker's file opens (RFC 0004).
    Intercept { apply: bool, audit: bool },
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
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
    match mode {
        Mode::Socket(socket) => match run(SocketArgs {
            grants,
            socket,
            command,
        }) {
            Ok(code) => code,
            Err(message) => {
                eprintln!("fsgate-broker: {message}");
                ExitCode::from(1)
            }
        },
        Mode::Intercept { apply, audit } => intercept::run(&grants, &command, apply, audit),
    }
}

fn run(args: SocketArgs) -> Result<ExitCode, String> {
    let mut gate = Gate::new();
    for (path, rights) in &args.grants {
        gate.grant(path, *rights)
            .map_err(|err| format!("granting `{}` failed: {err}", path.display()))?;
    }

    let listener = UnixListener::bind(&args.socket).map_err(|err| {
        format!(
            "binding socket `{}` failed: {err}; remove a stale socket file first",
            args.socket.display()
        )
    })?;

    let broker = Broker::new(gate);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            // Ends when the listener errors, e.g. at process exit.
            let _ = broker.serve(&listener);
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
                     --socket <path> -- <command> [args...]\n\
                     \x20      fsgate-broker --experimental-intercept --grant <path>:<rights> [--grant ...] \
                     [--audit] [--apply] -- <static-binary> [args...]\n\
                     rights letters: r read, w write, c create, l list";

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut grants = Vec::new();
    let mut socket = None;
    let mut intercept = false;
    let mut apply = false;
    let mut audit = false;
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
    let mode = match (intercept, socket) {
        (true, Some(_)) => {
            return Err(
                "`--socket` and `--experimental-intercept` are separate modes; pass one".into(),
            );
        }
        (true, None) => Mode::Intercept { apply, audit },
        (false, _) if apply || audit => {
            return Err("`--apply` and `--audit` need `--experimental-intercept`".into());
        }
        (false, Some(socket)) => Mode::Socket(socket),
        (false, None) => return Err("`--socket` is required".into()),
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
