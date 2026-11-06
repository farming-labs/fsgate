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
//! Exit codes: the child's code on success, 1 for operational failure,
//! 2 for usage errors.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use fsgate::{Broker, Gate, Rights};

struct Args {
    grants: Vec<(PathBuf, Rights)>,
    socket: PathBuf,
    command: Vec<String>,
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

    match run(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("fsgate-broker: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Args) -> Result<ExitCode, String> {
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

const USAGE: &str = "usage: fsgate-broker --grant <path>:<rights> [--grant ...] \
                     --socket <path> -- <command> [args...]\n\
                     rights letters: r read, w write, c create, l list";

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut grants = Vec::new();
    let mut socket = None;
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
    let socket = socket.ok_or("`--socket` is required")?;
    if command.is_empty() {
        return Err("a command after `--` is required".into());
    }
    Ok(Args {
        grants,
        socket,
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
