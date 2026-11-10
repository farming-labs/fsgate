//! Confines the worker `fsgate-broker` starts (RFC 0008).
//!
//! The broker starts itself again with [`ENTRY`] as the first argument. That
//! fresh, single-threaded process takes away what the worker must not have
//! and then becomes the worker, so nothing runs in a forked child of the
//! multi-threaded broker. `exec` is the last step and every failure before
//! it exits, so no path leads to an unconfined worker.
//!
//! The broker's grants never become rules here. If they did, the worker
//! could open granted files directly, with no audit event and no way to take
//! the access back.

use std::convert::Infallible;
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, PathFdError,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};
use rustix::process::Signal;

/// The first argument that selects this mode instead of the broker's own
/// command line.
pub(super) const ENTRY: &str = "--confined-exec";

/// Directories an ordinary program needs in order to start. One that does
/// not exist on this system is skipped, which only narrows the ruleset.
const RUNTIME_DIRS: [&str; 5] = ["/usr", "/lib", "/lib64", "/bin", "/sbin"];

/// The command that confines the process and then becomes `worker`.
///
/// `/proc/self/exe` names this binary even if its path has changed since it
/// started. `direct` and `env` were validated when the broker parsed them.
pub(super) fn command(
    connection: RawFd,
    direct: &[String],
    env: &[String],
    worker: &[String],
) -> Result<Command, String> {
    let mut command = Command::new("/proc/self/exe");
    command
        .arg0("fsgate-broker")
        .arg(ENTRY)
        .arg(std::process::id().to_string())
        .arg(connection.to_string());
    for spec in direct {
        command.args(["--direct", spec]);
    }
    for name in env {
        command.args(["--env", name]);
    }
    command.arg("--").args(worker);
    Ok(command)
}

struct Request {
    broker: u32,
    connection: RawFd,
    direct: Vec<String>,
    env: Vec<String>,
    worker: Vec<String>,
}

/// Runs the confining process. Returns only if the worker did not start.
pub(super) fn main(args: impl Iterator<Item = String>) -> ExitCode {
    let result = parse(args).and_then(run);
    let Err(message) = result;
    eprintln!("fsgate-broker: {message}");
    ExitCode::from(1)
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Request, String> {
    let malformed = || format!("`{ENTRY}` is internal to `fsgate-broker`; do not call it directly");
    let broker = args
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(malformed)?;
    let connection = args
        .next()
        .and_then(|value| value.parse().ok())
        .filter(|fd: &RawFd| *fd >= 0)
        .ok_or_else(malformed)?;

    let mut direct = Vec::new();
    let mut env = Vec::new();
    loop {
        match args.next().as_deref() {
            Some("--direct") => direct.push(args.next().ok_or_else(malformed)?),
            Some("--env") => env.push(args.next().ok_or_else(malformed)?),
            Some("--") => break,
            _ => return Err(malformed()),
        }
    }
    let worker: Vec<String> = args.collect();
    if worker.is_empty() {
        return Err(malformed());
    }
    Ok(Request {
        broker,
        connection,
        direct,
        env,
        worker,
    })
}

fn run(request: Request) -> Result<Infallible, String> {
    // `TIOCSTI` lets a process type into its controlling terminal, so a
    // worker could queue commands for the user's shell. A new session has
    // no controlling terminal.
    rustix::process::setsid().map_err(|err| format!("starting a new session failed: {err}"))?;

    // After `setsid`, Ctrl-C reaches only the broker. Without this, a killed
    // broker would leave its worker running.
    rustix::process::set_parent_process_death_signal(Some(Signal::KILL))
        .map_err(|err| format!("tying the worker to its broker failed: {err}"))?;
    // The broker may have died before that call took effect.
    if std::os::unix::process::parent_id() != request.broker {
        return Err("the broker exited before its worker started".into());
    }

    // Landlock does not restrict descriptors opened before it applies.
    close_others_at_exec(request.connection)
        .map_err(|err| format!("closing inherited descriptors failed: {err}"))?;

    let image = resolve(&request.worker[0])?;
    restrict(&image, &request.direct)?;

    let mut worker = Command::new(&image);
    worker.arg0(&request.worker[0]).args(&request.worker[1..]);
    worker.env_clear();
    for name in &request.env {
        if let Some(value) = std::env::var_os(name) {
            worker.env(name, value);
        }
    }
    worker.env("FSGATE_BROKER_FD", request.connection.to_string());
    let err = worker.exec();
    Err(format!("starting `{}` failed: {err}", request.worker[0]))
}

/// Marks every descriptor except standard input, output, and error and the
/// broker connection to close when the worker starts.
fn close_others_at_exec(connection: RawFd) -> io::Result<()> {
    let keep = connection.unsigned_abs();
    if keep > 3 {
        sys::close_at_exec(3, keep - 1)?;
    }
    sys::close_at_exec((keep + 1).max(3), u32::MAX)
}

/// Where `name` is, the way `execvp` would find it, so a rule can name the
/// worker's own image.
fn resolve(name: &str) -> Result<PathBuf, String> {
    if name.contains('/') {
        return Ok(PathBuf::from(name));
    }
    let path = std::env::var_os("PATH")
        .ok_or_else(|| format!("`PATH` is not set, so `{name}` cannot be found; give its path"))?;
    std::env::split_paths(&path)
        // An empty entry means the current directory. Without the `.` the
        // result has no `/`, and `exec` would search for it again.
        .map(|dir| {
            if dir.as_os_str().is_empty() {
                Path::new(".").join(name)
            } else {
                dir.join(name)
            }
        })
        .find(|candidate| is_executable(candidate))
        .ok_or_else(|| format!("`{name}` was not found on `PATH`; give its path"))
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Restricts this process, and so the worker it becomes, to the paths a
/// program needs to start and the `--direct` paths. Data comes from the
/// broker.
fn restrict(image: &Path, direct: &[String]) -> Result<(), String> {
    let runtime = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
    let mut ruleset = ruleset()?;
    for dir in RUNTIME_DIRS {
        ruleset = allow_if_present(ruleset, Path::new(dir), runtime)?;
    }
    ruleset = allow_if_present(
        ruleset,
        Path::new("/etc/ld.so.cache"),
        AccessFs::ReadFile.into(),
    )?;
    ruleset = allow_if_present(
        ruleset,
        Path::new("/dev/null"),
        AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate,
    )?;
    ruleset = allow_if_present(
        ruleset,
        Path::new("/dev/urandom"),
        AccessFs::ReadFile.into(),
    )?;
    ruleset = allow(ruleset, image, AccessFs::ReadFile | AccessFs::Execute)?;
    for spec in direct {
        let (path, letters) = super::parse_direct(spec)?;
        let mut access = BitFlags::<AccessFs>::EMPTY;
        for letter in letters.chars() {
            access |= match letter {
                'r' => AccessFs::ReadFile,
                'l' => AccessFs::ReadDir,
                _ => AccessFs::Execute,
            };
        }
        ruleset = allow(ruleset, &path, access)?;
    }

    let status = ruleset.restrict_self().map_err(unavailable)?;
    // The hard requirement in `ruleset` makes this unreachable. It is checked
    // anyway, so an unexpected crate or kernel answer cannot start a worker.
    if status.ruleset == RulesetStatus::NotEnforced || !status.no_new_privs {
        return Err(unavailable("the kernel did not apply the ruleset"));
    }
    Ok(())
}

/// A ruleset that handles every filesystem right `lock()` handles, and asks
/// for the RFC 0006 restrictions where the kernel has them.
fn ruleset() -> Result<RulesetCreated, String> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3))
        .map_err(unavailable)?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::IoctlDev)
        .map_err(unavailable)?
        // No rule below names this one. The worker already holds its
        // connection, so it never needs a connect.
        .handle_access(AccessFs::ResolveUnix)
        .map_err(unavailable)?
        .scope(Scope::AbstractUnixSocket)
        .map_err(unavailable)?
        .scope(Scope::Signal)
        .map_err(unavailable)?
        .create()
        .map_err(unavailable)
}

fn unavailable(err: impl std::fmt::Display) -> String {
    format!(
        "this kernel cannot confine the worker, which needs Landlock ABI v3 ({err}); \
         pass `--unconfined` to run it without confinement"
    )
}

fn allow(
    ruleset: RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, String> {
    let fd = PathFd::new(path).map_err(|err| {
        format!(
            "`{}` cannot be opened for the worker: {err}",
            path.display()
        )
    })?;
    add_rule(ruleset, path, fd, access)
}

fn allow_if_present(
    ruleset: RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, String> {
    match PathFd::new(path) {
        Ok(fd) => add_rule(ruleset, path, fd, access),
        Err(PathFdError::OpenCall { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Ok(ruleset)
        }
        Err(err) => Err(format!(
            "`{}` cannot be opened for the worker: {err}",
            path.display()
        )),
    }
}

fn add_rule(
    ruleset: RulesetCreated,
    path: &Path,
    fd: PathFd,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, String> {
    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map_err(|err| format!("allowing `{}` failed: {err}", path.display()))
}

/// The one `unsafe` call confinement needs, kept apart from its logic.
///
/// # Safety contract
///
/// `close_range(2)` takes plain integers and reads no memory of this
/// process. With `CLOSE_RANGE_CLOEXEC` it closes nothing now; it only marks
/// descriptors to close at `exec`. So it cannot invalidate a descriptor that
/// Rust code holds, whatever the range. Neither `std` nor `rustix` wraps it.
#[allow(unsafe_code)]
mod sys {
    use std::io;

    pub(super) fn close_at_exec(first: u32, last: u32) -> io::Result<()> {
        // SAFETY: the arguments are integers. See the module contract.
        let result = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                libc::c_ulong::from(first),
                libc::c_ulong::from(last),
                libc::c_ulong::from(libc::CLOSE_RANGE_CLOEXEC),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}
