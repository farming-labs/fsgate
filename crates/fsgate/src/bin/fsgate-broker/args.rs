//! Parses the `fsgate-broker` command line.
//!
//! This file uses only `std` and `fsgate::Rights`, so the `broker_args` fuzz
//! target in `fuzz/` can include it as a module.

use std::path::{Path, PathBuf};

use fsgate::Rights;

pub(super) struct Args {
    pub(super) grants: Vec<(PathBuf, Rights)>,
    pub(super) mode: Mode,
    pub(super) command: Vec<String>,
}

pub(super) enum Mode {
    /// Serve the grants to the command over a connection it inherits.
    Inherited(Start),
    /// Serve the grants over a Unix socket at this path.
    Socket(PathBuf),
    /// Experimental: intercept the worker's file opens (RFC 0004).
    Intercept { apply: bool, audit: bool },
}

/// How the command of [`Mode::Inherited`] starts.
pub(super) enum Start {
    /// Confined (RFC 0008), with these validated `--direct` specs and
    /// `--env` names.
    Confined {
        direct: Vec<String>,
        env: Vec<String>,
    },
    /// With this process's own environment and filesystem access.
    Unconfined,
}

/// The arguments as strings. `std::env::args` would panic on one that is not
/// UTF-8, and the broker protocol carries paths as UTF-8 anyway.
pub(super) fn utf8_args(
    args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Vec<String>, String> {
    args.enumerate()
        .map(|(index, arg)| {
            arg.into_string().map_err(|arg| {
                format!(
                    "argument {} (`{}`) is not valid UTF-8; fsgate-broker accepts only UTF-8 \
                     arguments, so pass this value to the worker another way",
                    index + 1,
                    arg.to_string_lossy()
                )
            })
        })
        .collect()
}

pub(super) fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
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

pub(super) fn parse_grant(spec: &str) -> Result<(PathBuf, Rights), String> {
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
/// sees, so there is no `w` or `c`. The path must be absolute, as for
/// `--grant`, because a relative one would depend on the broker's working
/// directory.
pub(super) fn parse_direct(spec: &str) -> Result<(PathBuf, &str), String> {
    let (path, letters) = spec
        .rsplit_once(':')
        .ok_or_else(|| format!("`--direct {spec}` is not `<path>:<rights>`"))?;
    if !Path::new(path).is_absolute() {
        return Err(format!(
            "`--direct {spec}` names a relative path; give an absolute one, as for `--grant`"
        ));
    }
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
