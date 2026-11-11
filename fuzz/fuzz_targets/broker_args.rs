//! Feeds arbitrary command lines to `fsgate-broker`'s parser: the `--grant`
//! and `--direct` specs, and the modes the other options select.
//!
//! The input is the argument list, split at each NUL byte, as `execve`
//! passes it. An argument that is one of the bytes in [`OPTIONS`] stands
//! for the option beside it, so that changing one byte swaps one option for
//! another; finding a combination of two options in their full spelling
//! took the fuzzer longer than five minutes. Each argument is also parsed
//! alone as a `--grant` spec and as a `--direct` spec. Every answer is compared with [`expected_args`],
//! [`expected_grant`], and [`expected_direct`], which restate the rules
//! the parser enforces. Besides panics, the target fails if the parser
//! accepts what they refuse, refuses what they accept, or gives a right or
//! a mode the command line did not ask for.

#![no_main]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use fsgate::Rights;
use libfuzzer_sys::fuzz_target;

#[path = "../../crates/fsgate/src/bin/fsgate-broker/args.rs"]
mod args;

use args::{Args, Mode, Start};

/// Arguments of one byte that stand for an option.
const OPTIONS: [(u8, &str); 10] = [
    (b'G', "--grant"),
    (b'D', "--direct"),
    (b'E', "--env"),
    (b'S', "--socket"),
    (b'U', "--unconfined"),
    (b'I', "--experimental-intercept"),
    (b'A', "--apply"),
    (b'T', "--audit"),
    (b'H', "--help"),
    (b'-', "--"),
];

/// `<path>:<letters>`, split at the last colon. Each letter is one of
/// `rwcl` and adds its right, and at least one is given.
fn expected_grant(spec: &str) -> Option<(&str, Rights)> {
    let colon = spec.rfind(':')?;
    let (path, letters) = (&spec[..colon], &spec[colon + 1..]);
    let mut rights = Rights::from_bits_truncate(0);
    for letter in letters.bytes() {
        rights = rights
            | match letter {
                b'r' => Rights::READ,
                b'w' => Rights::WRITE,
                b'c' => Rights::CREATE,
                b'l' => Rights::LIST,
                _ => return None,
            };
    }
    (!letters.is_empty()).then_some((path, rights))
}

/// `<path>:<letters>`, split at the last colon, with an absolute path and
/// at least one letter, each of them `r`, `l`, or `x`.
fn expected_direct(spec: &str) -> Option<(&str, &str)> {
    let colon = spec.rfind(':')?;
    let (path, letters) = (&spec[..colon], &spec[colon + 1..]);
    let valid = path.starts_with('/')
        && !letters.is_empty()
        && letters.bytes().all(|letter| b"rlx".contains(&letter));
    valid.then_some((path, letters))
}

/// What a command line asks for, before the rules between options apply.
#[derive(Default)]
struct Asked<'a> {
    grants: Vec<&'a str>,
    socket: Option<&'a str>,
    direct: Vec<&'a str>,
    env: Vec<&'a str>,
    unconfined: bool,
    intercept: bool,
    apply: bool,
    audit: bool,
    command: &'a [String],
}

/// The command line the parser must accept, or `None` for one it must
/// refuse. The last `--socket` wins.
fn expected_args(argv: &[String]) -> Option<Asked<'_>> {
    let mut asked = Asked::default();
    let mut rest = argv.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--grant" => {
                let spec = rest.next()?.as_str();
                expected_grant(spec)?;
                asked.grants.push(spec);
            }
            "--socket" => asked.socket = Some(rest.next()?.as_str()),
            "--direct" => {
                let spec = rest.next()?.as_str();
                expected_direct(spec)?;
                asked.direct.push(spec);
            }
            "--env" => {
                let name = rest.next()?.as_str();
                if name.is_empty() || name.contains('=') {
                    return None;
                }
                asked.env.push(name);
            }
            "--unconfined" => asked.unconfined = true,
            "--experimental-intercept" => asked.intercept = true,
            "--apply" => asked.apply = true,
            "--audit" => asked.audit = true,
            "--" => {
                asked.command = rest.as_slice();
                break;
            }
            _ => return None,
        }
    }

    let shapes_confinement = !asked.direct.is_empty() || !asked.env.is_empty();
    let valid = !asked.grants.is_empty()
        && !asked.command.is_empty()
        && !(asked.unconfined && shapes_confinement)
        && if asked.intercept {
            asked.socket.is_none() && !asked.unconfined && !shapes_confinement
        } else {
            !asked.apply && !asked.audit && (asked.socket.is_none() || asked.unconfined)
        };
    valid.then_some(asked)
}

fn check_grant(spec: &str) {
    match (args::parse_grant(spec), expected_grant(spec)) {
        (Ok(parsed), Some((path, rights))) => {
            assert_eq!(parsed, (PathBuf::from(path), rights), "`--grant {spec}`");
        }
        (Err(message), None) => {
            assert!(message.contains(spec), "{message:?} does not name `{spec}`");
        }
        (Ok(parsed), None) => panic!("`--grant {spec}` was accepted as {parsed:?}"),
        (Err(message), Some(_)) => panic!("`--grant {spec}` was refused: {message}"),
    }
}

fn check_direct(spec: &str) {
    match (args::parse_direct(spec), expected_direct(spec)) {
        (Ok(parsed), Some((path, letters))) => {
            assert_eq!(parsed, (PathBuf::from(path), letters), "`--direct {spec}`");
        }
        (Err(message), None) => {
            assert!(message.contains(spec), "{message:?} does not name `{spec}`");
        }
        (Ok(parsed), None) => panic!("`--direct {spec}` was accepted as {parsed:?}"),
        (Err(message), Some(_)) => panic!("`--direct {spec}` was refused: {message}"),
    }
}

fn check_args(argv: &[String]) {
    let parsed = args::parse_args(argv.iter().cloned());
    let (args, asked) = match (parsed, expected_args(argv)) {
        (Ok(args), Some(asked)) => (args, asked),
        (Err(message), None) => {
            assert!(!message.is_empty(), "an empty error for {argv:?}");
            return;
        }
        (Ok(_), None) => panic!("{argv:?} was accepted"),
        (Err(message), Some(_)) => panic!("{argv:?} was refused: {message}"),
    };

    let Args {
        grants,
        mode,
        command,
    } = args;
    let asked_grants: Vec<_> = asked
        .grants
        .iter()
        .map(|spec| {
            let (path, rights) = expected_grant(spec).expect("checked by expected_args");
            (PathBuf::from(path), rights)
        })
        .collect();
    assert_eq!(grants, asked_grants, "the grants of {argv:?}");
    assert_eq!(command, asked.command, "the command of {argv:?}");
    match mode {
        Mode::Intercept { apply, audit } => {
            assert!(asked.intercept, "{argv:?} became interception mode");
            assert_eq!((apply, audit), (asked.apply, asked.audit), "{argv:?}");
        }
        Mode::Socket(socket) => {
            assert!(
                !asked.intercept && asked.unconfined,
                "{argv:?} became socket mode"
            );
            assert_eq!(Some(socket), asked.socket.map(PathBuf::from), "{argv:?}");
        }
        Mode::Inherited(Start::Unconfined) => {
            assert!(
                !asked.intercept && asked.unconfined && asked.socket.is_none(),
                "{argv:?} started its worker unconfined"
            );
        }
        Mode::Inherited(Start::Confined { direct, env }) => {
            assert!(
                !asked.intercept && !asked.unconfined && asked.socket.is_none(),
                "{argv:?} became confined mode"
            );
            assert_eq!(direct, asked.direct, "the `--direct` specs of {argv:?}");
            assert_eq!(env, asked.env, "the `--env` names of {argv:?}");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let raw: Vec<OsString> = data
        .split(|byte| *byte == 0)
        .map(
            |arg| match OPTIONS.iter().find(|(byte, _)| arg == [*byte]) {
                Some((_, option)) => OsString::from(option),
                None => OsString::from_vec(arg.to_vec()),
            },
        )
        .collect();
    let all_utf8 = raw.iter().all(|arg| arg.to_str().is_some());
    let argv = match args::utf8_args(raw.into_iter()) {
        Ok(argv) => {
            assert!(all_utf8, "an argument that is not UTF-8 was accepted");
            argv
        }
        Err(message) => {
            assert!(!all_utf8, "UTF-8 arguments were refused: {message}");
            return;
        }
    };

    for arg in &argv {
        check_grant(arg);
        check_direct(arg);
    }
    check_args(&argv);
});
