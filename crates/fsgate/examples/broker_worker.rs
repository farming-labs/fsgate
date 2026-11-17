//! Reads, writes, and lists files through the connection from `fsgate-broker`.

use std::error::Error;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use fsgate::BrokerGate;

const USAGE: &str = "usage: broker_worker <read|write|list> <path>
    run through fsgate-broker --grant <directory>:<rights> -- broker_worker ...
    write copies stdin and replaces existing file contents";

enum Operation {
    Read,
    Write,
    List,
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let operation = args.next();
    if operation.as_deref() == Some(std::ffi::OsStr::new("--help")) && args.next().is_none() {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let operation = match operation.as_deref().and_then(|arg| arg.to_str()) {
        Some("read") => Operation::Read,
        Some("write") => Operation::Write,
        Some("list") => Operation::List,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let Some(path) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    match run(operation, Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("broker_worker: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(operation: Operation, path: &Path) -> Result<(), Box<dyn Error>> {
    let mut gate = BrokerGate::from_inherited()?;
    match operation {
        Operation::Read => {
            let mut file = gate.open(path)?;
            let mut stdout = io::stdout().lock();
            io::copy(&mut file, &mut stdout)?;
            stdout.flush()?;
        }
        Operation::Write => {
            let mut file = gate.create(path)?;
            io::copy(&mut io::stdin().lock(), &mut file)?;
        }
        Operation::List => {
            let mut names = gate.read_dir(path)?;
            names.sort();
            let mut stdout = io::stdout().lock();
            for name in names {
                writeln!(stdout, "{name}")?;
            }
            stdout.flush()?;
        }
    }
    Ok(())
}
