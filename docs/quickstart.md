# Run a worker through the broker

Build a worker that reads, writes, and lists files through fsgate. This
walkthrough uses the checked-out source and Rust 1.85 or later. It needs no
service, socket path, or experimental feature.

## Build the example

From the repository root:

```sh
cargo build --locked --release --target-dir target --bin fsgate-broker --example broker_worker
broker="$(pwd)/target/release/fsgate-broker"
worker="$(pwd)/target/release/examples/broker_worker"
```

The [worker source](../crates/fsgate/examples/broker_worker.rs) uses
`BrokerGate::from_inherited()` to adopt the connection passed by the broker.
Every data-file operation goes through that connection. It does not use
`std::fs` to open data directly.

On Linux x86_64 and aarch64, the broker confines this worker before it starts.
The kernel must provide Landlock ABI 3 (Linux 6.2 or later) with Landlock enabled.
If it cannot apply confinement, launch fails. On macOS, use the explicit
`--unconfined` form below: broker requests still obey grants, but the worker
retains its ordinary filesystem access. This example does not claim macOS
process containment.

## Make disposable data

Run these commands in the same shell as the build:

```sh
demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/fsgate-demo.XXXXXX")"
mkdir "$demo_dir/data" "$demo_dir/outside"
printf 'hello from fsgate\n' > "$demo_dir/data/input.txt"
printf 'outside the grant\n' > "$demo_dir/outside/private.txt"
```

Define the launcher for your platform. On Linux:

```sh
run_worker() {
  "$broker" --grant "$demo_dir/data:$1" -- "$worker" "$2" "$3"
}
```

On macOS:

```sh
run_worker() {
  "$broker" --unconfined --grant "$demo_dir/data:$1" -- "$worker" "$2" "$3"
}
```

## Read, write, and list

```sh
run_worker r read "$demo_dir/data/input.txt"
# hello from fsgate

printf 'written through the broker\n' | run_worker wc write "$demo_dir/data/output.txt"
run_worker r read "$demo_dir/data/output.txt"
# written through the broker

run_worker l list "$demo_dir/data"
# input.txt
# output.txt
```

| Operation | Rights | Worker call |
|---|---|---|
| `read` | `r` | `gate.open(path)`, then copy the file to stdout |
| `write` | `wc` | `gate.create(path)`, then copy stdin to the file |
| `list` | `l` | `gate.read_dir(path)`, then print sorted names |

`write` creates a file or **truncates an existing file**. It is a streaming
write, not an atomic replacement: an I/O failure can leave partial contents.
Use the disposable directory for this walkthrough. The broker does not create
missing parent directories. Input and output may contain arbitrary bytes;
the broker protocol requires UTF-8 paths and directory entry names.

Each command starts a fresh broker and worker. The worker holds only the
returned file descriptors, and the broker exits when that worker finishes.
There is no socket file to remove. This example uses the inherited connection;
`--socket` is a different connection mode and is not supported by the example.

## See a refusal

These commands intentionally fail with a nonzero exit status and an error on
stderr. A refused read prints no file contents:

```sh
run_worker r read "$demo_dir/outside/private.txt"
```

A read-only grant cannot create or truncate a file:

```sh
printf 'must not be written\n' | run_worker r write "$demo_dir/data/refused.txt"
test ! -e "$demo_dir/data/refused.txt"

printf 'must not replace input\n' | run_worker r write "$demo_dir/data/input.txt"
run_worker r read "$demo_dir/data/input.txt"
# hello from fsgate
```

Running the worker directly without the broker reports the missing inherited
connection. Running it with `--help` prints its arguments without connecting.

## Use it in your worker

Add the library with `cargo add fsgate`, then adopt the connection once, before
starting other programs. Read from and write to the returned `File` normally:

```rust,no_run
use fsgate::BrokerGate;
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut gate = BrokerGate::from_inherited()?;
    let mut input = gate.open("/srv/data/input.txt")?;
    io::copy(&mut input, &mut io::stdout().lock())?;
    Ok(())
}
```

Start it with `fsgate-broker --grant /srv/data:r -- ./your-worker` on Linux.
Ordinary file opens in a program that does not use `BrokerGate` are a separate
[experimental interception mode](interception.md). It supports a limited Linux
x86_64 read-only profile; dynamically linked programs require explicit runtime
grants for their loader and libraries. This walkthrough uses the supported broker
API.

## Clean up

When you are finished, remove the disposable directory created above:

```sh
rm -r -- "$demo_dir"
unset -f run_worker
unset demo_dir broker worker
```
