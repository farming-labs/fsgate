# fsgate fuzz targets

**Fuzzing for the inputs an untrusted worker controls, the paths a gate resolves, and the broker's command line.** This is a separate Cargo workspace. It is not published, and its lockfile pins fsgate's dependencies at the same versions as the main `Cargo.lock`.

| Target | Input | Fails when |
|---|---|---|
| `broker_requests` | Bytes on one broker connection | A descriptor the broker sends back reads the file outside the grant |
| `gate_paths` | Operations on paths beneath a fixed tree | An operation reaches or changes anything outside the grant its path routes to |
| `broker_args` | `fsgate-broker` command lines | The parser accepts, refuses, or grants other than its rules say |

Each also fails on a panic, a hang, or a sanitizer report.

## `broker_requests`

The target feeds arbitrary bytes to one `Broker::serve_conn` connection, as a hostile worker would. That covers the [RFC 0003](../docs/rfcs/0003-broker-protocol.md) frame reassembly and 1 MiB limit, JSON request parsing, and the gate's path handling behind them.

- **Deterministic input.** The whole input is queued on the socket before the broker reads, so a saved crash reproduces. Inputs above 128 KiB are skipped: that is enough for a frame to span two of the broker's 64 KiB reads, and it fits Linux's default socket buffer cap.
- **Fixture.** The target grants `READ | LIST` on `/tmp/fsgate-fuzz/granted`. A sibling directory holds the secret, and a symlink inside the grant points at it. The path is fixed so seeds can name files beneath the grant. The target refuses to start unless `/tmp/fsgate-fuzz` is a directory this user owns that nobody else can write.
- **Seeds.** `seeds/broker_requests/` has one valid frame for each operation, plus escape attempts (`..`, a symlink) and protocol violations: a malformed body, an unknown operation, an oversized prefix, a prefix shorter than its body, and a truncated body.

## `gate_paths`

The target runs `open`, `create`, `metadata`, and `read_dir` on arbitrary paths through one `Gate`, without the broker. It rebuilds the tree at `/tmp/fsgate-fuzz/paths` when it starts, under the same check on `/tmp/fsgate-fuzz`.

- **Tree.** Three grants: `granted` with `READ | LIST`, and inside it `granted/nested` with `READ` and `granted/w` with every right. Around them are a sibling directory with the secret, a sibling whose name starts with the grant's (`granted-evil`), FIFOs, and symlinks that stay inside, climb out with `..`, are absolute, dangle, or loop. Some lead from a nested grant into the one around it, so a symlink can reach a file another grant covers. No symlink leads out of the tree.
- **Checks.** A success must reach an object, found by device and inode, beneath the grant the path routes to, and a listing must be one of a directory there. A refusal must be the one the routing calls for: `NotAbsolute`, `NoGrant`, `RightsExceeded`, or an I/O error once policy allows the operation. `open` must never return a directory. The tree must not change, except that a `create` may make or truncate the file it returns, beneath its grant; the target then puts the tree back.
- **Input.** One operation a line. The first byte is `o`, `c`, `m`, or `d`, and the rest of the line is a path relative to the tree. In upper case, the letter takes the rest as the whole path, so it can be relative or name anything on the system.
- **Seeds.** `seeds/gate_paths/` has reads inside the grants, every escaping symlink, `..` out of a grant, a nested grant's missing rights, creates that should succeed and creates through symlinks that leave their grant, and odd paths: a relative one, a trailing slash, the sibling, a loop, a dangling link, a FIFO, and a NUL byte. `dicts/gate_paths.dict` holds the tree's names.
- **One process.** The tree is shared, so run one fuzzing process at a time, and not alongside another `gate_paths` run.

## `broker_args`

The target feeds arbitrary argument lists to the parser in [`fsgate-broker/args.rs`](../crates/fsgate/src/bin/fsgate-broker/args.rs), which it includes as a module. Each `--grant` and `--direct` spec, the modes, and the options that pick them are compared with a restatement of the parser's rules. Every argument is also parsed alone as a `--grant` and as a `--direct` spec.

- **Input.** Arguments are split at NUL bytes, as `execve` passes them. An argument that is one of the bytes `G D E S U I A T H -` stands for `--grant`, `--direct`, `--env`, `--socket`, `--unconfined`, `--experimental-intercept`, `--apply`, `--audit`, `--help`, or `--`. One changed byte then swaps one option for another. In their full spelling, the fuzzer had not combined two options in five minutes.
- **Seeds.** `seeds/broker_args/` has one command line for each mode, a path with a colon, and one for each refusal: no rights, an unknown letter, a relative or writable `--direct`, `--direct` with `--unconfined`, `--socket` without it, interception with either, an `--env` assignment, a non-UTF-8 argument, an option as a value, no command, and `--help`. One seed spells the options out. `dicts/broker_args.dict` holds the option names and rights letters.

## Running

Needs a nightly toolchain and `cargo install cargo-fuzz --locked`.

```sh
cd fuzz
mkdir -p corpus/broker_requests corpus/gate_paths corpus/broker_args
cargo +nightly fuzz run broker_requests corpus/broker_requests seeds/broker_requests -- \
  -max_len=131072 -timeout=10 -max_total_time=900
cargo +nightly fuzz run gate_paths corpus/gate_paths seeds/gate_paths -- \
  -max_len=4096 -dict=dicts/gate_paths.dict -timeout=10 -max_total_time=900
cargo +nightly fuzz run broker_args corpus/broker_args seeds/broker_args -- \
  -max_len=4096 -dict=dicts/broker_args.dict -timeout=10 -max_total_time=900
```

`corpus/` and `artifacts/` are ignored by git. If a run finds a crash, add the input from `artifacts/` as a regression test, then fix the code. The test goes in `crates/fsgate/tests/gate.rs` for `gate_paths` and in `tests/broker.rs` for the other two, where `broker_usage` runs the broker with given arguments.

CI builds and lints this crate on stable on every change. [`fuzz.yml`](../.github/workflows/fuzz.yml) runs each target for 15 minutes on Linux, and `gate_paths` on macOS too, when the crate or this directory changes, and on demand. Every Monday it runs each for an hour. A finding fails the job and attaches the input to the run as an artifact.
