# fsgate fuzz targets

**Fuzzing for the inputs an untrusted worker controls.** This is a separate Cargo workspace. It is not published, and its lockfile pins fsgate's dependencies at the same versions as the main `Cargo.lock`.

## `broker_requests`

The target feeds arbitrary bytes to one `Broker::serve_conn` connection, as a hostile worker would. That covers the [RFC 0003](../docs/rfcs/0003-broker-protocol.md) frame reassembly and 1 MiB limit, JSON request parsing, and the gate's path handling behind them.

It fails on a panic, a hang, or a sanitizer report. It also fails if any descriptor the broker sends back reads the file outside the grant.

- **Deterministic input.** The whole input is queued on the socket before the broker reads, so a saved crash reproduces. Inputs above 128 KiB are skipped: that is enough for a frame to span two of the broker's 64 KiB reads, and it fits Linux's default socket buffer cap.
- **Fixture.** The target grants `READ | LIST` on `/tmp/fsgate-fuzz/granted`. A sibling directory holds the secret, and a symlink inside the grant points at it. The path is fixed so seeds can name files beneath the grant. The target refuses to start unless `/tmp/fsgate-fuzz` is a directory this user owns that nobody else can write.
- **Seeds.** `seeds/broker_requests/` has one valid frame for each operation, plus escape attempts (`..`, a symlink) and protocol violations: a malformed body, an unknown operation, an oversized prefix, a prefix shorter than its body, and a truncated body.

## Running

Needs a nightly toolchain and `cargo install cargo-fuzz --locked`.

```sh
cd fuzz
mkdir -p corpus/broker_requests
cargo +nightly fuzz run broker_requests corpus/broker_requests seeds/broker_requests -- \
  -max_len=131072 -timeout=10 -max_total_time=900
```

`corpus/` and `artifacts/` are ignored by git. If the run finds a crash, add the input from `artifacts/` as a regression test in `crates/fsgate/tests/broker.rs`, then fix the code.

CI builds and lints this crate on stable on every change. [`fuzz.yml`](../.github/workflows/fuzz.yml) runs this target for 15 minutes on Linux when `broker.rs` or this crate changes, and on demand. A finding fails the job and attaches the input to the run as an artifact.
