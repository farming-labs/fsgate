# RFC 0013: list a directory without handing out its descriptor

- Status: accepted
- Date: 2026-11-14
- Roadmap: [M9](../../ROADMAP.md#m9--review-readiness-and-020)
- Builds on: [RFC 0001](0001-core-design.md) (the API)
- Revisits: [ADR 0001](../decisions/0001-dependency-pins.md#consequences)'s re-export of cap-std's `ReadDir`

## Problem

`Gate::read_dir` returned cap-std's `ReadDir`. It holds a descriptor for
the listed directory, and each `DirEntry` it yields can open, create,
truncate, stat, and remove what it names relative to that descriptor,
without asking the gate. `open_dir` returns a `Dir` for a subdirectory,
which does all of that beneath it. So `LIST` alone gave every right
beneath the listed directory, none of it audited, and the entries kept
working after `revoke` and `narrow`:

```rust
let grant = gate.grant("/data", Rights::LIST)?;
let entries: Vec<_> = gate.read_dir("/data")?.collect();
gate.revoke(grant)?;
let entry = entries[0].as_ref()?;
entry.open()?;        // reads /data/secret.txt
entry.remove_file()?; // and removes it
```

The internal review at `ea159a6` found it. A process served by a `Broker`
was not affected, because the broker sends names. After `lock()`, the
kernel refuses what the rules do not give, since Landlock checks the
object an open reaches, whichever descriptor it starts from. Before
`lock()`, code that holds a `Gate` could use a listing to get around its
rights and its revocations.

Since 0.3.0 `Gate::open` refuses a directory, because a directory
descriptor is authority the gate cannot see used
([RFC 0003](0003-broker-protocol.md#alternatives-considered)).
`read_dir` handed one out inside the iterator.

## Goals

- A listing gives only what `LIST` means: the names in a directory and
  what each one is.
- Anything beyond the listing goes through the gate, with the rights it
  needs, and is audited.
- A listing gives nothing after `revoke`.

## Non-goals

- Streaming a very large directory. The broker already collects a listing
  into one response.

## Design

```rust
pub use cap_std::fs::{FileType, Metadata};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry { /* name, file type */ }

impl DirEntry {
    pub fn file_name(&self) -> &OsStr;
    pub fn file_type(&self) -> FileType;
}

impl Gate {
    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<Vec<DirEntry>, GateError>;
}
```

- **`read_dir`** opens the directory beneath the grant as before, reads
  every entry, and closes the descriptor before it returns. An error while
  reading fails the whole call and is audited as `allow` with its errno,
  like any error after a policy allow
  ([RFC 0002](0002-audit-events.md)). A partial listing is never
  returned.
- **`DirEntry`** is fsgate's own: a name and a `FileType`, read when the
  directory was listed. It holds no descriptor, so it has no method that
  could reach the filesystem. A symlink is reported as a symlink.
- **Order** is the order the filesystem gives, as before, without `.` and
  `..`.
- **`FileType`** is cap-std's, re-exported like `Metadata`. It is a value
  with no descriptor. `cap_std::fs::FileTypeExt` tells a FIFO, socket, or
  device apart.

`BrokerGate::read_dir` keeps returning names; the broker now builds them
from the new entries, and the protocol does not change.

### Compatibility

Code that iterated `read_dir`'s results as `io::Result<DirEntry>` stops
compiling, and so does code that opened, removed, or stat'ed an entry
through it. That breaks callers, so it ships in 0.5.0. The replacement for
`entry.open()` is `gate.open(dir.join(entry.file_name()))`, which needs
`READ` and is audited; for `entry.metadata()` it is `gate.metadata`.
`fsgate::ReadDir` is removed. A deprecated alias could not help: the type
itself was the defect.

## What this does not stop

- A listing is a snapshot. An entry can be renamed, removed, or replaced
  after `read_dir` returns, and the next gate call sees the directory as it
  is then.
- A directory with many entries is read into memory at once. The same was
  true through the broker.

## Testing

- A `compile_fail` doctest on `DirEntry`: calling `open` on an entry does
  not compile. On `main` before this change, a `LIST`-only listing opened
  and removed a file after `revoke`, which a scratch test showed; it cannot
  be a test now, because the code no longer compiles.
- `gate.rs`: a listing has each entry's name and type, without `.` and
  `..`, reports a symlink as a symlink, and is unchanged when the directory
  changes after `read_dir` returns.
- `gate_model.rs` and the `gate_paths` fuzz target compare a listing's
  names and types with the directory the path should reach, instead of
  the inode numbers of its entries, which an entry no longer has. A
  listing that matches gives the caller what the target's listing gives.
  The fuzz target also asserts that every directory in its fixture lists
  something different, so its check still names the directory. The
  model's generated trees reuse four names, so a listing there can match
  another directory's; its `open` and `metadata` checks, which route and
  resolve the same way, still compare inode numbers.

## Alternatives considered

- **Keep `ReadDir` and document it.** No caller breaks, but `LIST` keeps
  meaning every right, and the threat model's `revoke` row stays false for
  listings.
- **Wrap `ReadDir` as a lazy iterator.** It keeps the descriptor open
  after `read_dir` returns, so a revoked grant keeps listing, and an error
  partway through reaches the caller unaudited.
- **Return only names**, as the broker does. A caller that needs the type
  would stat each entry through the gate, which needs `READ` as well as
  `LIST`, and costs a call per entry.

## Decisions

1. Return names and types, in 0.5.0 (maintainer, 2026-11-14).
