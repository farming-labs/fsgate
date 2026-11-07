# RFC 0003: broker protocol

- Status: accepted
- Date: 2026-11-06

## Problem

Where Landlock does not exist (macOS today), kernel containment has to be
structural: the worker process holds no filesystem authority, and a
trusted broker process holds the `Gate` and performs every operation on
the worker's behalf. The two need a wire protocol that keeps all policy
server-side and fails closed when the broker is gone.

## Design

### Transport

A `SOCK_STREAM` Unix domain socket. The `fsgate-broker` binary publishes
its socket path to the child in `FSGATE_BROKER_SOCKET`; embedders may
instead pass an inherited socketpair to `BrokerGate::from_stream`.

### Framing

Every message is a 4-byte little-endian length followed by that many
bytes of JSON. Frames above 1 MiB are a protocol violation; the receiver
fails the connection closed. A response that carries a file descriptor
attaches exactly one via `SCM_RIGHTS` ancillary data on the same message.
The receiver marks every received descriptor close-on-exec, so a
delivered file does not leak into programs the worker starts. Linux
does this atomically with `MSG_CMSG_CLOEXEC`; other platforms set
`FD_CLOEXEC` right after `recvmsg`, so a thread that forks and execs in
that window can still inherit the descriptor.
The client is strictly lockstep: one request, then its response.

### Messages

Requests (`op` tag): `open`, `create`, `metadata`, `read_dir`, each with
a `path` string. Paths and directory entry names must be valid UTF-8 on
this transport; anything else is refused with an error, never transcoded.

Responses (`result` tag):

- `fd` — success for `open`/`create`; the descriptor is in the ancillary
  data.
- `stat` — `{is_dir, is_file, len}` for `metadata`.
- `entries` — entry name list for `read_dir`.
- `error` — `{kind, message, path?, grant_path?, missing?, op?, errno?}`.
  Kinds mirror `GateError`: `not_absolute`, `no_grant`,
  `rights_exceeded` (with the missing rights as bits), `io` (with the OS
  errno), and `broker` for everything else. The client reconstructs the
  same typed `GateError` the in-process gate would have returned.

### Authority

The broker deserializes the path and hands it to its own `Gate`. The
normalization, grant routing, rights checks, and beneath-handle opens are
the same code as in-process use — the worker is never trusted with any
part of the decision, and a compromised worker can at most ask, be
denied, and be logged (M4).

### Failure semantics

A lost, closed, or protocol-violating connection maps every subsequent
client operation to `GateError::Broker`. There is no reconnect, retry,
or local fallback; a worker that outlives its broker has no filesystem.

## Non-goals

Non-UTF-8 paths (revisit if a real embedder needs them), multiplexed or
pipelined requests, streaming directory iteration, and cross-machine
transport. The protocol is same-host, version-locked to the crate.

## Alternatives considered

- **seqpacket sockets** for self-delimiting messages: not in `std`, and
  stream framing is 20 lines.
- **binary serde (bincode)** over JSON: saves bytes that do not matter at
  this call rate; JSON keeps captures debuggable with `socat`.
- **Sending directory descriptors to the worker** so it can `openat`
  locally: faster, but it moves authority into the untrusted process and
  dissolves the structural guarantee; rejected.
