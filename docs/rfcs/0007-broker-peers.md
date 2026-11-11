# RFC 0007: decide who can reach the broker

- Status: accepted ([#46](https://github.com/farming-labs/fsgate/pull/46)); implemented in [#47](https://github.com/farming-labs/fsgate/pull/47) and [#48](https://github.com/farming-labs/fsgate/pull/48)
- Date: 2026-11-08
- Roadmap: [M9](../../ROADMAP.md#m9--review-readiness-and-020)
- Builds on: [RFC 0003](0003-broker-protocol.md) (broker protocol), the [threat model](../threat-model.md#3-the-broker-and-its-worker)

## Problem

Whoever can connect to the broker's socket has the broker's grants. RFC
0003 made that a non-goal and left it to the embedder, but `fsgate-broker`
is not an embedder's code, and the README's first example runs it with a
socket in `/tmp`. The threat model lists two gaps with no test:

1. **Another process connecting.** `fsgate-broker` binds with the process
   umask and checks no peer. The socket's mode follows the umask: `0755`
   under `022`, and `0777` under `000` (measured on macOS, Darwin 25.2).
   Under a loose umask, any local user who can reach the path gets the
   grants. Under the usual `022`, every process of the same user still does.
2. **Many connections at once.** `Broker::serve` starts a thread per
   connection with no limit, and each can buffer about 1 MiB.

The broker is what makes fsgate usable on macOS, and the independent
review (M9) will start here. These should be settled before it.

## Goals

- `fsgate-broker` can give its command a connection no other process can
  connect to, with no name in the filesystem.
- A pathname socket from `fsgate-broker` is owner-only whatever the umask,
  with no moment when it is looser.
- `Broker::serve` refuses peers running as another user unless the
  embedder allows them.
- `Broker::serve` has a limit on connections.
- A denied peer gets a closed connection and no answer. Nothing falls back
  to serving it.

## Non-goals

- **Stopping the same user on a pathname socket.** A process of the same
  user can already signal the broker, and trace it where the system's
  ptrace policy allows. Inherited connections are the answer for that.
- **Identifying the peer's program.** See the alternatives.
- **Rate limits or quotas** (out of scope for v1), or an idle timeout: a
  worker may be idle between requests for as long as it likes.
- **Changing the wire format.** RFC 0003 frames are unchanged.

## Design

### An inherited connection

`--socket` becomes optional. Without it, `fsgate-broker` creates a
socketpair, serves one end with `serve_conn`, and passes the other to its
command, naming the descriptor in `FSGATE_BROKER_FD`:

```sh
fsgate-broker --grant /srv/data:rl -- ./worker
```

No other process can connect to it, because it has no name. Programs the
command starts before it adopts the connection inherit it too, and a
process allowed to trace the worker or broker can copy it. It needs no
`pre_exec`, so no `unsafe` in the broker: the parent clears close-on-exec
on the child's end just before spawning and closes its copy afterwards
(measured on macOS). `fsgate-broker` starts only that one program.

It also removes an ordering rule. A worker that calls `lock()` must
otherwise connect first, because Linux 7.1 and later refuse new connects
after the lock ([RFC 0006](0006-lock-restrictions.md)). An inherited
connection is never a connect.

The worker adopts it with a new constructor:

```rust
let mut gate = BrokerGate::from_inherited()?;
```

`from_inherited` reads `FSGATE_BROKER_FD`, checks that the number names an
inherited Unix stream socket, marks it close-on-exec so the worker's own children do
not inherit it, and fails with `GateError::Broker` and the remedy
otherwise. A second call fails, because a descriptor can have only one
owner. Turning the number into an `OwnedFd` is `unsafe`, so it goes in an
isolated module with a written safety contract, as AGENTS.md requires.

A worker gets one lockstep connection. One that needs several still uses
`--socket`.

### Owner-only pathname sockets

With `--socket`, `fsgate-broker` calls `socket`, `bind`, `chmod 0600`, then
`listen`, through `rustix`, instead of `UnixListener::bind`, which does the
bind and listen together. A connect before `listen` is refused (measured
on macOS), so the socket is never reachable while its mode is loose. If
the `chmod` fails, the broker exits with the error before starting the
command.

Workers find the broker by that path, so a mode on the socket is not
enough: whoever can rename an entry along the path can put their own
socket in its place. Before binding, the broker checks every directory
the path passes through, before and after resolving symlinks. Each must
belong to the broker's user or root, and must not be writable by others
unless it is sticky, as `/tmp` is. Otherwise it exits 1 before binding.

### A peer check in `Broker::serve`

`serve` compares each accepted peer's kernel-reported uid with an allow
set, and closes the connection without answering if it is not in the set.
The default set is the broker's effective uid. An embedder that runs its
worker as another user, a common way to separate privileges, says so:

```rust
broker.serve_with(&listener, ServeOptions::default().allow_peer_uids([worker_uid]))?;
```

`serve(&listener)` is `serve_with` with the defaults, the shape of
`Gate::lock` and `Gate::lock_with`. `serve_conn` is unchanged: its caller
already chose the stream.

Linux uses `SO_PEERCRED`, which `rustix` provides. macOS uses
`getpeereid`, which `rustix` does not, so it needs a direct `libc`
dependency on macOS and the same isolated `unsafe` module. On any other
platform `serve` fails with `ErrorKind::Unsupported` before accepting
anything, unless the caller sets `ServeOptions::any_peer`, so a missing
check is never silent.

### A connection limit

`ServeOptions::max_connections` defaults to 64, which bounds the broker at
64 threads and about 64 MiB of buffered requests. At the limit, `serve`
closes each new connection at once, and the worker gets the usual
fail-closed `GateError::Broker`. It does not queue them: a queue would
hold descriptors, and hang a worker with no error. A peer that holds its
slots idle can still use up the limit; after the uid check that is the
same user or one the embedder allowed.

### Compatibility

The library changes are behavior changes for a minor release, so they
belong in 0.2.0, and the changelog names them:

- `Broker::serve` refuses peers of other users by default.
- `Broker::serve` closes connections past 64.
- `fsgate-broker --socket` creates a `0600` socket. A worker of another
  user or group that relied on a looser umask loses access. It can use
  the library with `allow_peer_uids`.

`BrokerGate::connect`, `from_stream`, and `serve_conn` do not change.
`--socket` keeps working, so existing command lines do too.

## Testing

Security tests assert the denial and the absence of the side effect,
against real sockets:

- `fsgate-broker` with `--socket` under `umask 000` creates a `0600`
  socket. The real binary, on Linux and macOS.
- `fsgate-broker` with no `--socket` serves a worker through
  `from_inherited`, and creates no socket file.
- `from_inherited` refuses a missing variable, a number that is not a
  descriptor, a descriptor that is not a Unix stream socket, and a second
  call, and the adopted descriptor is close-on-exec.
- A peer outside the allow set gets no answer and no file is created. CI
  has one user, so the test allows only a uid other than its own, which
  exercises the real kernel credentials without a second account. A second
  case allows its own uid and is served.
- With `max_connections(1)`, a second connection is closed without an
  answer, and a new one is served once the first ends.

The ordering of `chmod` before `listen` cannot be observed from a test; it
is a property of the code, for review.

## Alternatives considered

- **A shared secret in the first frame.** Changes the wire format, and an
  environment variable is readable by the same user through `/proc`, so
  it stops nothing the uid check does not.
- **Checking the peer's executable or pid.** Pids are reused, and an
  executable path says nothing about what a process has been made to do.
- **`umask` around `bind`.** The umask is process-wide, so it races any
  other thread creating files.
- **A private `0700` directory for the socket.** Sound, but it changes
  what `--socket <path>` means, and `chmod` before `listen` gets the same
  result without that.
- **The worker's stdin as the connection.** Needs no `unsafe` anywhere, but
  takes stdin from every worker.
- **Queueing past the limit.** See the connection limit.

## Decisions

Accepted in [#46](https://github.com/farming-labs/fsgate/pull/46), with its
open questions answered:

1. `max_connections` defaults to 64.
2. The README leads with the inherited form, the safe one to copy.
3. A refused peer produces no audit event. RFC 0002 events describe
   operations on paths, and a refused peer has none. Superseded by
   [RFC 0011](0011-audit-broker-refusals.md): a refused peer, a
   connection past the limit, and a request that breaks the protocol are
   each one event.
