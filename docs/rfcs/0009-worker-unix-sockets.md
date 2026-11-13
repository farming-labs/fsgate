# RFC 0009: keep a confined worker off other Unix sockets

- Status: accepted ([#71](https://github.com/farming-labs/fsgate/pull/71)); implemented in [#76](https://github.com/farming-labs/fsgate/pull/76)
- Date: 2026-11-10
- Roadmap: [M9](../../ROADMAP.md#m9--review-readiness-and-020)
- Builds on: [RFC 0006](0006-lock-restrictions.md) (restrictions at `lock()`), [RFC 0008](0008-confine-broker-worker.md) (the confined worker), the [threat model](../threat-model.md#3-the-broker-and-its-worker)

## Problem

Landlock restricts connects to pathname Unix sockets from Linux 7.1 (ABI
9), and to abstract ones from 6.12 (ABI 6). Before that, a worker
`fsgate-broker` confines can connect to any Unix socket it can name. Some
of those services act with their own authority. On a desktop, the session
bus at `/run/user/<uid>/bus` reaches systemd's user manager, and one
`StartTransientUnit` call, which is what `systemd-run --user` sends,
starts a program outside the confinement with the user's full access. The
grants, the audit sink, and revocation all stop applying.

The threat model and README say this. Nearly every system runs a kernel
before 7.1 today, so for most users the confinement has a documented hole
that a worker can use with one connect.

A confined worker does not need a new Unix socket. It holds its broker
connection before it is confined (RFC 0008), and `--socket`, the only form
that connects later, already requires `--unconfined`.

## Goals

- On a kernel where Landlock does not restrict pathname socket connects,
  a confined worker and everything it starts cannot connect to any Unix
  socket, pathname or abstract.
- It keeps its inherited broker connection and its standard streams.
- If this cannot be applied, the worker does not start.
- On Linux 7.1 and later, nothing changes: Landlock already does this.

## Non-goals

- **Network sockets.** fsgate does not restrict the network in v1. A
  worker can still open TCP and UDP sockets.
- **Inspecting connect addresses.** That would need seccomp user
  notification and a supervisor that reads the worker's memory, which is
  RFC 0004's machinery and its time-of-check problems.
- **Sockets the worker already holds.** Standard streams that are sockets,
  such as a journald stream, stay usable.

## Design

### A seccomp filter after the Landlock rules

The confining process (RFC 0008) gains one step, after it restricts itself
and before it marks descriptors close-on-exec. It reads the effective
Landlock ABI that `restrict_self` reports. Below ABI 9, it installs a
seccomp filter. Landlock has already set `no_new_privs`, so no privilege
is needed, and the filter can never be removed. Every program the worker
starts inherits it, across `exec`.

The filter answers:

| Call | Answer |
|---|---|
| `socket` with domain `AF_UNIX` | `EACCES` |
| `socketpair` with domain `AF_UNIX` and any type but `SOCK_STREAM` and `SOCK_SEQPACKET` | `EACCES` |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | `ENOSYS` |
| a call from another architecture, or an x32 call | kills the process |
| anything else | allowed |

- **`socket(AF_UNIX)`.** Without a new Unix socket there is nothing to
  connect, pathname or abstract. `EACCES` matches the other refusals a
  confined worker gets.
- **Stream and seqpacket pairs stay allowed.** `socketpair` with
  `SOCK_STREAM` or `SOCK_SEQPACKET` makes two ends that stay connected to
  each other and reach nothing else, and programs use them for their own
  pipes. Every other pair is refused. Either end of a `SOCK_DGRAM` pair
  can send to any datagram socket by address, and connect to another, and
  the kernel makes a Unix `SOCK_RAW` socket a datagram one. The filter
  compares the type without `SOCK_CLOEXEC` and `SOCK_NONBLOCK`.
- **`io_uring`.** `IORING_OP_SOCKET` and `IORING_OP_CONNECT` create and
  connect sockets without the system calls a filter sees. `ENOSYS` is
  what a kernel without `io_uring` answers, and libraries fall back to
  ordinary calls. The experimental launcher's profile refuses `io_uring`
  too.
- **Other architectures.** On x86_64, a 32-bit call through `int 0x80`
  arrives with another architecture and other system call numbers, and an
  x32 call sets bit 30 of the number. The filter knows only the native
  table, so it kills the process for those calls instead of guessing.

The domain and type arguments are `int`s, so the filter compares their
low 32 bits, as the kernel does.

The filter is 18 BPF instructions, written in fsgate for x86_64 and
aarch64. Installing it passes a pointer to the kernel, which needs
`unsafe`. It goes in the existing `sys` module of `confine.rs` with a
written safety contract, as `close_range` does. On any other
architecture, confinement fails before the worker starts and names
`--unconfined`, as on a kernel without Landlock.

### What a worker sees

On Linux 6.6, `UnixStream::connect` to any path fails with `EACCES`, and
so does `UnixListener::bind`. glibc's lookups through `nscd` and
`systemd-userdb` fail and fall back to files, and `syslog(3)` drops its
messages, as they do without those services. Programs that need D-Bus,
X11, Wayland, or PulseAudio cannot reach them, which is the point and
what Landlock already does on 7.1.

On Linux 7.1 and later, nothing changes. A worker can create Unix sockets,
and Landlock refuses connects to those created outside its sandbox.

### Compatibility

This changes the confined worker on kernels before 7.1, so it goes in the
changelog under Changed. `--unconfined` is unaffected. A worker that
needs a Unix socket service before 7.1 must run with `--unconfined`, the
same choice it would face on 7.1.

## What this does not stop

- A worker using its broker connection. The grants are the ceiling.
- A worker using a socket it holds on its standard streams.
- Network sockets, including a TCP service on `localhost` that acts for
  its callers.
- Before Linux 6.12, signals to the broker. Landlock scopes signals from
  6.12.

## Testing

Security tests run the real `fsgate-broker` on the real kernel, and
assert the refusal and the absence of the side effect:

- The test listens on a pathname socket outside the grants. A confined
  worker's connect to it fails with `EACCES`, and the listener accepts no
  connection. With `--unconfined`, the same worker connects, so the test
  can tell the difference. This runs on Linux 6.6, where the filter
  applies, and on 7.3, where Landlock refuses the connect.
- On Linux 6.6, `socket(AF_UNIX)` itself fails with `EACCES`, and so does
  binding an abstract name. On 7.3, creating one succeeds.
- A datagram to a pathname socket outside the grants, from a socket of
  the worker's own and from half of a datagram or raw pair, reaches nothing on
  either kernel, and does with `--unconfined`.
- On Linux 6.6, a datagram pair fails with `EACCES`, and stream and
  seqpacket pairs and a TCP socket still work. `io_uring_setup`,
  `io_uring_enter`, and `io_uring_register` fail with `ENOSYS`, from a
  test-only module with its own safety contract. On x86_64, a program
  that makes an x32 call is killed by `SIGSYS`.
- A program the worker starts gets the same refusals, so the filter
  survives `exec`.
- The worker still reaches the broker through its inherited connection.

Not testable in CI: a foreign-architecture call, and a kernel that
refuses the filter.

## Alternatives considered

- **Refuse confinement before 7.1.** Closes the hole, but no worker could
  be confined on nearly any system today.
- **Leave it documented.** One connect undoes the confinement.
- **Refuse `connect` instead of `socket`.** A filter cannot read the
  address, so it would refuse TCP connects too, and fsgate does not
  restrict the network.
- **A network namespace.** Abstract sockets belong to a network
  namespace, but pathname sockets are found through the filesystem.
- **A mount namespace that hides `/run/user`.** It needs unprivileged
  user namespaces, which Ubuntu 24.04 and later restrict by default, and
  sockets elsewhere would stay reachable.
- **The `seccompiler` crate.** It does what a dozen instructions do here,
  and adds a dependency with its own `unsafe`.

## Open questions

1. Should the filter apply on every kernel, so behavior does not depend
   on the Landlock ABI? That would also refuse sockets a worker creates
   for itself on 7.1, which Landlock allows.
2. Testing the `io_uring` refusal needs an `unsafe` call in a test, since
   `rustix` marks `io_uring_setup` unsafe. Is a test-only module with its
   own safety contract acceptable, or should that row of the threat model
   say it is untested?

## Decisions

Accepted in [#71](https://github.com/farming-labs/fsgate/pull/71), with its
open questions answered:

1. The filter applies only below Landlock ABI 9. On Linux 7.1 and later,
   Landlock refuses connects to sockets created outside the sandbox, and a
   worker keeps the sockets it makes for itself.
2. The `io_uring` refusal is tested with an `unsafe` call in a test-only
   module that has its own safety contract.

## Changes during implementation

1. **A datagram pair is refused.** As accepted, the filter allowed every
   `socketpair(AF_UNIX)`, on the grounds that its ends reach only each
   other. That holds for stream and seqpacket pairs, which stay connected,
   but not for a datagram pair: either end can `sendto` any datagram
   socket by path or abstract name, and `connect` to another. The
   unconfined control in
   `broker_confined.rs::kernel::a_confined_worker_cannot_reach_a_unix_socket`
   shows a datagram from half of a pair reaching a socket outside the
   grants, and the confined run shows the filter refusing the pair.
2. **The x32 refusal is tested** on x86_64, by a program that makes an
   x32 `getpid` and is killed by `SIGSYS`. A call from another
   architecture is still not tested.
3. **Where the filter is written for.** x86_64 means the 64-bit ABI, not
   an x32 build, and aarch64 means little-endian with 64-bit pointers.
   Below Linux 7.1, a confined worker on any other target does not start,
   and the error names `--unconfined`.

## Changes after release

1. **Only stream and seqpacket pairs are allowed.** 0.4.0 refused a
   `socketpair(AF_UNIX)` only when its type was `SOCK_DGRAM`. The kernel
   makes a Unix `SOCK_RAW` socket a datagram one (`unix_create` in
   `net/unix/af_unix.c`), so below Linux 7.1 a confined worker could
   still make a datagram pair by asking for `SOCK_RAW` and send from it to
   any datagram socket it could name. The filter now allows a Unix pair
   only for `SOCK_STREAM` and `SOCK_SEQPACKET`, the two types that stay
   connected to each other, and refuses every other type, including types
   a later kernel might add. `a_confined_worker_cannot_reach_a_unix_socket`
   sends a datagram from half of a raw pair, and unit tests run the
   filter's instructions on each call it answers.
