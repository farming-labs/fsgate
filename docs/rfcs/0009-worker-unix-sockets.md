# RFC 0009: keep a confined worker off other Unix sockets

- Status: accepted
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
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | `ENOSYS` |
| a call from another architecture, or an x32 call | kills the process |
| anything else | allowed |

- **`socket(AF_UNIX)`.** Without a new Unix socket there is nothing to
  connect, pathname or abstract. `EACCES` matches the other refusals a
  confined worker gets.
- **`socketpair(AF_UNIX)` stays allowed.** Its two ends are connected to
  each other and reach nothing else, and programs use it for their own
  pipes.
- **`io_uring`.** `IORING_OP_SOCKET` and `IORING_OP_CONNECT` create and
  connect sockets without the system calls a filter sees. `ENOSYS` is
  what a kernel without `io_uring` answers, and libraries fall back to
  ordinary calls. The experimental launcher's profile refuses `io_uring`
  too.
- **Other architectures.** On x86_64, a 32-bit call through `int 0x80`
  arrives with another architecture and other system call numbers, and an
  x32 call sets bit 30 of the number. The filter knows only the native
  table, so it kills the process for those calls instead of guessing.

The domain argument is an `int`, so the filter compares its low 32 bits,
as the kernel does.

The filter is about a dozen BPF instructions, written in fsgate for x86_64
and aarch64. Installing it passes a pointer to the kernel, which needs
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
- A program the worker starts gets the same refusal, so the filter
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
