# RFC 0008: confine the worker `fsgate-broker` starts

- Status: accepted and implemented in [#51](https://github.com/farming-labs/fsgate/pull/51)
- Date: 2026-11-09
- Roadmap: [M9](../../ROADMAP.md#m9--review-readiness-and-020)
- Builds on: [RFC 0003](0003-broker-protocol.md) (broker protocol), [RFC 0004](0004-filesystem-interception.md) (the launcher's worker profile), [RFC 0006](0006-lock-restrictions.md) (restrictions at `lock()`), [RFC 0007](0007-broker-peers.md) (the inherited connection), the [threat model](../threat-model.md#3-the-broker-and-its-worker)

## Problem

`fsgate-broker` starts its command as the same user, with the same
environment and filesystem access as itself. The grants decide what the
broker will open. Nothing decides what the worker can open on its own. A
compromised worker does not need the broker: it calls `open` on
`~/.ssh/id_ed25519` directly.

The threat model lists this as the embedder's job, and RFC 0003 made it a
non-goal. That is fair for a library, but `fsgate-broker` is not an
embedder's code. It is the command the README tells people to run, and the
grants on its command line read like a limit on the worker.

A worker can call `lock()` itself. That helps only if it does so before
the hostile code runs, and a worker that is the hostile code never will.

Privilege separation has always confined this side. In the
[OpenSSH design](https://www.usenix.org/events/sec03/tech/full_papers/provos_et_al/provos_et_al_html/index.html)
this broker resembles, the worker changes to unused user and group IDs
before it handles network input. The experimental launcher (RFC 0004)
confines static binaries. Ordinary workers have nothing.

## Goals

- On Linux, a worker started by `fsgate-broker` reaches data only through
  the broker.
- An ordinary dynamically linked program still starts.
- If confinement cannot be applied, the worker does not run.
- Running a worker unconfined is something the command line says.
- The worker does not inherit the broker's environment or stray
  descriptors.

## Non-goals

- **macOS containment.** The `sandbox-exec` and `sandbox_init` man pages
  mark both as deprecated (Darwin 25.2), and fsgate has no other mechanism
  there.
- **Network access.** Out of scope for v1.
- **A library API for embedders.** One can follow if an embedder asks.
- **Unmodified programs.** A confined worker that does not use
  `BrokerGate` gets `EACCES` for its data. Answering plain `open` calls is
  RFC 0004's job.
- **Changing grants during a run.** A separate RFC.
- **Stopping a compromised worker from using its own connection.** It
  gets what the grants allow, which is why grants should be small.

## Design

### Confined by default

```sh
fsgate-broker --grant /srv/data:rl -- ./worker
```

On Linux this now starts `./worker` confined. Running it without
confinement takes a flag:

```sh
fsgate-broker --unconfined --grant /srv/data:rl -- ./worker
```

Where confinement cannot be applied, on macOS or on a kernel without
Landlock ABI v3, the command exits 1 before the worker runs and names
`--unconfined` as the remedy. There is no silent fallback.

### What the worker may still touch

The broker's data grants never become worker rules, as in RFC 0004. If
they did, the worker could open granted files directly, with no audit
event and no way to take the access back.

The worker's Landlock ruleset handles every filesystem right `lock()`
handles and allows only:

| Path | Allowed |
|---|---|
| `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin` | read, list, execute |
| `/etc/ld.so.cache` | read |
| `/dev/null` | read, write |
| `/dev/urandom` | read |
| the command's own image | read, execute |

A listed path that does not exist is skipped, which only narrows the
ruleset.

`--direct <path>:<rights>` adds a path the worker may open itself, with
the letters `r`, `l`, and `x`:

```sh
fsgate-broker --direct /opt/python:rlx --grant /srv/data:rl -- ./worker
```

There is no `w` or `c`, because a write the worker makes directly is one
the broker never sees. Direct opens are not audited, so `--direct` is for
runtime files, not data.

A grant that overlaps a runtime directory or a `--direct` path, in either
direction, would be partly readable without the broker, and revoking it
would not stop those reads. The broker refuses one before the worker
starts, when the grant gives a right the worker has there: `READ` where
it may read, `LIST` where it may list. Paths are compared after resolving
symlinks, as the rules see them. The image and the single files in the
table hold no data and are not compared.

The ruleset also requests the RFC 0006 restrictions where the kernel has
them: device ioctls, abstract sockets, signals, and pathname sockets. The
worker holds its connection before the lock, so it never needs a connect.

Landlock adds one more limit without a rule. A sandboxed process can trace
another only if
[the tracee is in a sub-domain of the tracer](https://docs.kernel.org/userspace-api/landlock.html),
so the worker cannot trace its broker.

### How it is applied

`Command::pre_exec` is `unsafe`, and its closure runs in a forked child of
a multi-threaded process, where allocating is not safe. Nothing here needs
that. `fsgate-broker` starts itself again with an internal first argument.
That fresh, single-threaded process, in order:

1. Calls `setsid`, so the worker has no controlling terminal.
2. Asks for `SIGKILL` when the broker dies (`PR_SET_PDEATHSIG`).
3. Resolves the command on `PATH`, opens each allowed path, and builds the
   ruleset with the `landlock` crate.
4. Restricts itself, which also sets `no_new_privs`, so a set-ID program
   cannot gain privileges.
5. Closes every descriptor except standard input, output, and error and
   the broker connection, when the command starts.
6. Clears the environment, keeping `FSGATE_BROKER_FD` and any name given
   with `--env NAME`, and calls `exec` on the command.

Any failure exits 1 with the error. `exec` is the last step, so no path
leads to an unconfined worker.

Each step closes a specific hole:

- **Step 1.** `TIOCSTI` lets a process type into its controlling terminal,
  so a worker could queue commands for the user's shell. This is
  [CVE-2017-5226](https://nvd.nist.gov/vuln/detail/CVE-2017-5226) in
  bubblewrap, whose `--new-session` option is the same `setsid`. Landlock
  cannot help, because the terminal was opened before the sandbox.
- **Step 2.** After `setsid`, Ctrl-C reaches only the broker. Without this
  a killed broker would leave its worker running. It binds only a worker
  that keeps it: the worker can clear its own death signal, and a program
  the worker starts never has one. [RFC 0010](0010-worker-process-group.md)
  kills the worker's process group when the worker exits or the broker
  gets `SIGINT`, `SIGTERM`, or `SIGHUP`, which covers those programs
  unless the broker gets `SIGKILL`.
- **Step 5.** Landlock says
  [files opened before the sandboxing are not subject to its restrictions](https://docs.kernel.org/userspace-api/landlock.html),
  so a leaked descriptor is a way out. `close_range` is not wrapped by
  `std` or `rustix`, so it goes in an isolated module with a written
  safety contract, as AGENTS.md requires, and `libc` becomes a regular
  Linux dependency. It comes after step 4 so that on a kernel too old for
  both, before Linux 5.11, the error is the one that names `--unconfined`.
  Descriptors close at `exec` either way.
- **Step 6.** Environments often hold tokens, and Landlock does not cover
  them. The launcher's worker already starts with an empty environment.

### The `--socket` form

With `--socket`, the worker connects after it starts. On Linux 7.1 and
later `RESOLVE_UNIX` refuses that, and dropping the restriction would
leave every other socket on the machine open too. So `--socket` requires
`--unconfined`, and fails with a usage error otherwise. A worker that
needs several connections can make them and then call `lock()` itself.

### Compatibility

These are behavior changes for a minor release. 0.2.0 was already prepared
when this was accepted, so they belong in the next one, and the changelog
names them:

- `fsgate-broker` confines its worker on Linux and refuses to start one
  on macOS, unless given `--unconfined`.
- `--socket` requires `--unconfined`.
- A confined worker no longer inherits the environment.
- A confined worker that opens data directly must use `BrokerGate` or
  `--direct`.

With `--unconfined` the worker starts as it does today, so an existing
command line keeps working with one added flag. The library and
`--experimental-intercept` do not change.

## What this does not stop

- A compromised worker using its connection. The grants are the ceiling.
- Reading anything beneath the runtime paths or a `--direct` path.
- File metadata anywhere. Landlock cannot restrict `stat`, `chmod`,
  `chown`, `utime`, or `setxattr`.
- Network access.
- Before Linux 6.12, signals to the broker and connects to abstract
  sockets. Before Linux 7.1, connects to pathname sockets, which include
  services that act for their caller, such as systemd's user manager on
  the session bus.
- After `SIGKILL` to the broker, a worker that cleared its death signal,
  and programs it started, which never had one. Otherwise RFC 0010 ends
  them, except a program that left the worker's process group with
  `setsid` or `setpgid`.
- The worker's use of the terminal it inherited. It leads its own
  session, so job control does not stop it.
- Any containment on macOS.

## Testing

Security tests run the real `fsgate-broker` on the real kernel, and assert
the denial and the absence of the side effect:

- A worker that reads a file outside the grants with `std::fs` gets
  `EACCES`, and one that creates a marker leaves none. With `--unconfined`
  the same worker succeeds at both, so the test can tell the difference.
- A worker reads a granted file through `BrokerGate::from_inherited`, and
  a direct read of that same file gets `EACCES`. This shows the grants did
  not become worker rules.
- The test binaries are dynamically linked, so passing shows the default
  list is enough on the CI systems.
- On macOS and on the kernel booted with `lsm=capability`, the broker
  exits 1 without `--unconfined` and the worker's marker is absent.
- A descriptor left open by the parent is closed in the worker.
- A variable in the broker's environment is absent in the worker, and
  present when named with `--env`.
- The worker is a session leader, so it has no controlling terminal. The
  test checks the session rather than `TIOCSTI` itself: calling that ioctl
  needs `unsafe`, and whether a control could succeed depends on
  `dev.tty.legacy_tiocsti`.
- Killing the broker kills the worker.
- `--direct` allows a read beneath its path. A `w` or `c` letter is a
  usage error, as is `--socket` without `--unconfined`.
- With `--direct /proc:r`, a worker cannot read its broker's
  `/proc/<pid>/environ`, which the kernel guards with the same check as
  ptrace, and its `/proc/self/status` shows `NoNewPrivs: 1`. An unconfined
  control reads the file. Attaching with ptrace would need `unsafe`, and
  Yama can refuse its control.

These run in the `kernels` job on Linux 6.6 and 7.3, and on the runner's
kernel.

## Alternatives considered

- **Grants as worker rules.** The worker could then skip the broker, with
  no audit and no later revocation.
- **`pre_exec` with raw syscalls, as the launcher does.** More `unsafe`,
  for no gain here. The launcher needs it to hand a seccomp notification
  descriptor to its supervisor.
- **An unused user ID or a chroot, as OpenSSH does.** Needs root or
  unprivileged user namespaces, which not every system allows.
- **bubblewrap.** An external dependency with the same requirement.
- **An opt-in `--confine` flag.** A new flag does not fix a bad default.
- **Keeping `--socket` confined without `RESOLVE_UNIX`.** Leaves every
  other pathname socket reachable, including the ones this should close.

## Decisions

Accepted by the maintainer, with these answers:

1. Confinement is the default, and `--unconfined` opts out.
2. macOS refuses to start a worker without `--unconfined`, because the flag
   states what is true there.

## Open question

Is the default path list right? It starts dynamically linked programs on
CI's Ubuntu 26.04 systems, and that is all it has been measured on. Some
layouts will need `--direct`, such as NixOS with
`--direct /nix/store:rlx`.
