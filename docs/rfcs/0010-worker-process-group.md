# RFC 0010: end a confined worker's programs with it

- Status: accepted
- Date: 2026-11-10
- Roadmap: [M9](../../ROADMAP.md#m9--review-readiness-and-020)
- Builds on: [RFC 0008](0008-confine-broker-worker.md) (the confined worker), the [threat model](../threat-model.md#3-the-broker-and-its-worker)

## Problem

A confined worker leads its own session (RFC 0008, step 1), so its
process ID is also its process group's. Programs it starts join that
group. Today none of them end when the worker does:

- **The worker exits.** The broker reaps it and exits with its code.
  A program the worker left running keeps its `--direct` paths, the
  runtime directories, the network, and the terminal. Every broker
  operation fails closed, but nothing the user can see says it is still
  there.
- **The broker is stopped.** Ctrl-C, `kill`, or a closed terminal sends
  `SIGINT`, `SIGTERM`, or `SIGHUP` to the broker, which dies by the
  default action. The kernel sends the worker its death signal
  (`PR_SET_PDEATHSIG`), but a program the worker started has none and
  outlives both.

The threat model lists both, and
`broker_confined.rs::kernel::a_program_a_confined_worker_starts_outlives_its_broker`
shows the second. A user who stops `fsgate-broker` expects what it started
to stop too.

## Goals

- When a confined worker exits, every program still in its process group
  is killed before the broker exits.
- When the broker gets `SIGINT`, `SIGTERM`, or `SIGHUP`, the worker and
  its process group are killed, and the broker exits as that signal would
  have ended it.
- The broker still exits with the worker's code when the worker exits.
- No new dependency, and no `unsafe` outside the existing `sys` module.

## Non-goals

- **Programs that leave the group.** A program that calls `setsid` or
  `setpgid` is out of reach. See below.
- **`SIGKILL` to the broker.** Nothing runs after it. The worker's death
  signal still applies.
- **`--unconfined`.** That worker shares the broker's process group, and
  often the user's shell job, so killing the group would kill the broker
  and its caller.
- **Job control.** Stopping the broker with Ctrl-Z does not stop the
  worker, as today.

## Design

### When the worker exits

The broker waits for the worker without reaping it, kills the group, and
then reaps:

1. `waitid(P_PID, worker, WEXITED | WNOWAIT)` returns when the worker
   exits, and leaves it a zombie.
2. `kill(-worker, SIGKILL)` kills every process still in the group.
   `ESRCH` means the group is empty and is not an error.
3. `waitpid(worker)` reaps the worker, and the broker exits with its
   code.

The zombie keeps the worker's process ID in use, so between steps 1 and 3
no new process can take that ID or lead a group with it. Killing the
group by ID is therefore safe without a `pidfd`. A program being forked
at that moment is killed too: the kernel delivers a group signal either
to the parent before the fork or to both after it. `rustix` wraps
`waitid` and `kill_process_group` as safe calls.

### When the broker is stopped

The broker blocks `SIGINT`, `SIGTERM`, and `SIGHUP` in its main thread
before it starts any thread or the worker, so every thread inherits the
mask. A signal that arrives before anything waits for it stays pending.
After the worker starts, one thread waits for them with `sigwait`:

1. When a signal arrives, that thread records it and kills the worker's
   group with `SIGKILL`. The worker is still the broker's unreaped child,
   so its ID cannot have been reused.
2. The main thread's `waitid` returns as the worker dies. It kills the
   group again, finding it empty, and reaps the worker.
3. Because a signal was recorded, the main thread restores that signal's
   default action, unblocks it, and raises it, so the broker's parent
   sees it die by that signal.

`std`'s `Command` keeps the signal mask in the processes it starts, and
`exec` keeps it too. So the confining process unblocks the three signals
before it becomes the worker, and the worker and its programs can still
be stopped by them. A stop signal the broker inherited as ignored, as
under `nohup`, is not blocked or waited for, so it stays ignored.

Blocking and waiting are not wrapped safely by `std` or `rustix`, so
`pthread_sigmask`, `sigaction`, and `sigwait` go in the `sys` module of
`confine.rs`, next to `close_range`, with a written safety contract.
`libc` is already a Linux dependency.

The supervisor's thread starts before the worker, as the thread that
serves the worker's connection does, so no worker runs without it. The
two threads share the worker's ID only until just before it is reaped,
behind a lock, so a late signal cannot reach a reused ID. Until the
confining process calls `setsid`, the worker is not in a group of its
own, so each kill also names the worker by ID.

### Why the process group

The worker leads its session, and so its group, from step 1 of RFC 0008.
A program it starts stays in that group unless it leaves on purpose. One
`kill` reaches all of them, with no tracking and no `/proc` walk.

### Compatibility

A confined worker can no longer leave a program running after it exits,
such as a server started in the background. That goes in the changelog
under Changed. A worker that needs that runs with `--unconfined`.

## What this does not stop

- A program that calls `setsid` or `setpgid` to leave the group. It stays
  confined, and keeps the network, its `--direct` paths, and any terminal
  it holds.
- Anything after `SIGKILL` to the broker, beyond the worker's own death
  signal.

## Testing

Security tests run the real `fsgate-broker` on the real kernel, and
assert the kill and the absence of the side effect:

- **The worker exits.** The worker starts a program that holds a pipe and
  waits, then exits 3. The broker exits 3, the pipe reaches end of file,
  and the program's process ID no longer exists. End of file is the
  readiness signal, so the test does not sleep.
- **The broker gets `SIGTERM`.** With the worker and a program it started
  both running, the test sends `SIGTERM` to the broker. Both are gone, the
  pipe reaches end of file, and the broker's status is death by `SIGTERM`.
  The same for `SIGINT` and `SIGHUP`.
- **The worker's own signals.** `SIGTERM` sent to the worker directly
  still ends it, so the blocked mask did not leak into it. Without the
  confining process unblocking them, it would have.
- **The documented limit.** A program that calls `setsid` survives the
  worker's exit. The test then kills it.
- **`SIGKILL` to the broker.** The existing test that shows a program
  outliving it stays, as the documented limit.
- **`--unconfined`.** The broker exits with the worker's code and kills
  nothing.

## Alternatives considered

- **Leave it documented.** Every confined worker can leave programs
  running past the session the user ended.
- **A PID namespace.** When its first process dies, the kernel kills the
  rest, which also covers `setsid` and a killed broker. It needs
  unprivileged user namespaces, which Ubuntu 24.04 and later restrict by
  default.
- **`cgroup.kill`.** It kills everything in a cgroup, escapees included,
  from Linux 5.14. It needs a cgroup the user can write, which depends on
  how systemd delegated it, and fsgate would have to create and remove it.
- **Become a child subreaper and kill descendants.** Orphans would
  reparent to the broker instead of `init`, so it could kill programs that
  left the group by walking `/proc` until none remain. That reaches
  `setsid` escapees, but adds a `/proc` walk and its races, and still
  does nothing after `SIGKILL`. It could follow if that escape matters.
- **The `signal-hook` crate.** It handles signals without `unsafe` in
  fsgate, through a handler and a pipe. It adds a dependency, with its
  own `unsafe`, for two calls.

## Open questions

1. `sigwait` in the `sys` module, or `signal-hook`? This RFC proposes the
   `sys` module, to add no dependency.
2. When stopped by a signal, should the broker die by that signal, as
   proposed, or exit 128 plus its number? Dying by it is what a shell
   expects from Ctrl-C.

## Decisions

Accepted in [#72](https://github.com/farming-labs/fsgate/pull/72), with its
open questions answered:

1. The broker waits for signals with `sigwait` in the `sys` module of
   `confine.rs`, and adds no dependency.
2. A broker stopped by a signal dies by that signal.
