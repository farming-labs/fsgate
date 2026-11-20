# Security review brief

**What an independent reviewer needs to review fsgate: the scope, how to run it, and what the review has to leave behind.**

- Status: handoff prepared; no independent review has happened and no reviewer is assigned.
- Roadmap: [M9](../ROADMAP.md#m9--review-readiness-and-020)
- Reporting: [SECURITY.md](../SECURITY.md)

## What fsgate claims

fsgate scopes a process's filesystem authority to directories granted up front. The kernel or a held descriptor enforces that, never a string comparison.

[The threat model](threat-model.md) states the claims boundary by boundary: what each one trusts, what it stops and the test that shows it, and what it does not stop. Start there. A row whose test is "none" is a claim no fsgate test exercises.

## Scope

Review the published [`fsgate` 0.6.0](https://crates.io/crates/fsgate/0.6.0) at commit [`61cf0dc58e3bbb2ccce489850b807e483fa5db32`](https://github.com/farming-labs/fsgate/commit/61cf0dc58e3bbb2ccce489850b807e483fa5db32), the commit signed as [`v0.6.0`](https://github.com/farming-labs/fsgate/tree/v0.6.0). Record that full SHA in the report. If the reviewer selects a later commit, record the new scope and evidence rather than treating this handoff as a review of it. It has all four of the broker's designs: the worker confinement of [RFC 0008](rfcs/0008-confine-broker-worker.md), the worker's Unix socket filter before Linux 7.1 ([RFC 0009](rfcs/0009-worker-unix-sockets.md)), its process group ([RFC 0010](rfcs/0010-worker-process-group.md)), and the audit of what the broker refuses ([RFC 0011](rfcs/0011-audit-broker-refusals.md)). It also has the fixes from an internal review at `ea159a6` ([#100](https://github.com/farming-labs/fsgate/pull/100) to [#106](https://github.com/farming-labs/fsgate/pull/106)), two of which change the API: a nested grant must hold every right of the grant around it ([RFC 0012](rfcs/0012-nested-grants.md)), and `read_dir` returns names and types ([RFC 0013](rfcs/0013-read-dir-entries.md)). They are released in 0.5.0: the signed tag `v0.5.0` on `af142c4` has the four designs and those fixes. 0.4.1 has the four designs and not those fixes. 0.3.0 has only the first design. 0.4.0 has all four, but its socket filter let a raw Unix socket pair through, which 0.4.1 fixes ([#93](https://github.com/farming-labs/fsgate/pull/93)). In 0.6.0 a confined worker gets a terminal on its standard streams for output only, unless `fsgate-broker` is given `--terminal` ([#117](https://github.com/farming-labs/fsgate/pull/117), [RFC 0008](rfcs/0008-confine-broker-worker.md#the-terminal)). `b4d56e5` also makes a socket broker refuse to serve when it would admit the overflow uid in a user namespace with unmapped uids ([#121](https://github.com/farming-labs/fsgate/pull/121), [RFC 0007](rfcs/0007-broker-peers.md#changes-after-release)). This check shipped in 0.6.0 and requires readable procfs files and a kernel built with `CONFIG_USER_NS=y` when checking peer identities on Linux or Android. Read the threat model from the commit under review.

The target also includes the pre-lock `io_uring` inspection
([#123](https://github.com/farming-labs/fsgate/pull/123),
[RFC 0014](rfcs/0014-lock-io-uring-rings.md)). Both Linux lock policies
refuse detectable existing rings and inspection failures before applying
containment, unless the caller explicitly opts out. This is a trusted-setup
precondition, not another kernel restriction. The target includes the signal-scope tests from
[#116](https://github.com/farming-labs/fsgate/pull/116).

The release includes the broker quickstart
([#126](https://github.com/farming-labs/fsgate/pull/126)), and dynamic program
support for the experimental launcher ([#127](https://github.com/farming-labs/fsgate/pull/127)).
The launcher is outside this review's scope. Its changes in shared files add
the audit event names `runtime_grant`, `runtime_open`, `runtime_metadata`, and
`runtime_revoke`, and the broker CLI's `--runtime` flag. The implementation of
`lock()`, `containment.rs`, `uring_guard.rs`, and `broker.rs` is the same as at
`2eaf9a1`.

| Area | Code in `crates/fsgate/src/` | Claims |
|---|---|---|
| Handle layer | `lib.rs` | [Threat model 1](threat-model.md#1-the-gate-before-lock), [RFC 0001](rfcs/0001-core-design.md), [RFC 0012](rfcs/0012-nested-grants.md), [RFC 0013](rfcs/0013-read-dir-entries.md) |
| Containment, including the M8 restrictions and pre-lock inspection | `containment.rs`, `uring_guard.rs`, and `LockOptions` in `lib.rs` | [Threat model 2](threat-model.md#2-the-locked-process-linux), [RFC 0006](rfcs/0006-lock-restrictions.md), [RFC 0014](rfcs/0014-lock-io-uring-rings.md) |
| Broker, including its confined worker | `broker.rs`, `broker_sys.rs`, `bin/fsgate-broker.rs`, `bin/fsgate-broker/args.rs`, `bin/fsgate-broker/confine.rs`, `bin/fsgate-broker/acl.rs` (macOS) | [Threat model 3](threat-model.md#3-the-broker-and-its-worker), [RFC 0003](rfcs/0003-broker-protocol.md), [RFC 0007](rfcs/0007-broker-peers.md), [RFC 0008](rfcs/0008-confine-broker-worker.md), [RFC 0009](rfcs/0009-worker-unix-sockets.md), [RFC 0010](rfcs/0010-worker-process-group.md) |
| Audit sink | `audit.rs` | [Threat model, audit](threat-model.md#audit-is-observation-not-a-boundary), [RFC 0002](rfcs/0002-audit-events.md), [RFC 0011](rfcs/0011-audit-broker-refusals.md) |

Out of scope:

- The `experimental-intercept` feature: `crates/fsgate/src/intercept/`, `fsgate-broker --experimental-intercept`, and [RFC 0004](rfcs/0004-filesystem-interception.md). It needs its own review before it can ship. Its source is in the published crate, and the feature stops at a `compile_error!` in `lib.rs` there.
- What the threat model lists under [Outside this model](threat-model.md#outside-this-model).

## Where to push hardest

The project's own tests and fuzzing cover the attacks the threat model lists. These are the places they say least about.

- **Resolution races.** `Gate::resolve` picks a grant by path prefix, which is routing only. The security is in what happens beneath the held handle: `openat2` on Linux and cap-std's component walk elsewhere. On Linux, `openat2` that keeps failing with `EAGAIN` falls back to that walk too. One stress test swaps a symlink during resolution, and it could show an escape but cannot rule one out. It has found one defect so far, `Gate::open` returning a directory, fixed in [#55](https://github.com/farming-labs/fsgate/pull/55).
- **The gate and the kernel disagreeing.** `containment.rs` builds Landlock rules from the held descriptors. Landlock allows an access when any rule allows it, which is why `grant` and `narrow` refuse a nested grant with fewer rights than the grant around it ([RFC 0012](rfcs/0012-nested-grants.md)). That check reads nesting from device and inode numbers up through `..`; look for a way to nest grants it misses, and for other places the gate and the kernel differ.
- **What `lock()` reports.** `Gate::restrictions`, `LockStatus`, and the `lock` audit event have to match what the kernel applied, including on kernels that lack a restriction.
- **Pre-lock inspection.** `uring_guard.rs` walks held procfs directories and each visible thread's descriptor table. Check that an unreadable entry, wrong filesystem, or incomplete scan refuses both lock policies before containment, leaves the gate grantable, closes temporary descriptors, and produces one denied audit event. Check the separate `allow_existing_io_uring` opt-out and that the scan is never reported as a kernel restriction. Hidden registered rings, descriptors queued in sockets, concurrent changes, renamed polling threads, and deliberately misleading procfs mounts remain documented limits; assess whether the implementation or documentation promises more than the scan can establish.
- **Descriptors crossing the broker.** `read_frame` handles `SCM_RIGHTS` from a hostile worker. macOS and Linux treat descriptors that do not fit differently, and macOS sets close-on-exec only after `recvmsg`.
- **The confined worker.** `confine.rs` takes authority away in a fresh process before `exec`, so the order of steps and the failure paths matter. No path should reach `exec` without the ruleset, and the grants should never become worker rules. Unless `--terminal` is given, a terminal on the worker's standard input becomes `/dev/null` and one on standard output or error is opened again write-only through `/proc/self/fd`; look for a way the worker can still read it. Before Linux 7.1, a seccomp filter written as raw BPF in its `unix_socket_filter` module stands in for Landlock's Unix socket rules ([RFC 0009](rfcs/0009-worker-unix-sockets.md)): no call on x86_64 or aarch64 should give the worker a Unix socket it can point at a new peer, and a call through another architecture's table should kill it. The broker kills the worker's process group while the worker is still an unreaped zombie, so that no new process can take the group's ID first ([RFC 0010](rfcs/0010-worker-process-group.md)). Two of its tests are indirect, as M9 records. Its default paths have been tested on Ubuntu 26.04 and, since M10, in Debian, Fedora, Arch, Alpine (musl), and Nix containers on Linux 7.0, on x86_64 and, except Arch, on arm64.
- **The `unsafe`.** A release build has it in three places: `broker_sys.rs`, the `sys` module of `confine.rs` on Linux, and `fsgate-broker/acl.rs` on macOS, which reads a directory's access list. Each states its safety contract. The descriptor number `broker_sys.rs` adopts comes from `FSGATE_BROKER_FD`.
- **Who reaches the broker.** The peer check and connection limit in `Broker::serve_with`, the order of steps in `bind_owner_only`, and `BrokerGate::from_inherited`. On Linux and Android, `refuse_lookalike_uids` checks the uid map and overflow uid before accepting a connection; look for a namespace or allowed-uid set that still admits indistinguishable peers, and a failure reading procfs that lets serving proceed. `ServeOptions::any_peer` deliberately bypasses this identity check and admits every peer that can reach the socket.
- **Audit completeness.** Every decision through a gate or a broker should emit exactly one event. Look for a path that emits none, or two.

## Run it

Needs Rust 1.85 or later, and [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) for the dependency checks.

```sh
git clone https://github.com/farming-labs/fsgate
cd fsgate
git switch --detach 61cf0dc58e3bbb2ccce489850b807e483fa5db32
git rev-parse HEAD
cargo fmt --all --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo deny check
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps
```

Kernel enforcement needs Linux. On macOS these commands cover the handle layer and the broker, and both a strict `lock()` and a confined worker fail closed.

What the Linux tests exercise depends on the kernel running them. Strict `lock()` needs Linux 6.2 (Landlock ABI v3). Device ioctls need 6.10, abstract sockets and signals 6.12, all threads 7.0, and pathname sockets 7.1. On a kernel without one of these, the same test checks the refusal instead.

The `kernels` job in [`ci.yml`](../.github/workflows/ci.yml) boots Linux 6.1.192, 6.6.162, 6.12.117, and 7.3.3 under virtme-ng and is the recipe for running them. 6.1 is below the Landlock floor, so it runs only the tests that show a strict `lock()` and a confined worker failing closed. [`guest-tests.sh`](../.github/kernels/guest-tests.sh) is what runs in the guest.

[`fuzz/README.md`](../fuzz/README.md) has the commands for the fuzz targets: the broker's requests, the gate's paths, and the broker's command line. M9 and M10 record the runs so far. To confirm that the crate on crates.io is the tagged commit, use the checks at the end of [Manual fallback](RELEASING.md#manual-fallback).

## Existing evidence for the prepared target

The [release workflow](https://github.com/farming-labs/fsgate/actions/runs/44438265600)
verified the uploaded and downloaded crate against the registry checksum,
`52eb31b3c7b79d4ebfb1253bd083a4c895e33f382ca97f4a9de552ee0b99496e`.
The archive's `.cargo_vcs_info.json` records the review target above.

[CI on the target commit](https://github.com/farming-labs/fsgate/actions/runs/44421385273)
passed all 20 jobs. It includes the default and experimental-feature
suites, Rust 1.85.0, macOS, Linux x86_64 and arm64, dependency policy,
workflow checks, distro smoke tests, and the declared kernel matrix.
The `check` job tests an unpacked crate outside the checkout and verifies
that its experimental feature refuses to build. The supported-kernel jobs
run packaged release builds; the 6.1 job exercises refusal below the
Landlock floor.

The signal and `io_uring` tests were last examined in detail on `2eaf9a1`,
whose Git tree `d14ca16ad209716164eff94dca4c4f74c55112ea` is identical to
#116's tested head `7da922c34fee0862b63a6a0705d72f0e69571192`; the target
contains that commit.
Those [CI logs](https://github.com/farming-labs/fsgate/actions/runs/44175897669)
show the two signal tests and the visible-ring refusal test passing in
all nine relevant suite executions. The guard-removal control fails for
the missing refusal and restores the source before later passing runs.
The [four fuzz jobs](https://github.com/farming-labs/fsgate/actions/runs/44175897558)
also passed on that earlier tree; they do not establish coverage of every boundary.

These results are implementation evidence, not independent review.
Retain the documented gaps: the death signal under the scope before
Linux 7.0, TCP urgent data and `F_SETOWN_EX` to a thread, kernels 7.1 and
7.2 individually, hidden rings and concurrent setup, and limits listed in
the threat model. Reviewers should add adversarial cases beyond the
existing tests and state what they did not examine.

## What the review leaves behind

The roadmap item closes when all of these exist:

- The reviewer, the scope, and the full SHA of the reviewed commit.
- The findings, each with a stable identifier, severity, source location, what an attacker gains, and a reproduction where there is one. Record the expected and observed outcome, environment, and any filesystem side effects.
- For each finding, a fix with a regression test, or a written answer. Record the fixed commit and whether the reviewer checked the fix.
- A README status that says what was reviewed and what was not.

M9 records these and links the report. Send anything exploitable in a published version through [SECURITY.md](../SECURITY.md) first, and publish it after the fix ships.
