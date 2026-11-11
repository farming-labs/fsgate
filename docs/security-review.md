# Security review brief

**What an independent reviewer needs to review fsgate: the scope, how to run it, and what the review has to leave behind.**

- Status: no independent review has happened.
- Roadmap: [M9](../ROADMAP.md#m9--review-readiness-and-020)
- Reporting: [SECURITY.md](../SECURITY.md)

## What fsgate claims

fsgate scopes a process's filesystem authority to directories granted up front. The kernel or a held descriptor enforces that, never a string comparison.

[The threat model](threat-model.md) states the claims boundary by boundary: what each one trusts, what it stops and the test that shows it, and what it does not stop. Start there. A row whose test is "none" is a claim no fsgate test exercises.

## Scope

Review one named commit of `main` and record its full SHA. Use `6070452` or later, which has the final broker, including the worker confinement of [RFC 0008](rfcs/0008-confine-broker-worker.md). The latest release, `v0.2.0` on `aee17a7`, does not have that confinement. Read the threat model from the commit under review.

| Area | Code in `crates/fsgate/src/` | Claims |
|---|---|---|
| Handle layer | `lib.rs` | [Threat model 1](threat-model.md#1-the-gate-before-lock), [RFC 0001](rfcs/0001-core-design.md) |
| Containment, including the M8 restrictions | `containment.rs` | [Threat model 2](threat-model.md#2-the-locked-process-linux), [RFC 0006](rfcs/0006-lock-restrictions.md) |
| Broker, including its confined worker | `broker.rs`, `broker_sys.rs`, `bin/fsgate-broker.rs`, `bin/fsgate-broker/args.rs`, `bin/fsgate-broker/confine.rs` | [Threat model 3](threat-model.md#3-the-broker-and-its-worker), [RFC 0003](rfcs/0003-broker-protocol.md), [RFC 0007](rfcs/0007-broker-peers.md), [RFC 0008](rfcs/0008-confine-broker-worker.md) |
| Audit sink | `audit.rs` | [Threat model, audit](threat-model.md#audit-is-observation-not-a-boundary), [RFC 0002](rfcs/0002-audit-events.md) |

Out of scope:

- The `experimental-intercept` feature: `crates/fsgate/src/intercept/`, `fsgate-broker --experimental-intercept`, and [RFC 0004](rfcs/0004-filesystem-interception.md). It needs its own review before it can ship. Its source is in the published crate, and the feature stops at a `compile_error!` in `lib.rs` there.
- What the threat model lists under [Outside this model](threat-model.md#outside-this-model).

## Where to push hardest

The project's own tests and fuzzing cover the attacks the threat model lists. These are the places they say least about.

- **Resolution races.** `Gate::resolve` picks a grant by path prefix, which is routing only. The security is in what happens beneath the held handle: `openat2` on Linux and cap-std's component walk elsewhere. On Linux, `openat2` that keeps failing with `EAGAIN` falls back to that walk too. One stress test swaps a symlink during resolution, and it could show an escape but cannot rule one out. It has found one defect so far, `Gate::open` returning a directory, fixed in [#55](https://github.com/farming-labs/fsgate/pull/55).
- **The gate and the kernel disagreeing.** `containment.rs` builds Landlock rules from the held descriptors. Landlock allows an access when any rule allows it, so the kernel does not enforce a nested grant's lesser rights. Look for other places the two differ.
- **What `lock()` reports.** `Gate::restrictions`, `LockStatus`, and the `lock` audit event have to match what the kernel applied, including on kernels that lack a restriction.
- **Descriptors crossing the broker.** `read_frame` handles `SCM_RIGHTS` from a hostile worker. macOS and Linux treat descriptors that do not fit differently, and macOS sets close-on-exec only after `recvmsg`.
- **The confined worker.** `confine.rs` takes authority away in a fresh process before `exec`, so the order of steps and the failure paths matter. No path should reach `exec` without the ruleset, and the grants should never become worker rules. Two of its tests are indirect, and its default paths have been measured only on Ubuntu 26.04; M9 records both.
- **The `unsafe`.** A release build has it in two places: `broker_sys.rs` and the `sys` module of `confine.rs`. Each states its safety contract. The descriptor number `broker_sys.rs` adopts comes from `FSGATE_BROKER_FD`.
- **Who reaches the broker.** The peer check and connection limit in `Broker::serve_with`, the order of steps in `bind_owner_only`, and `BrokerGate::from_inherited`.
- **Audit completeness.** Every decision through a gate or a broker should emit exactly one event. Look for a path that emits none, or two.

## Run it

Needs Rust 1.85 or later, and [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) for the last command.

```sh
git clone https://github.com/farming-labs/fsgate
cd fsgate
git switch --detach <commit>
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo deny check
```

Kernel enforcement needs Linux. On macOS these commands cover the handle layer and the broker, and both a strict `lock()` and a confined worker fail closed.

What the Linux tests exercise depends on the kernel running them. Strict `lock()` needs Linux 6.2 (Landlock ABI v3). Device ioctls need 6.10, abstract sockets and signals 6.12, all threads 7.0, and pathname sockets 7.1. On a kernel without one of these, the same test checks the refusal instead.

The `kernels` job in [`ci.yml`](../.github/workflows/ci.yml) boots Linux 6.6.162 and 7.3.3 under virtme-ng and is the recipe for running them. [`guest-tests.sh`](../.github/kernels/guest-tests.sh) is what runs in the guest.

[`fuzz/README.md`](../fuzz/README.md) has the commands for the fuzz targets: the broker's requests, the gate's paths, and the broker's command line. M9 and M10 record the runs so far. To confirm that the crate on crates.io is the tagged commit, use the checks at the end of [Manual fallback](RELEASING.md#manual-fallback).

## What the review leaves behind

The roadmap item closes when all of these exist:

- The reviewer, the scope, and the full SHA of the reviewed commit.
- The findings, each with its location, what an attacker gains, and a reproduction where there is one.
- For each finding, a fix with a regression test, or a written answer.
- A README status that says what was reviewed and what was not.

M9 records these and links the report. Send anything exploitable in a published version through [SECURITY.md](../SECURITY.md) first, and publish it after the fix ships.
