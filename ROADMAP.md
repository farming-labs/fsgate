# Roadmap

This file owns task status. A box is checked only when the acceptance criteria are met, the change is merged, and the PR is linked as evidence.

## M0 — foundation

- [x] Scaffold workspace, roadmap, and core design RFC (dec192b)
- [x] Pin dependency decisions: `cap-std` version, Landlock crate (`landlock`), seccomp crate (`seccompiler` vs raw `libseccomp`), MSRV ([ADR 0001](docs/decisions/0001-dependency-pins.md))
- [x] Add `cargo-deny` config and wire it into CI
- [x] Decide and document the audit event format ([RFC 0002](docs/rfcs/0002-audit-events.md))

Acceptance: decisions recorded as RFCs or ADRs with the rejected alternatives named; CI runs fmt, clippy `-D warnings`, test `--locked`, and deny on every PR.

## M1 — handle layer and resolver (Linux first)

- [x] `Gate::new`, `grant(path, Rights) -> Grant`, `Rights` (READ, WRITE, CREATE, LIST)
- [x] Resolver: longest-grant match, then open beneath the handle via `openat2` + `RESOLVE_BENEATH` (cap-std; component walk on macOS)
- [x] `open`, `create`, `metadata`, `read_dir` through the gate (`read`/`write` happen on the returned `File`)
- [x] Fail-closed errors: `NoGrant`, `RightsExceeded`, each naming the path and the missing right

M1 note: `revoke` landed here with its tests (it fell out of the grant table design); M4 keeps the audit half.

Acceptance: tests cover allowed operations, denied operations, symlink escape attempts, `..` traversal, and absolute-path symlink targets — and the denial tests assert the side effect did not happen. No name/string-prefix check anywhere in the enforcement path.

## M2 — process lock

- [x] `lock()`: apply a Landlock ruleset derived from the grants (seccomp was dropped for path mediation — it cannot inspect path arguments; [ADR 0002](docs/decisions/0002-landlock-not-seccomp-for-paths.md))
- [x] `lock()` is irreversible; `grant()` after `lock()` fails
- [x] Graceful degradation is explicit: on kernels without Landlock, `lock()` returns an error unless the caller opts into `LockPolicy::BestEffort` (which reports the achieved `LockStatus`)

Acceptance met: `tests/lock.rs` re-executes the test binary as a locked child and proves raw `std::fs::File::open` of an ungated path fails at the kernel (`PermissionDenied`), writes outside leave no file behind, and the gate's own granted opens still work.

## M3 — broker (macOS and defense in depth)

- [x] `fsgate-broker` binary: parent holds grants, child requests opens over a Unix socket, descriptors passed via `SCM_RIGHTS` (protocol: [RFC 0003](docs/rfcs/0003-broker-protocol.md))
- [x] Same verbs in the child via `BrokerGate` (`open`/`create`/`metadata`/`read_dir`; `metadata` returns the serializable `FileStat` and `read_dir` returns names, since results cross a process boundary)
- [x] Broker applies the same rights checks server-side; the child is never trusted (requests feed the broker's own `Gate` — same resolution code as in-process)

Acceptance met: `tests/broker.rs` covers socketpair and real-binary transports, typed denials crossing the wire with no side effects, and the kill test — after `fsgate-broker` dies, every client operation returns `GateError::Broker`. Verified on macOS and Linux (CI).

## M4 — revocation and audit

- [x] `revoke(grant)` takes effect for subsequent operations and is covered by tests (landed early, in M1)
- [x] Every allow/deny decision emits a structured audit event (format from [RFC 0002](docs/rfcs/0002-audit-events.md)): `AuditSink` on the gate, events for grant/revoke/lock and all four operations, kernel refusals recorded as allow + errno, broker decisions audited server-side, denials observed even when the caller swallows the error

## M5 — v0.1.0

- [x] API review pass against RFC 0001; deviations folded back into the RFC ([PR #1](https://github.com/farming-labs/fsgate/pull/1), `168ae27`)
- [x] Docs: every public item documented, README examples compile as doctests ([PR #1](https://github.com/farming-labs/fsgate/pull/1), `168ae27`)
- [x] Release v0.1.0 (signed tag [`v0.1.0`](https://github.com/farming-labs/fsgate/tree/v0.1.0), `0ad477f`; preparation in [PR #3](https://github.com/farming-labs/fsgate/pull/3)). Publishing to crates.io is a separate, explicit maintainer decision.
- [x] Publish to crates.io as 0.1.1, from the signed tag [`v0.1.1`](https://github.com/farming-labs/fsgate/tree/v0.1.1) ([`fsgate` 0.1.1](https://crates.io/crates/fsgate/0.1.1); preparation in [PR #15](https://github.com/farming-labs/fsgate/pull/15)). v0.1.0 was tagged with `publish = false` and is never published. Acceptance: `cargo publish --locked` runs from a clean checkout of the verified tag, and the crates.io checksum matches the uploaded archive.

Preparation merged in PR #1: `LockStatus`, `create` rights, audit delivery, broker client types, and containment limits are folded into RFC 0001. Public documentation is required, the README compiles as a doctest, and CI tests the unpacked crate. Audit regression coverage checks the actual matched grant ID for duplicate and nested grants, revocation, and broker requests. The release followed [the release procedure](docs/RELEASING.md): the signed tag `v0.1.0` (tag object `5bd7761`) points to `0ad477f`, which also includes grant narrowing (M7), non-exhaustive audit and error types, the cross-gate grant fix, and the audit `rights` key (#6–#11).

The crates.io release is 0.1.1: the signed tag `v0.1.1` (tag object `fc3e6e6`) points to `4250f31`, which adds the broker close-on-exec fix (#13) to v0.1.0, plus the publishable manifest and procedure from #15. Verification for the publish: [CI](https://github.com/farming-labs/fsgate/actions/runs/42352929757) passed `check`, `msrv`, `deny`, and `macos` on `4250f31`. Locally, 54 tests passed from the checkout and from the unpacked crate on Rust 1.99.1 and 1.85.0. `cargo publish --locked --dry-run` and then `cargo publish --locked` ran from a clean detached checkout of `v0.1.1`. crates.io reports checksum `c016d61994ce23e45901f914b7a746ac9bf959daf896c71ef4ef907821a02118`, byte-identical to the uploaded archive, and the published `.cargo_vcs_info.json` records `4250f31ab6254a20938335c179da699f885764e5`. `cargo install fsgate --version 0.1.1 --locked` builds the published crate and runs `fsgate-broker`. GitHub marks `v0.1.1` verified. No GitHub release or binary asset was created.

Verification for PR #1: macOS formatting, clippy, rustdoc, and cargo-deny checks passed. The 32 runtime tests and two compile-only doctests passed from both the checkout and the unpacked crate on Rust 1.99.1 and 1.85.0. The duplicate-grant audit tests and packaged README doctest failed before their fixes. [Linux CI](https://github.com/farming-labs/fsgate/actions/runs/42288527953) passed `check`, `msrv`, and `deny` on head `c5d2f7c`: the kernel bypass-denial test passed on stable Rust and Rust 1.85.0, and the stable job tested the unpacked crate. The automated reviewer was skipped; this is not an independent security review.

Verification for the tag: [Linux CI](https://github.com/farming-labs/fsgate/actions/runs/42347094963) passed `check`, `msrv`, and `deny` on `0ad477f`, including the kernel tests on stable Rust (checkout and unpacked crate) and Rust 1.85.0 (checkout). Locally on macOS, formatting, clippy, rustdoc, and cargo-deny passed, and 53 tests (43 runtime, 10 doctests) passed from the checkout and the unpacked crate on Rust 1.99.1 and 1.85.0. `git verify-tag v0.1.0` reports a good signature from ED25519 key `SHA256:fvFBB9+wFOaTFgWwJYn52qSZJ/2gQlaapZk7amEw48I`, and GitHub marks the tag verified. No crate, binary asset, or GitHub release was published.

## M6 — Linux filesystem interception (experimental)

Experimental and unreleased: implemented after v0.1.1 behind the `experimental-intercept` feature, with no release version assigned and no independent security review. Design: [RFC 0004](docs/rfcs/0004-filesystem-interception.md). M2 already enforces Linux filesystem rules in the kernel. M6 would let a supported binary's ordinary file-open syscalls reach the broker without linking fsgate or calling `BrokerGate`.

Planning landed in [#2](https://github.com/farming-labs/fsgate/pull/2). The prototype profile merged in [#4](https://github.com/farming-labs/fsgate/pull/4) (`9699168`): native Linux x86_64 static binaries, with Linux 6.6 as the initial test baseline, seccomp notifications, broker-side read-only opens, a separate executable rule, a syscall allowlist, and atomic descriptor delivery. That settled the design task. The runtime evidence below comes from Linux CI on GitHub's `ubuntu-latest` x86_64 runners and, since [#35](https://github.com/farming-labs/fsgate/pull/35), from Linux 6.6 booted in a VM.

- [x] Settle the authority boundary and backend in RFC 0004 ([#4](https://github.com/farming-labs/fsgate/pull/4)): review the specified seccomp notification profile and its distinction from a preload shim and privileged eBPF LSM hooks. Acceptance: record the supported kernel/architecture, syscall and flag coverage, bootstrap authority, and bypass analysis before runtime implementation.
- [x] Add an opt-in experimental launcher using the existing grant resolver and audit sink. Acceptance: the worker starts only after required kernel support, containment, descriptor cleanup, and supervisor readiness are confirmed; unsupported hosts fail before executing the target. Evidence: `intercept::Launch` ([#24](https://github.com/farming-labs/fsgate/pull/24)) and `fsgate-broker --experimental-intercept` with plan and `--apply` ([#25](https://github.com/farming-labs/fsgate/pull/25)). The image rule and execution by descriptor ([#22](https://github.com/farming-labs/fsgate/pull/22)); the allowlist and readiness only after both filters are installed ([#23](https://github.com/farming-labs/fsgate/pull/23)). Tests: the worker starts with only stdio open; an aborted startup never executes it; dynamic, script, and set-ID images are refused before launch; the mode is a usage error off Linux x86_64 (macOS CI). A kernel booted without Landlock is refused before the worker runs ([#35](https://github.com/farming-labs/fsgate/pull/35)). A kernel without seccomp user notifications, or with a Landlock ABI below 3, is still untested.
- [x] Intercept the supported `open` / `openat` / `openat2` calls, initially read-only regular files named by absolute paths. Acceptance: standalone libc and direct-syscall fixtures read granted bytes without a fsgate dependency, and unsupported arguments return documented errors without ambient fallback. Evidence: a static C worker that does not link fsgate reads granted bytes through libc `open` (`openat`), raw `open` ([#26](https://github.com/farming-labs/fsgate/pull/26)), and raw `openat2` ([#16](https://github.com/farming-labs/fsgate/pull/16), [#19](https://github.com/farming-labs/fsgate/pull/19)). Relative and `..` paths, write and create flags, unsupported resolve flags, symlinks (`ELOOP`), directories (`EISDIR`), and FIFOs (`EOPNOTSUPP`) return the RFC's errors ([#16](https://github.com/farming-labs/fsgate/pull/16), [#19](https://github.com/farming-labs/fsgate/pull/19), [#21](https://github.com/farming-labs/fsgate/pull/21)).
- [x] Enforce broker-side authorization and descriptor delivery. Acceptance: denied opens and attempted writes leave protected files unchanged, symlink and argument races cannot escape a grant, and mediated decisions reach the audit sink. Evidence:
  - Denied opens, writes, truncation, and creation leave files unchanged; `execve`, `io_uring`, sockets, and namespace `clone` are refused ([#16](https://github.com/farming-labs/fsgate/pull/16), [#23](https://github.com/farming-labs/fsgate/pull/23)).
  - A FIFO or symlink renamed over a checked path is never opened ([#19](https://github.com/farming-labs/fsgate/pull/19)), and a path rewritten in worker memory mid-request never delivers an ungranted file over 2000 rounds ([#26](https://github.com/farming-labs/fsgate/pull/26)).
  - Every mediated request emits one audit event, with its syscall and notification ID ([#21](https://github.com/farming-labs/fsgate/pull/21)).
- [x] Handle shutdown, cancellation, and revocation. Acceptance: supervisor death prevents new brokered opens, interrupted requests leak no descriptors, descendants retain restrictions, and revocation denies subsequent brokered opens. Document that already-delivered file descriptors remain usable. Evidence: `Launch::spawn` and `intercept::Running` ([#32](https://github.com/farming-labs/fsgate/pull/32)). A revoke made through `Running` while the worker runs waits for the in-flight request, and the next open is denied (`EACCES`, audited `no_grant`) while the already-delivered descriptor still reads; this is documented on `Running`. A request interrupted by a signal after its decision installs no descriptor in the worker (`EINTR`), and the supervisor drops its copy ([#32](https://github.com/farming-labs/fsgate/pull/32)). A lost supervisor fails later opens with `ENOSYS` (first in [#16](https://github.com/farming-labs/fsgate/pull/16), a unit test since [#24](https://github.com/farming-labs/fsgate/pull/24)). Forked children and threads stay mediated ([#23](https://github.com/farming-labs/fsgate/pull/23)). `kill` followed by `wait` reaps the worker, and dropping a `Running` kills and reaps it ([#32](https://github.com/farming-labs/fsgate/pull/32)).
- [x] Verify and document the supported subset from a release build and unpacked crate on Linux. Acceptance: real-filesystem denial and bypass tests pass on the declared kernels and architectures, unsupported-host startup tests pass, and the README and example state the remaining compatibility limits. Evidence: CI's `kernels` job ([#35](https://github.com/farming-labs/fsgate/pull/35)) builds Linux 6.6.162, the declared baseline, from the kernel.org tarball (pinned SHA-256) with Landlock and seccomp. It boots that kernel under virtme-ng with KVM and runs every test of the packaged crate, built with `--release` and `experimental-intercept`: 107 passed across 8 test executables in [the first run](https://github.com/farming-labs/fsgate/actions/runs/42434784539). A second boot with `lsm=capability` runs the unsupported-host tests: `Launch::check` and `Launch::run` fail with `Unsupported`, `fsgate-broker` exits 1 in plan and apply mode, and the worker's marker file stays absent. The `check` job still covers the runner's own kernel. The README's launcher section, next to its `fsgate-broker` example, states the requirements and limits, and RFC 0004 names the declared kernels. Not covered: kernels between 6.6 and the runner's; a kernel without seccomp user notifications or with a Landlock ABI below 3; and other architectures (none are declared).

Implementation steps 1 and 2 of RFC 0004 landed as a disposable probe ([#16](https://github.com/farming-labs/fsgate/pull/16), [#22](https://github.com/farming-labs/fsgate/pull/22), [#23](https://github.com/farming-labs/fsgate/pull/23)) plus `Gate::open_regular_strict` ([#19](https://github.com/farming-labs/fsgate/pull/19)) and the audited dispatcher `Gate::open_intercepted` ([#21](https://github.com/farming-labs/fsgate/pull/21)), all behind fsgate's `experimental-intercept` feature. The probe has since moved into fsgate as `intercept::Launch` (Linux x86_64): the image rule, Landlock, both seccomp filters, the startup barrier, and execution from a reserved descriptor, tested against a static worker in Linux CI. `fsgate-broker --experimental-intercept` exposes it with a plan by default and an explicit `--apply`. CI's `kernels` job runs the packaged crate's release-built tests on Linux 6.6 in a VM ([#35](https://github.com/farming-labs/fsgate/pull/35)).

M6 does not promise every filesystem syscall or arbitrary binary compatibility. Relative paths and directory descriptors, writes and creation, metadata, and directory enumeration need explicit semantics and coverage before support expands. macOS interception, a preload shim, and a custom eBPF LSM backend are not part of the proposed first implementation.

## M7 — grant narrowing

Implemented in [#6](https://github.com/farming-labs/fsgate/pull/6) and included in v0.1.0; independent of M6. Design: [RFC 0005](docs/rfcs/0005-grant-narrowing.md), which resolves RFC 0001's attenuated-grant open question. `GateError` and `AuditOp` are non-exhaustive, so the new variants are additive.

- [x] `Gate::narrow(grant, rights)` narrows a live grant in place ([#6](https://github.com/farming-labs/fsgate/pull/6)), before or after `lock()`, keeping its id and held directory handle. Acceptance: denied operations after narrowing leave files absent or unchanged; a set naming a right the grant lacks fails with `GateError::WouldWiden` and leaves the grant unchanged, including an attempt to restore narrowed rights; narrowing a revoked grant fails with `UnknownGrant`; swapping a different directory in under the granted path does not change what the narrowed grant reaches.
- [x] Kernel enforcement follows the narrowed rights ([#6](https://github.com/farming-labs/fsgate/pull/6)). Acceptance: a Linux locked child proves raw writes beneath a grant narrowed before `lock()` fail at the kernel and leave files unchanged, and that narrowing after `lock()` denies gate operations without side effects.
- [x] Audit: one `narrow` event per decision (RFC 0002, [#6](https://github.com/farming-labs/fsgate/pull/6)). Acceptance: tests cover allow, a widening denial (`rights_exceeded`), and an unknown grant (`unknown_grant`), each naming the narrowed grant's id.

Acceptance met: `tests/gate.rs` covers denied creates and truncation after narrowing with files left absent or unchanged, `WouldWiden` on an attempt to restore the original rights with the grant left read-only, `UnknownGrant` after revocation, and a directory swapped in under the granted path. `tests/lock.rs` runs a strict-locked child: a raw write beneath a grant narrowed before `lock()` fails with `PermissionDenied` and leaves the file unchanged, and narrowing after `lock()` denies `create` without creating the file. `tests/audit.rs` checks the allow, `rights_exceeded`, and `unknown_grant` events name grant 1. [Linux CI](https://github.com/farming-labs/fsgate/actions/runs/42320274648) ran the locked-child test on stable and Rust 1.85.0 at #6's head `238351f`. Not independently reviewed.

## M8 — containment beyond file paths (Linux)

Design accepted in [RFC 0006](docs/rfcs/0006-lock-restrictions.md). Implemented ([#36](https://github.com/farming-labs/fsgate/pull/36), [#43](https://github.com/farming-labs/fsgate/pull/43)) and released in 0.2.0. Before M8, `lock()` installed Landlock filesystem rules up to ABI v3 and nothing else. A locked process could therefore still connect to Unix domain sockets and signal processes outside the sandbox, and through them reach an unconfined process that acts on files for it or passes it descriptors ([#30](https://github.com/farming-labs/fsgate/pull/30) documents this). The `landlock` 0.4.7 crate fsgate already pins supports the ABIs that restrict these. CI runners boot Linux 7.0, so ABI v5, v6, and v8 are tested there; ABI v9 (Linux 7.1) is tested on Linux 7.3 in the `kernels` job.

- [x] [RFC 0006](docs/rfcs/0006-lock-restrictions.md) ([#34](https://github.com/farming-labs/fsgate/pull/34)): decide how `lock()` adopts the newer restrictions: abstract Unix socket and signal scopes (ABI v6, Linux 6.12), device ioctls (`IoctlDev`, ABI v5, Linux 6.10), and pathname socket connects (`ResolveUnix`, ABI v9, Linux 7.1). Acceptance: the RFC settles what strict `lock()` requires on kernels older than 6.12 (today it requires only v3). It settles how callers learn which restrictions took effect: `LockStatus` and `LockPolicy` are exhaustive, so a new variant breaks callers and has to ship in 0.2.0. And it settles how a locked worker still reaches its broker socket once pathname connects are restricted. Settled: strict `lock()` keeps the v3 floor and every newer restriction is on by default where supported; `LockOptions` can drop or require each one; `Gate::restrictions()` and the `lock` audit event report what took effect, so no new variant is needed; a worker connects to its broker before locking. The RFC also adds all-thread enforcement (ABI v8, Linux 7.0).
- [x] Implement `Restrictions`, `LockOptions`, and `Gate::restrictions()` with device ioctls, abstract socket and signal scopes, and all-thread enforcement (ABI v5, v6, v8) ([#36](https://github.com/farming-labs/fsgate/pull/36)). Acceptance: RFC 0006's locked-child tests for these pass against the real kernel, each asserting the refusal and the missing side effect, with a control run that succeeds without the restriction. A missing requirement fails before anything is applied. The effective-ABI mapping is unit-tested for every ABI. The README, RFC 0001, and the changelog describe the new default.

  Evidence comes from [Linux CI](https://github.com/farming-labs/fsgate/actions/runs/42435971317). A probe child reads the kernel's Landlock ABI through the `landlock` crate, not fsgate, and each test picks its modes from it.

  On the `ubuntu-26.04` runners (Linux 7.0, ABI v8), the tests ran on stable and Rust 1.85.0, with and without `experimental-intercept`. Each restriction is enforced, and each control run without it succeeds:
  - A connect to the parent's abstract socket fails with `EPERM`, and the parent accepts nothing.
  - A `SIGTERM` to a process the parent started fails with `EPERM`, and that process stays alive.
  - `tcgetattr` on `/dev/null` beneath a `READ` grant fails with `EACCES`; the control and a `WRITE` grant get `ENOTTY`.
  - A thread started before the lock cannot read or write outside the grants, and no file is created.

  On Linux 6.6.162 (ABI v4, the `kernels` job, release build of the packaged crate), none of the four restrictions exists. For each, requiring it fails with `LockUnsupported`, which names it. Nothing has been applied at that point: the gate is unlocked and a raw read outside the grants still succeeds. A bare `lock()` then reports `FullyEnforced` without the restriction and denies that read.

  The effective-ABI mapping is unit-tested for ABI 0 through 9. Not independently reviewed.
- [x] Restrict pathname socket connects (ABI v9) ([#43](https://github.com/farming-labs/fsgate/pull/43)). Acceptance: a locked-child test of the same shape passes on Linux 7.1 or later. Until CI boots such a kernel, the item records where the test ran or stays open.

  Evidence comes from [Linux CI](https://github.com/farming-labs/fsgate/actions/runs/42490995922). The `kernels` job built Linux 7.3.3 from the kernel.org tarball (pinned SHA-256) and ran the packaged crate's tests there with `--release`, in both modes, with and without the restriction:
  - A stream connect and a datagram send to sockets beneath a grant holding every right fail with `EACCES`. The listener accepts nothing, and the receiver gets nothing. A connection made before the lock still delivers its byte.
  - A `BrokerGate` connected before the lock still opens files through the broker. A later `connect` fails with `GateError::Broker` naming the order.
  - Each control run, without the restriction, succeeds.

  On the runners (Linux 7.0) and Linux 6.6.162, requiring the restriction fails with `LockUnsupported` before anything is applied, and a bare `lock()` then succeeds without it. Not run on Linux 7.1 or 7.2 individually. Not independently reviewed.

## M9 — review readiness and 0.2.0

Started. No part of fsgate has had an independent security review. These are the steps between the current state and a release someone can rely on.

- [x] Threat model: one document naming each boundary (the gate before `lock()`, the locked process, the broker and its worker, the experimental launcher), what each trusts, and what each does not stop. Acceptance: the README and RFC limit statements link to it, and every listed attack names the test that covers it or says that none does.

  Evidence: [docs/threat-model.md](docs/threat-model.md). The README and RFCs 0001 to 0004 and 0006 link to it. Every row names a test or says "none", and each named test exists at the commit the document describes. Writing it found gaps that no fsgate test covers:
  - The broker does not authenticate who connects, and it accepts any number of connections. [RFC 0007](docs/rfcs/0007-broker-peers.md) addresses both.
  - Neither the 1 MiB frame limit nor a malformed request has a test. The fuzzing task below covers both.
  - Landlock cannot restrict `stat`, `chmod`, `utime`, or `setxattr`, so a locked process can read metadata anywhere and change the mode of files it owns outside the grants.
  - Hard links and mount points beneath a grant are reachable through both the gate and the kernel rules.

  The document is not independently reviewed.
- [x] Fuzz the broker's server-side decoder: the RFC 0003 framing (length prefix, 1 MiB limit) and JSON request parsing. Acceptance: a `cargo fuzz` target over frame reassembly and request parsing, a recorded run (duration, corpus size, toolchain) without a crash, and a regression test for any crash found.

  Evidence: the `broker_requests` target in [`fuzz/`](fuzz/README.md) feeds arbitrary bytes to `Broker::serve_conn`, as a worker would. Besides panics, hangs, and sanitizer reports, it fails if a descriptor the broker sends back reads the file outside the grant. A control run, with the grant widened to cover that file, trips this check on the `..` seed.

  Recorded run on macOS, with no crash, hang, or check failure:
  - 900 seconds and 53,863,032 inputs, 59,781 per second.
  - The corpus grew from 14 seeds to 1,393 inputs (72 KiB), and coverage from 1,109 to 2,269 counters.
  - Toolchain: rustc 1.102.0-nightly (`f5cedb83a` 2026-11-07), cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13, with AddressSanitizer, on macOS (Apple M1). libFuzzer seed 3216607579.
  - The build combined the harness at `5d95b38` with the decoder from [#38](https://github.com/farming-labs/fsgate/pull/38) at `0c6a876`.

  Reading the decoder for this task found the framing bug that #38 fixes, with its own regression test. The run found no crash, so there is no crash regression test. `broker.rs` now tests the 1 MiB limit and malformed requests directly.

  Recorded run on Linux, [in CI](https://github.com/farming-labs/fsgate/actions/runs/42469046454), also with no crash, hang, or check failure:
  - 901 seconds and 15,559,663 inputs, 17,269 per second.
  - The corpus grew from 14 seeds to 1,274 inputs (82 KiB), and coverage from 969 to 2,027 counters.
  - Toolchain: the same rustc, cargo-fuzz, and libfuzzer-sys as the macOS run, with AddressSanitizer, on Linux 7.0.0-1019-azure x86_64. libFuzzer seed 2985355736.
  - The build is `d9aca86`, which includes the broker's descriptor fix from [#40](https://github.com/farming-labs/fsgate/pull/40).

  [`fuzz.yml`](.github/workflows/fuzz.yml) repeats this run when `broker.rs` or the harness changes. The control run was on macOS only.
- [x] [RFC 0007](docs/rfcs/0007-broker-peers.md) ([#46](https://github.com/farming-labs/fsgate/pull/46)): decide who can reach the broker: an inherited connection and owner-only sockets for `fsgate-broker`, and a peer check and connection limit in `Broker::serve`. Acceptance: the RFC is accepted with its open questions answered.
- [x] Implement RFC 0007 ([#47](https://github.com/farming-labs/fsgate/pull/47), [#48](https://github.com/farming-labs/fsgate/pull/48)). Acceptance: the RFC's tests pass on Linux and macOS, and the threat model's rows for other processes and for many connections cite them.
- [x] [RFC 0011](docs/rfcs/0011-audit-broker-refusals.md) ([#73](https://github.com/farming-labs/fsgate/pull/73)): audit what the broker refuses before the gate: refused peers, the connection limit, and protocol errors, with the peer's uid. It revisits RFC 0007's decision that a refused peer produces no event. Found in an internal review of the broker. Acceptance: the RFC is accepted with its open questions answered.
- [x] Implement RFC 0011. Acceptance: the RFC's tests pass on Linux and macOS, RFC 0002 and RFC 0007 point to it, and the threat model's audit section cites the tests.

  Evidence: six tests in [`tests/broker_serve.rs`](crates/fsgate/tests/broker_serve.rs) drive a real `Broker` over real sockets with a recording sink: a refused peer, an admitted connection before its request, a connection past the limit, four requests that break the protocol (with no gate event and no file created), `serve_conn` without a uid, and, on Linux only, a connection without a thread. Each of the first five fails against the broker before this change. RFC 0002 lists the new values and key, RFC 0007's decision 3 points to RFC 0011, and the threat model's rows and audit section cite the tests. Not independently reviewed.
- [x] [RFC 0008](docs/rfcs/0008-confine-broker-worker.md) ([#51](https://github.com/farming-labs/fsgate/pull/51)): confine the worker `fsgate-broker` starts, so a compromised worker cannot skip the broker on Linux. Acceptance: the RFC is accepted with its decisions recorded.
- [x] Implement RFC 0008 ([#51](https://github.com/farming-labs/fsgate/pull/51)). Acceptance: the RFC's tests pass on Linux 6.6, Linux 7.3, and macOS, and the threat model's rows for a confined worker cite them.

  Evidence comes from [CI](https://github.com/farming-labs/fsgate/actions/runs/42697211561) on `6153b3c`. On Linux 6.6.162 and 7.3.3 (the `kernels` job, release build of the packaged crate) and the `ubuntu-26.04` runners' own kernel, the real `fsgate-broker` ran each scenario in `tests/broker_confined.rs`:
  - A worker's direct read and create outside the grants fail with `EACCES`, and no file appears. A program it starts is confined too. The control run with `--unconfined` succeeds at both.
  - A file the broker serves is refused when opened directly, so the grants did not become worker rules.
  - A descriptor the parent left open is closed in the worker, and a variable is absent unless named with `--env`.
  - Killing the broker kills the worker. The unconfined control keeps running.

  In the boot with `lsm=capability`, on both kernels, the broker exits 1, names `--unconfined`, and the worker's marker is absent. macOS refuses the same way. Two tests are indirect: the session check stands in for `TIOCSTI`, and reading `/proc/<pid>/environ` stands in for `PTRACE_ATTACH`. The default paths have been measured only on Ubuntu 26.04. Not independently reviewed.
- [x] Cover the threat model's untested rows. Acceptance: every row for the gate, `lock()`, and the broker names a test or says why it has none, and a test that shows a defense also shows the attack otherwise works.

  Evidence: the rows of [docs/threat-model.md](docs/threat-model.md) name 12 new tests against the real filesystem, and Linux CI runs them on Linux 6.6, Linux 7.3, and the runner's kernel. In the magic-link and symlink-swap tests an ordinary open reaches the secret, so the attack is real. The symlink-swap test is a stress test: it could show an escape but cannot rule one out. Replacing the gate's open with a path open makes it fail on its first open. Reading cap-std for it showed that the component walk also runs on Linux when `openat2` keeps failing with `EAGAIN`, and the threat model now says so. On ext4 the symlink-swap test exposed a real defect: `Gate::open` could return a directory, which then showed that any directory beneath a grant could be opened and delivered. [#55](https://github.com/farming-labs/fsgate/pull/55) fixed that with its own regression tests. Not independently reviewed.
- [x] [RFC 0009](docs/rfcs/0009-worker-unix-sockets.md) ([#71](https://github.com/farming-labs/fsgate/pull/71)): keep a confined worker off other Unix sockets before Linux 7.1, with a seccomp filter that refuses new `AF_UNIX` sockets and `io_uring`. Found in an internal review of the broker. Acceptance: the RFC is accepted with its open questions answered.
- [x] Implement RFC 0009 ([#76](https://github.com/farming-labs/fsgate/pull/76)). Acceptance: the RFC's tests pass on Linux 6.6, Linux 7.3, and macOS, and the threat model's rows for a confined worker's sockets cite them.

  Evidence: [CI](https://github.com/farming-labs/fsgate/actions/runs/42950556454) on `1f0968f` passed the two new tests in [`tests/broker_confined.rs`](crates/fsgate/tests/broker_confined.rs) on Linux 6.6.162 and 7.3.3 (the `kernels` job), on the `ubuntu-26.04` runner's kernel in all three runs of `check`, and on Rust 1.85 in `msrv`. On every kernel, a confined worker and a program it starts reach no Unix socket outside the grants: not a stream socket by path or by abstract name, and not a datagram socket, from a socket of their own or from half of a datagram pair. The test's sockets receive nothing. Below Linux 7.1, on 6.6 and the runner's kernel, the filter refuses Unix sockets and datagram pairs with `EACCES` and `io_uring` with `ENOSYS`, and an x32 call kills the program with `SIGSYS`, while stream and seqpacket pairs, a TCP socket, and the broker connection still work. On 7.3, where Landlock refuses the connects, the filter is not installed. The unconfined controls reach all three sockets, including with a datagram from half of a pair, which the RFC as accepted would have allowed, and `io_uring` fails there with errors other than `ENOSYS`. The tests went up first, in [CI](https://github.com/farming-labs/fsgate/actions/runs/42950042198) on `01a0a7c`: they failed on 6.6 and the runner's kernel and passed on 7.3. The new tests do not run on macOS, where nothing is confined; the rest of the suite passed there. Not run in that CI: aarch64, which was only built and linted. The `arm64` job added later ran both tests there ([CI](https://github.com/farming-labs/fsgate/actions/runs/43119600394) on `4141869`, after [#77](https://github.com/farming-labs/fsgate/pull/77) merged main). Not run: a call from another architecture, and a kernel that refuses the filter. Not independently reviewed.
- [ ] Independent security review of the handle layer, containment (including M8), broker, and audit sink. Acceptance: the reviewer, scope, reviewed commit, and findings are recorded; each finding is fixed or answered; and the README status says what was reviewed.

  Preparation: [docs/security-review.md](docs/security-review.md) gives a reviewer the scope, the commands, and what the review has to leave behind. [SECURITY.md](SECURITY.md) and GitHub's private vulnerability reporting give anyone a private way to report a bug. No reviewer has been chosen.

  Maintainer decision (2026-11-10): the review is set aside for now, and work moves to [M10](#m10--battle-tested-tests). This item stays open, and the README keeps saying fsgate is unreviewed.
- [x] Release 0.2.0 through the trusted-publishing workflow, its first real run (signed tag [`v0.2.0`](https://github.com/farming-labs/fsgate/tree/v0.2.0), [`fsgate` 0.2.0](https://crates.io/crates/fsgate/0.2.0); preparation in [PR #50](https://github.com/farming-labs/fsgate/pull/50)). Acceptance: the release job's verify step matches the uploaded, crates.io, and downloaded checksums and the `.cargo_vcs_info.json` commit. Before tagging, record two maintainer decisions here: whether 0.2.0 waits for M6 and the review, and whether it includes the `experimental-intercept` feature.

  Maintainer decisions:
  - 0.2.0 does not wait for the independent review, and the README says plainly that it is unreviewed.
  - It does not include `experimental-intercept`. The feature builds only from this repository; in the published crate it stops with a compile error, which CI checks.

  The signed tag `v0.2.0` (tag object `3e7e819`) points to `aee17a7`. Verification for the publish: [CI](https://github.com/farming-labs/fsgate/actions/runs/42691559881) passed `check`, `msrv`, `deny`, `macos`, `workflows`, and the Linux 6.6 and 7.3 `kernels` jobs on `aee17a7`. The [release run](https://github.com/farming-labs/fsgate/actions/runs/42696725231), approved under the `crates-io` environment, passed `cargo test --locked` and the dry run and published through trusted publishing. Its verify step reported one checksum, `627d402dbbe425242bb9f9f29d5711efaec666fce8202a1056ee51186bd84903`, for the uploaded, crates.io, and downloaded archives, and `aee17a7d598d503f5f4454fd37dba93571d37875` in `.cargo_vcs_info.json`. crates.io records the GitHub trusted publisher for `farming-labs/fsgate` at that commit. Locally on macOS with Rust 1.99.1, 80 tests passed from the crate downloaded from crates.io; `cargo install fsgate --version 0.2.0 --locked` builds it and `fsgate-broker` prints its usage; a program depending on `fsgate = "=0.2.0"` reads inside a grant and is refused outside it; and the same dependency with `experimental-intercept` stops at the compile error. The launcher's source ships in the crate, inactive. GitHub marks `v0.2.0` verified. No GitHub release or binary asset was created.
- [x] Release 0.3.0 through the trusted-publishing workflow (signed tag [`v0.3.0`](https://github.com/farming-labs/fsgate/tree/v0.3.0), [`fsgate` 0.3.0](https://crates.io/crates/fsgate/0.3.0); preparation in [PR #56](https://github.com/farming-labs/fsgate/pull/56)). It carries the `Gate::open` directory fix ([#55](https://github.com/farming-labs/fsgate/pull/55)), which 0.1.1 and 0.2.0 lack, and worker confinement ([#51](https://github.com/farming-labs/fsgate/pull/51)), whose new `fsgate-broker` default makes this a minor release. Acceptance: the release job's verify step matches the uploaded, crates.io, and downloaded checksums and the `.cargo_vcs_info.json` commit.

  Maintainer decisions:
  - 0.3.0 does not wait for the independent review, because the `Gate::open` defect is public and the published versions still have it. The README says plainly that it is unreviewed.
  - A fix-only 0.2.1 is not possible: the release workflow publishes only commits on `main`, which already has worker confinement.
  - It does not include `experimental-intercept`, as with 0.2.0.

  The signed tag `v0.3.0` (tag object `2548800`) points to `78a33ae`. [CI](https://github.com/farming-labs/fsgate/actions/runs/42748674037) passed on `78a33ae`. The [release run](https://github.com/farming-labs/fsgate/actions/runs/42749497588), approved under the `crates-io` environment, passed `cargo test --locked`, the dry run, the trusted publish, and its verify step. The archive built locally from `78a33ae`, the crates.io checksum, and the crate downloaded from `static.crates.io` all agree on `994d202864ac1c81ce402da4d47182d010360d74c228a77d2f0544ce9d775ac4`, and `.cargo_vcs_info.json` records `78a33ae5303465697694d6d83917dfd2f31ee306`. crates.io records the GitHub trusted publisher for `farming-labs/fsgate` at that commit. Locally on macOS with Rust 1.99.1, 96 tests passed from the crate downloaded from crates.io; `cargo install fsgate --version 0.3.0 --locked` builds it and `fsgate-broker` prints its usage; a program depending on `fsgate = "=0.3.0"` reads inside a grant, is refused outside it, and gets `EISDIR` for a directory; and the same dependency with `experimental-intercept` stops at the compile error. GitHub marks `v0.3.0` verified. No GitHub release or binary asset was created.
- [x] [RFC 0010](docs/rfcs/0010-worker-process-group.md) ([#72](https://github.com/farming-labs/fsgate/pull/72)): end a confined worker's programs with it, by killing its process group when it exits or when the broker gets `SIGINT`, `SIGTERM`, or `SIGHUP`. Found in an internal review of the broker. Acceptance: the RFC is accepted with its open questions answered.
- [x] Implement RFC 0010. Acceptance: the RFC's tests pass on Linux 6.6 and Linux 7.3, and the threat model's rows for a confined worker's lifetime cite them.

  Evidence: [CI](https://github.com/farming-labs/fsgate/actions/runs/42946400437) on `9f81bad` passed the five new tests in [`tests/broker_confined.rs`](crates/fsgate/tests/broker_confined.rs) on Linux 6.6.162 and 7.3.3 (the `kernels` job), on the `ubuntu-26.04` runner's kernel in all three runs of `check`, and on Rust 1.85 in `msrv`. A program a confined worker leaves running ends with it. `SIGTERM`, `SIGINT`, or `SIGHUP` to the broker ends the worker and its program, and the broker dies by that signal. The worker can still be stopped by `SIGTERM`. In the controls, a program that calls `setsid` and an unconfined worker's program keep running. The tests went up first and failed on the first two cases. Without the confining process unblocking the stop signals, only the third failed: implementing the RFC found that `std` keeps a child's signal mask, which the RFC had said it resets. Not run: a broker under `nohup`, and a signal that arrives before the worker starts. Not independently reviewed.

Order: M8 first, because it changes what `lock()` means for existing users and its `LockStatus` change needs a minor release anyway. Then the threat model and fuzzing, then RFC 0007, then 0.2.0, then RFC 0008 so the reviewer sees the final broker, then 0.3.0 for the `Gate::open` fix, then the review. M6's tasks are all done ([#35](https://github.com/farming-labs/fsgate/pull/35) closed the last); it remains unreviewed and unreleased.

## M10 — battle-tested tests

Started. Today each attack in the threat model has a test written for it, and one stress test races a symlink swap. Those check cases someone chose. These tasks check the same claims against generated inputs, on more kernels and systems, and measure whether the tests catch bugs put in on purpose.

- [x] Model-based tests of the gate ([`tests/gate_model.rs`](crates/fsgate/tests/gate_model.rs), [#60](https://github.com/farming-labs/fsgate/pull/60)). Generate trees of directories, files, and symlinks (inner, escaping, absolute, dangling, and looping), nested grants with random rights, and sequences of `open`, `create`, `metadata`, `read_dir`, `grant`, `narrow`, and `revoke`. Acceptance: every success reaches an object beneath the grant it was routed to, checked by inode against the real tree; every failure leaves the tree unchanged, outside the grants included; each answer and its audit event match a reference model of RFC 0001's resolution and RFC 0002's events; the run fails if it never reaches one of the answers it is meant to check; a shrunk failure is kept as a fixed case; and CI runs it on Linux (`openat2`) and macOS (the component walk). Controls: replacing the gate's open with a plain path open, or routing to the shortest grant, makes it fail.

  Evidence: [CI](https://github.com/farming-labs/fsgate/actions/runs/42907442197) on `0f2e46a` passed both tests in `gate_model.rs` on the `ubuntu-26.04` runner's kernel, where the gate resolves with `openat2`, in all three runs of the `check` job (the checkout, `experimental-intercept`, and the packaged crate), on Rust 1.85 in the `msrv` job, and on macOS, where it uses cap-std's component walk. Each default run is 512 cases. On macOS, two runs of 20,000 cases also passed. The test found two defects in how refusals are recorded, fixed in [#58](https://github.com/farming-labs/fsgate/pull/58) and [#59](https://github.com/farming-labs/fsgate/pull/59); the decisions themselves were correct. The two controls fail within a second. The generator makes no hard links, mounts, or concurrent renames, and the model follows RFC 0001, so it cannot find a flaw in the RFC's own rules.
- [ ] Gate and kernel agree. On Linux, replay the generated cases as raw opens in a locked child. Acceptance: every place the kernel and the gate answer differently is one the threat model documents, such as a nested grant's lesser right, or it is fixed.
- [x] Mutation testing of the security core (`lib.rs`, `containment.rs`, `broker.rs`, `broker_sys.rs`, and `fsgate-broker` with `confine.rs`) with `cargo-mutants`, on Linux and macOS ([`.cargo/mutants.toml`](.cargo/mutants.toml), [`mutants.yml`](.github/workflows/mutants.yml), [#80](https://github.com/farming-labs/fsgate/pull/80)). Acceptance: the caught and missed counts are recorded, and each missed mutant in an authorization, resolution, or confinement path gets a test that catches it or a written reason it cannot change behavior.

  Evidence: [CI](https://github.com/farming-labs/fsgate/actions/runs/43126099546) on `5373307`, with cargo-mutants 27.1.0 and rustc 1.99.1, after the worker's supervisor (RFC 0010) and Unix socket filter (RFC 0009) merged:

  | Platform | Mutants | Caught | Timed out | Missed | Did not build |
  |---|---|---|---|---|---|
  | The runner's Linux 7.0 (Landlock ABI v8), with `experimental-intercept` | 420 | 281 | 8 | 29 | 102 |
  | macOS | 278 | 196 | 6 | 6 | 70 |

  The first macOS run, before any new test, missed 26 mutants. The first Linux run, with the tests for those added, missed 28. Two let a lock or a worker hold more than asked for. Building the requested restrictions with `&` instead of `|` left a plain `lock()` restricting nothing beyond files. A `--direct <dir>:l` without its match arm gave the worker execute instead of list. The other new tests cover the rights and restrictions as sets, errnos and remedies, the broker's 1 MiB frame limit, and finding the worker on `PATH`. After RFCs 0009 and 0010 merged, the Linux run found that the stray-descriptor test planted one stray, above the worker's connection, so leaving every descriptor below the connection open still passed. It now plants one on each side.

  Every remaining miss is listed in [`.github/mutants/`](.github/mutants) with the reason it cannot change behavior on that platform:
  - code the platform does not build;
  - `^` for `|` on distinct flags, and `&` between the socket filter's `BPF_LD` and `BPF_W`, which are both 0;
  - checks that only a kernel below Landlock ABI v3 reaches, which the kernels job's boot without Landlock covers;
  - whether Landlock refuses Unix socket connects itself, which is false below Linux 7.1 anyway, and which the kernels job's 7.3 boot checks;
  - a descriptor number the broker never uses.

  The workflow fails when the misses differ from the lists, but it runs only on demand and when its setup changes, so a change to the code can add a miss that the next run reports. Doctests are left out. A timeout counts as caught: each one leaves a client waiting for an answer that never comes. Mutation testing also found a flaky coverage check in the model test, fixed in [#79](https://github.com/farming-labs/fsgate/pull/79). A flaky test can also make a listed miss look caught and fail the run: in one run, `a_program_a_confined_worker_leaves_running_ends_with_it` reported "the program never ran" under an equivalent mutant.
- [x] More fuzzing: targets for the `--grant` and `--direct` parsers and for path resolution beneath a fixed tree, where nothing outside the tree may be reached. Run every target on a weekly schedule as well as when the code changes. Acceptance: each target has seeds and a recorded run with its duration, and every crash becomes a regression test.

  Evidence ([#81](https://github.com/farming-labs/fsgate/pull/81)): two targets join `broker_requests` in [`fuzz/`](fuzz/README.md), each with seeds and a dictionary.
  - `gate_paths` runs `open`, `create`, `metadata`, and `read_dir` on arbitrary paths through one gate. Its three nested grants cover a fixed tree whose symlinks stay inside, climb out, are absolute, dangle, or loop. It fails if a success reaches an object outside the grant the path routes to, checked by device and inode. It also fails if a refusal is not the one the routing calls for, or if anything changes but the file a `create` returned.
  - `broker_args` compares `fsgate-broker`'s parser with a restatement of its rules, for each `--grant` and `--direct` spec and for the mode the options select. The parser moved unchanged into [`fsgate-broker/args.rs`](crates/fsgate/src/bin/fsgate-broker/args.rs) so the target can include it, and [`.cargo/mutants.toml`](.cargo/mutants.toml) examines it there.
  - [`fuzz.yml`](.github/workflows/fuzz.yml) runs every target on Linux, and `gate_paths` on macOS too. Each runs for 15 minutes when the crate or a harness changes, and for an hour every Monday.

  Controls: each defect below was put in on purpose, and fuzzing from one or two seeds found it, with libFuzzer seed 1 on macOS.

  | Defect | Target | Found after | Check that failed |
  |---|---|---|---|
  | `open` follows the path from the root, not beneath the grant | `gate_paths` | 100,511 inputs, about a minute | `granted/up` reached the secret outside the grant |
  | Routing picks the shortest covering grant | `gate_paths` | 51,386 inputs, under 40 seconds | A `create` in the writable grant was refused with the outer grant's rights |
  | `create` follows the path from the root | `gate_paths` | 15,937 inputs, under 40 seconds | `create` through `w/wup` truncated `granted/a.txt` |
  | `--direct` accepts `w` | `broker_args` | 6,155 inputs, under 3 seconds | `--direct /data:rldata:rw` was accepted |
  | Interception mode accepts `--unconfined` | `broker_args` | 303,507 inputs, under 12 seconds | An interception command line with `--unconfined` was accepted |

  At first the last control was not found in five minutes, twice: once with a dictionary of the option names and once with each name ending in a NUL. One input byte now stands for an option, so changing it swaps one option for another.

  Recorded runs, none with a crash, hang, or check failure. The first two ran locally; the rest are the [`fuzz` jobs](https://github.com/farming-labs/fsgate/actions/runs/43089069857) on `144078d`, with the same seeds and flags.

  | Target | Where | Seconds | Inputs | Per second | Corpus | Coverage counters | libFuzzer seed |
  |---|---|---|---|---|---|---|---|
  | `gate_paths` | macOS 26.2, Apple M1 | 901 | 371,858 | 412 | 9 seeds to 564 inputs (82 KiB) | 1,037 to 1,095 | 4200607416 |
  | `broker_args` | macOS 26.2, Apple M1 | 901 | 5,846,233 | 6,488 | 19 seeds to 733 inputs (167 KiB) | 442 to 614 | 4200606091 |
  | `gate_paths` | Linux 7.0.0-1019-azure x86_64 | 901 | 411,576 | 456 | 9 seeds to 405 inputs (63 KiB) | 840 to 873 | 859958495 |
  | `broker_args` | Linux 7.0.0-1019-azure x86_64 | 901 | 3,155,653 | 3,502 | 19 seeds to 759 inputs (211 KiB) | 444 to 622 | 2992076140 |
  | `broker_requests` | Linux 7.0.0-1019-azure x86_64 | 901 | 26,466,766 | 29,374 | 14 seeds to 1,376 inputs (74 KiB) | 1,013 to 2,111 | 2081091315 |
  | `gate_paths` | macOS runner, Darwin 25.6.0 arm64 | 901 | 385,580 | 427 | 9 seeds to 566 inputs (82 KiB) | 1,037 to 1,098 | 1508359095 |

  Toolchain everywhere: rustc 1.102.0-nightly (`f5cedb83a` 2026-11-07), cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13, with AddressSanitizer. No run found a crash, so there is no crash regression test. `gate_paths` resolves with `openat2` on Linux and with cap-std's component walk on macOS, so the two platforms cover different code. The weekly run starts once this workflow is on `main`.

  The tree has no hard links or mounts, and no rename happens while a path resolves; the threat model lists those gaps. The parser's restatement follows the same rules, so it cannot find a flaw in the rules themselves. The corpus is not kept between CI runs, so each run starts from the seeds.
- [x] More kernels and an architecture. Add Linux 6.1 (Landlock ABI v2, below fsgate's floor, where a strict `lock()` and a confined worker must fail closed) and 6.12 (the first kernel with signal and abstract socket scopes) to the `kernels` job, and run `check` on an arm64 runner too. Acceptance: the threat model's row for Landlock ABI below v3 names a test. ([#77](https://github.com/farming-labs/fsgate/pull/77))

  Evidence: [CI](https://github.com/farming-labs/fsgate/actions/runs/43115468823) on `6f7cb0f`. The threat model's rows for a strict lock, a best-effort lock, and a confined worker below Landlock ABI v3 name the 6.1 tests.
  - Linux 6.1.192 (Landlock ABI v2) runs only the three `below_landlock_v3` tests, and requires exactly three to pass. Each first checks that the kernel's Landlock is v2.
    - A strict `lock()` returns `LockUnsupported` and applies nothing, so a raw read outside the grants still works.
    - A best-effort lock reports `PartiallyEnforced`. The kernel refuses a read and a create outside the grants, but a raw `truncate(2)` empties a file beneath a read-only grant.
    - `fsgate-broker` refuses to start a confined worker and names `--unconfined`; the `--unconfined` control starts it.
  - Linux 6.12.117 (ABI v6) passes the full suite and the boot without Landlock. It is the only kernel in CI where the signal and abstract socket scopes are enforced, each with its control, while the all-threads and pathname socket restrictions take their refusal path.
  - A new `arm64` job runs clippy and `cargo test --locked` on `ubuntu-26.04-arm`, including the confined-worker tests. Its kernel is 7.0.0-1019-azure, according to the runner image's notes. Formatting, the packaged crate, and the fuzz crate stay in `check` on x86_64, and so does `experimental-intercept`, whose launcher is x86_64 only. After RFC 0009 merged, [CI](https://github.com/farming-labs/fsgate/actions/runs/43119600394) on `4141869` ran its two tests on arm64 and on 6.12, so the worker's seccomp filter now runs on aarch64 too.

  Writing this found that the guest script could pass without checking its count. A child process's test summary broke the count's arithmetic, so bash skipped the rest of the mode and still wrote `<mode>.passed` ([the 6.1 job](https://github.com/farming-labs/fsgate/actions/runs/42965991693/job/130343239403) passed that way). The script now counts each executable's last summary and stops on a missing one. A control commit that expected four tests failed with "expected 4 passing \*below_landlock_v3\* tests, got 3" ([run](https://github.com/farming-labs/fsgate/actions/runs/43115058029)). Not run: the `kernels` job on arm64, and the full suite on 6.1, where strict locks fail by design.
- [x] The confined worker beyond Ubuntu. Run `tests/broker_confined.rs` in Debian, Fedora, Arch, Alpine (musl), and NixOS containers on the runner's kernel. Acceptance: [RFC 0008](docs/rfcs/0008-confine-broker-worker.md)'s open question is answered with what each system needs, and the default paths or the docs change to match. ([#83](https://github.com/farming-labs/fsgate/pull/83))

  Evidence: a `distros` job in [`ci.yml`](.github/workflows/ci.yml) runs the tests in containers pinned by digest, on the runner's Linux 7.0. Each builds them with the system's own toolchain ([`.github/distros/`](.github/distros)), so they load through its own loader and libc, and runs them as the runner's user with no `--direct`.
  - Debian 13 (rustc 1.85.1), Fedora 45 (1.99.1), Arch (1.99.1), and Alpine 3.24 with musl (1.96.1) passed all 47 under the old defaults ([CI](https://github.com/farming-labs/fsgate/actions/runs/43162403028) on `112acfe`). Their loaders are `/lib64/ld-linux-x86-64.so.2`, or `/lib/ld-musl-x86_64.so.1` on Alpine.
  - The `nixos/nix` image (nixpkgs `nixos-26.05`, rustc 1.95.0) has NixOS's layout, with every program, loader, and library in `/nix/store`. In the same run, 18 tests failed: the worker could not start, with `EACCES`.
  - [RFC 0008](docs/rfcs/0008-confine-broker-worker.md#answer) now lists `/nix/store` as a runtime directory, and all five pass 47 ([CI](https://github.com/farming-labs/fsgate/actions/runs/43162855571) on `5eb744b`). The README, the threat model, and the changelog list it too.

  Not run: a full NixOS system, Guix, and arm64 containers. Arch packages are not pinned, so its toolchain is whatever is current when the job runs.

Order: the model-based tests first, because they cover the most code on both platforms and need no new CI machinery. Then the kernel comparison, which reuses them, then mutation testing to find what all the tests miss, then fuzzing, kernels, and distributions.

## Out of scope for v1

Preload shim for unmodified binaries, Windows, quotas and rate budgets, network or non-filesystem capabilities.
