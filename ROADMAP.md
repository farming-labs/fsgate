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

Design accepted in [RFC 0006](docs/rfcs/0006-lock-restrictions.md). Implemented ([#36](https://github.com/farming-labs/fsgate/pull/36), [#43](https://github.com/farming-labs/fsgate/pull/43)) and unreleased. Before M8, `lock()` installed Landlock filesystem rules up to ABI v3 and nothing else. A locked process could therefore still connect to Unix domain sockets and signal processes outside the sandbox, and through them reach an unconfined process that acts on files for it or passes it descriptors ([#30](https://github.com/farming-labs/fsgate/pull/30) documents this). The `landlock` 0.4.7 crate fsgate already pins supports the ABIs that restrict these. CI runners boot Linux 7.0, so ABI v5, v6, and v8 are tested there; ABI v9 (Linux 7.1) is tested on Linux 7.3 in the `kernels` job.

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
- [ ] Implement RFC 0007. Acceptance: the RFC's tests pass on Linux and macOS, and the threat model's rows for other processes and for many connections cite them.
- [ ] Independent security review of the handle layer, containment (including M8), broker, and audit sink. Acceptance: the reviewer, scope, reviewed commit, and findings are recorded; each finding is fixed or answered; and the README status says what was reviewed.
- [ ] Release 0.2.0 through the trusted-publishing workflow, its first real run. Acceptance: the release job's verify step matches the uploaded, crates.io, and downloaded checksums and the `.cargo_vcs_info.json` commit. Before tagging, record two maintainer decisions here: whether 0.2.0 waits for M6 and the review, and whether it includes the `experimental-intercept` feature.

Order: M8 first, because it changes what `lock()` means for existing users and its `LockStatus` change needs a minor release anyway. Then the threat model and fuzzing, then RFC 0007, so the reviewer sees the final broker, then the review, then 0.2.0. M6's tasks are all done ([#35](https://github.com/farming-labs/fsgate/pull/35) closed the last); it remains unreviewed and unreleased.

## Out of scope for v1

Preload shim for unmodified binaries, Windows, quotas and rate budgets, network or non-filesystem capabilities.
