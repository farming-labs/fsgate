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
- [ ] Release v0.1.0 (signed tag). Publishing to crates.io is a separate, explicit maintainer decision.

Preparation merged in PR #1: `LockStatus`, `create` rights, audit delivery, broker client types, and containment limits are folded into RFC 0001. Public documentation is required, the README compiles as a doctest, and CI tests the unpacked crate. Audit regression coverage checks the actual matched grant ID for duplicate and nested grants, revocation, and broker requests. The signed release remains pending; follow [the release procedure](docs/RELEASING.md).

Verification for PR #1: macOS formatting, clippy, rustdoc, and cargo-deny checks passed. The 32 runtime tests and two compile-only doctests passed from both the checkout and the unpacked crate on Rust 1.99.1 and 1.85.0. The duplicate-grant audit tests and packaged README doctest failed before their fixes. [Linux CI](https://github.com/farming-labs/fsgate/actions/runs/42288527953) passed `check`, `msrv`, and `deny` on head `c5d2f7c`: the kernel bypass-denial test passed on stable Rust and Rust 1.85.0, and the stable job tested the unpacked crate. The automated reviewer was skipped; this is not an independent security review.

## M6 — Linux filesystem interception (experimental)

Proposed after M5 / v0.1.0; not implemented and not assigned a release version. Design: [RFC 0004](docs/rfcs/0004-filesystem-interception.md). M2 already enforces Linux filesystem rules in the kernel. M6 would let a supported binary's ordinary file-open syscalls reach the broker without linking fsgate or calling `BrokerGate`.

Planning landed in [#2](https://github.com/farming-labs/fsgate/pull/2). The prototype profile merged in [#4](https://github.com/farming-labs/fsgate/pull/4) (`9699168`): native Linux x86_64 static binaries, with Linux 6.6 as the initial test baseline, seccomp notifications, broker-side read-only opens, a separate executable rule, a syscall allowlist, and atomic descriptor delivery. That settles the design task only; the profile has no Linux runtime evidence and no independent security review yet.

- [x] Settle the authority boundary and backend in RFC 0004 ([#4](https://github.com/farming-labs/fsgate/pull/4)): review the specified seccomp notification profile and its distinction from a preload shim and privileged eBPF LSM hooks. Acceptance: record the supported kernel/architecture, syscall and flag coverage, bootstrap authority, and bypass analysis before runtime implementation.
- [ ] Add an opt-in experimental launcher using the existing grant resolver and audit sink. Acceptance: the worker starts only after required kernel support, containment, descriptor cleanup, and supervisor readiness are confirmed; unsupported hosts fail before executing the target.
- [ ] Intercept the supported `open` / `openat` / `openat2` calls, initially read-only regular files named by absolute paths. Acceptance: standalone libc and direct-syscall fixtures read granted bytes without a fsgate dependency, and unsupported arguments return documented errors without ambient fallback.
- [ ] Enforce broker-side authorization and descriptor delivery. Acceptance: denied opens and attempted writes leave protected files unchanged, symlink and argument races cannot escape a grant, and mediated decisions reach the audit sink.
- [ ] Handle shutdown, cancellation, and revocation. Acceptance: supervisor death prevents new brokered opens, interrupted requests leak no descriptors, descendants retain restrictions, and revocation denies subsequent brokered opens. Document that already-delivered file descriptors remain usable.
- [ ] Verify and document the supported subset from a release build and unpacked crate on Linux. Acceptance: real-filesystem denial and bypass tests pass on the declared kernels and architectures, unsupported-host startup tests pass, and the README and example state the remaining compatibility limits.

M6 does not promise every filesystem syscall or arbitrary binary compatibility. Relative paths and directory descriptors, writes and creation, metadata, and directory enumeration need explicit semantics and coverage before support expands. macOS interception, a preload shim, and a custom eBPF LSM backend are not part of the proposed first implementation.

## M7 — grant narrowing

Implemented in [#6](https://github.com/farming-labs/fsgate/pull/6) and included in v0.1.0; independent of M6. Design: [RFC 0005](docs/rfcs/0005-grant-narrowing.md), which resolves RFC 0001's attenuated-grant open question. `GateError` and `AuditOp` are non-exhaustive, so the new variants are additive.

- [x] `Gate::narrow(grant, rights)` narrows a live grant in place ([#6](https://github.com/farming-labs/fsgate/pull/6)), before or after `lock()`, keeping its id and held directory handle. Acceptance: denied operations after narrowing leave files absent or unchanged; a set naming a right the grant lacks fails with `GateError::WouldWiden` and leaves the grant unchanged, including an attempt to restore narrowed rights; narrowing a revoked grant fails with `UnknownGrant`; swapping a different directory in under the granted path does not change what the narrowed grant reaches.
- [x] Kernel enforcement follows the narrowed rights ([#6](https://github.com/farming-labs/fsgate/pull/6)). Acceptance: a Linux locked child proves raw writes beneath a grant narrowed before `lock()` fail at the kernel and leave files unchanged, and that narrowing after `lock()` denies gate operations without side effects.
- [x] Audit: one `narrow` event per decision (RFC 0002, [#6](https://github.com/farming-labs/fsgate/pull/6)). Acceptance: tests cover allow, a widening denial (`rights_exceeded`), and an unknown grant (`unknown_grant`), each naming the narrowed grant's id.

Acceptance met: `tests/gate.rs` covers denied creates and truncation after narrowing with files left absent or unchanged, `WouldWiden` on an attempt to restore the original rights with the grant left read-only, `UnknownGrant` after revocation, and a directory swapped in under the granted path. `tests/lock.rs` runs a strict-locked child: a raw write beneath a grant narrowed before `lock()` fails with `PermissionDenied` and leaves the file unchanged, and narrowing after `lock()` denies `create` without creating the file. `tests/audit.rs` checks the allow, `rights_exceeded`, and `unknown_grant` events name grant 1. [Linux CI](https://github.com/farming-labs/fsgate/actions/runs/42320274648) ran the locked-child test on stable and Rust 1.85.0 at #6's head `238351f`. Not independently reviewed.

## Out of scope for v1

Preload shim for unmodified binaries, Windows, quotas and rate budgets, network or non-filesystem capabilities.
