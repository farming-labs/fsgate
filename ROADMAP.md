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

- [ ] API review pass against RFC 0001; deviations folded back into the RFC
- [ ] Docs: every public item documented, README examples compile as doctests
- [ ] Release v0.1.0 (signed tag). Publishing to crates.io is a separate, explicit maintainer decision.

Preparation: the local branch folds `LockStatus`, `create` rights, audit delivery, broker client types, and containment limits into RFC 0001. It requires public documentation, compiles the README as a doctest, and adds a CI check that tests the unpacked crate. Audit regression coverage checks the actual matched grant ID for duplicate and nested grants, revocation, and broker requests. These items remain unchecked until merged; no signed release tag exists yet.

Local verification on macOS (Rust 1.99.1): `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, and `RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps` passed. `cargo test --locked` passed 32 runtime tests and two compile-only doctests. `cargo package --locked` succeeded; the same 34 tests passed against the archive extracted outside the repository. `cargo deny check` passed with warnings for duplicate dependencies and unused license allowances. The duplicate-grant audit tests and packaged README doctest failed before their fixes. Rust 1.85.0 also passed all 34 tests in both the checkout and the unpacked crate. CI now runs the suite on Linux with stable Rust and Rust 1.85.0; Linux enforcement remains pending CI verification.

## Out of scope for v1

Preload shim for unmodified binaries, Windows, quotas and rate budgets, network or non-filesystem capabilities.
