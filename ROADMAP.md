# Roadmap

This file owns task status. A box is checked only when the acceptance criteria are met, the change is merged, and the PR is linked as evidence.

## M0 — foundation

- [x] Scaffold workspace, roadmap, and core design RFC (dec192b)
- [x] Pin dependency decisions: `cap-std` version, Landlock crate (`landlock`), seccomp crate (`seccompiler` vs raw `libseccomp`), MSRV ([ADR 0001](docs/decisions/0001-dependency-pins.md))
- [x] Add `cargo-deny` config and wire it into CI
- [x] Decide and document the audit event format ([RFC 0002](docs/rfcs/0002-audit-events.md))

Acceptance: decisions recorded as RFCs or ADRs with the rejected alternatives named; CI runs fmt, clippy `-D warnings`, test `--locked`, and deny on every PR.

## M1 — handle layer and resolver (Linux first)

- [ ] `Gate::new`, `grant(path, Rights) -> Grant`, `Rights` (READ, WRITE, CREATE, LIST)
- [ ] Resolver: longest-grant match, then open beneath the handle via `openat2` + `RESOLVE_BENEATH`
- [ ] `open`, `read`, `write`, `metadata`, `read_dir` through the gate
- [ ] Fail-closed errors: `NoGrant`, `RightsExceeded`, each naming the path and the missing right

Acceptance: tests cover allowed operations, denied operations, symlink escape attempts, `..` traversal, and absolute-path symlink targets — and the denial tests assert the side effect did not happen. No name/string-prefix check anywhere in the enforcement path.

## M2 — process lock

- [ ] `lock()`: apply Landlock ruleset derived from the grants + seccomp filter denying path-based syscalls
- [ ] `lock()` is irreversible; `grant()` after `lock()` fails
- [ ] Graceful degradation is explicit: on kernels without Landlock, `lock()` returns an error unless the caller opts into `LockPolicy::BestEffort`

Acceptance: a test spawns a child, locks it, and proves raw `std::fs::File::open` of an ungated path fails at the kernel, not in the library.

## M3 — broker (macOS and defense in depth)

- [ ] `fsgate-broker` binary: parent holds grants, child requests opens over a Unix socket, descriptors passed via `SCM_RIGHTS`
- [ ] Same `Gate` API in the child, backed by the broker transport
- [ ] Broker applies the same rights checks server-side; the child is never trusted

Acceptance: broker-backed tests pass on macOS and Linux; killing the broker fails all child filesystem operations closed.

## M4 — revocation and audit

- [ ] `revoke(grant)` takes effect for subsequent operations and is covered by tests
- [ ] Every allow/deny decision emits a structured audit event (format from RFC 0002)

## M5 — v0.1.0

- [ ] API review pass against RFC 0001; deviations folded back into the RFC
- [ ] Docs: every public item documented, README examples compile as doctests
- [ ] Release v0.1.0 (signed tag). Publishing to crates.io is a separate, explicit maintainer decision.

## Out of scope for v1

Preload shim for unmodified binaries, Windows, quotas and rate budgets, network or non-filesystem capabilities.
