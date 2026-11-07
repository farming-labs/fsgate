# RFC 0002: audit event format

- Status: accepted
- Date: 2026-11-06

## Problem

Every authority decision fsgate makes must be observable by the embedder — for debugging denials, for intrusion detection, and for proving what a sandboxed workload actually touched. The format has to be stable enough to build tooling on.

## Format

One event per decision, as a Rust struct delivered to a sink trait; the canonical serialized form is JSON Lines.

```json
{"v":1,"ts":"2026-11-06T12:00:00.000Z","op":"open","path":"/srv/data/users/1.json","grant":0,"decision":"allow","reason":"ok","errno":null}
{"v":1,"ts":"2026-11-06T12:00:01.000Z","op":"create","path":"/etc/cron.d/x","grant":null,"decision":"deny","reason":"no_grant","errno":null}
```

Fields:

- `v` — format version, starts at 1. The contract is versioned and only gains keys within a version; removing or retyping a key bumps `v`.
- `ts` — RFC 3339 UTC with milliseconds.
- `op` — `grant`, `revoke`, `narrow` (RFC 0005), `lock`, `open`, `create`, `metadata`, `read_dir` (grows with the API).
- `path` — the normalized requested path. For `grant`/`revoke`/`narrow`, the grant's path. `null` for `lock`, which has no path.
- `grant` — the matched grant's id, or `null` when none matched.
- `decision` — `allow` or `deny`. An operation that passed policy but failed at the kernel is `allow` with a non-null `errno`: policy said yes, the OS said no, and both facts are recorded.
- `reason` — `ok`, `no_grant`, `rights_exceeded` (for `narrow`: the requested set names a right the grant does not hold), `not_absolute`, `locked`, `unsupported` (a lock the kernel could not enforce), `unknown_grant` (revoking or narrowing a grant that does not exist). Grows with the API.
- `errno` — OS error number when the underlying syscall failed, else `null`.

## Delivery

```rust
pub trait AuditSink: Send + Sync {
    fn event(&self, event: &AuditEvent);
}
```

- Delivery is synchronous in the calling thread; the embedder owns buffering and backpressure. fsgate never drops an event itself and never blocks on anything but the sink the embedder installed.
- The default sink is a no-op. Auditing is opt-in and costs one branch when off.
- Events are emitted after the decision and before the result returns, so a sink always sees a denial even if the caller swallows the error.

## Rust compatibility

`AuditOp`, `AuditReason`, and `AuditEvent` are `#[non_exhaustive]`, so new operations, reasons, and fields do not need a breaking release. This mirrors the wire rule: version 1 gains keys and `op`/`reason` values, so tooling reading JSON Lines must accept unknown values too.

- A `match` on `AuditOp` or `AuditReason` outside fsgate needs a wildcard arm.
- Code outside fsgate reads `AuditEvent` fields or destructures with `..`. It cannot build an event; only a `Gate` creates them, so test a sink by driving a gate.
- `AuditDecision` stays exhaustive: allow and deny are the whole decision space.

## Non-goals

Signing or tamper-evidence of the log (the embedder's storage problem), rate limiting, and sampling. Nothing in the sink can veto or alter a decision; audit is observation only.
