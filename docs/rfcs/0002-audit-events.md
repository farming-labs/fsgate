# RFC 0002: audit event format

- Status: accepted
- Date: 2026-11-06

## Problem

Every authority decision fsgate makes must be observable by the embedder — for debugging denials, for intrusion detection, and for proving what a sandboxed workload actually touched. The format has to be stable enough to build tooling on.

## Format

One event per decision, as a Rust struct delivered to a sink trait; the canonical serialized form is JSON Lines.

```json
{"v":1,"ts":"2026-11-06T11:59:59.000Z","op":"grant","path":"/srv/data","grant":0,"rights":["read","list"],"restrictions":null,"status":null,"decision":"allow","reason":"ok","errno":null,"syscall":null,"notification":null,"peer_uid":null}
{"v":1,"ts":"2026-11-06T11:59:59.500Z","op":"lock","path":null,"grant":null,"rights":null,"restrictions":["ioctl_dev","abstract_unix_socket","signal","all_threads"],"status":"fully_enforced","decision":"allow","reason":"ok","errno":null,"syscall":null,"notification":null,"peer_uid":null}
{"v":1,"ts":"2026-11-06T12:00:00.000Z","op":"open","path":"/srv/data/users/1.json","grant":0,"rights":null,"restrictions":null,"status":null,"decision":"allow","reason":"ok","errno":null,"syscall":null,"notification":null,"peer_uid":null}
{"v":1,"ts":"2026-11-06T12:00:01.000Z","op":"create","path":"/etc/cron.d/x","grant":null,"rights":null,"restrictions":null,"status":null,"decision":"deny","reason":"no_grant","errno":null,"syscall":null,"notification":null,"peer_uid":null}
{"v":1,"ts":"2026-11-06T12:00:02.000Z","op":"open","path":"a.txt","grant":null,"rights":null,"restrictions":null,"status":null,"decision":"deny","reason":"unsupported_input","errno":null,"syscall":"openat","notification":7,"peer_uid":null}
{"v":1,"ts":"2026-11-06T12:00:03.000Z","op":"connect","path":null,"grant":null,"rights":null,"restrictions":null,"status":null,"decision":"deny","reason":"peer_refused","errno":null,"syscall":null,"notification":null,"peer_uid":1001}
```

Fields:

- `v` — format version, starts at 1. The contract is versioned and only gains keys within a version; removing or retyping a key bumps `v`.
- `ts` — RFC 3339 UTC with milliseconds.
- `op` — `grant`, `revoke`, `narrow` (RFC 0005), `lock`, `open`, `create`, `metadata`, `read_dir`, and from a broker `connect` and `request` ([RFC 0011](0011-audit-broker-refusals.md)) (grows with the API).
- `path` — the normalized requested path. For `grant`/`revoke`/`narrow`, the grant's path. `null` for `lock`, which has no path.
- `grant` — the matched grant's id, or `null` when none matched. `revoke` and `narrow` of an already revoked grant record the requested id; a grant from another gate is `null`, because its id names nothing in this gate.
- `rights` — for `grant` and `narrow`, the rights the grant holds after the decision, as an array of `read`, `write`, `create`, `list` in that order; `[]` for a grant narrowed to no rights. A refused widening records the unchanged set. `null` when no grant was created or matched, and for every other `op`. Added within v1 (RFC 0005).
- `restrictions` — for a successful `lock`, the [RFC 0006](0006-lock-restrictions.md) restrictions that took effect, as an array of `ioctl_dev`, `abstract_unix_socket`, `signal`, `all_threads`, `resolve_unix` in that order; `[]` when none did. `null` for a refused `lock` and every other `op`. Added within v1.
- `status` — for a successful `lock`, what the kernel enforced for the filesystem rules built from the grants: `fully_enforced`, `partially_enforced` (an older Landlock ABI), or `library_only` (nothing; only a `BestEffort` lock succeeds this way). `null` for a refused `lock` and every other `op`. Without it, a best-effort lock the kernel did not enforce read the same as an enforced one. Added within v1.
- `decision` — `allow` or `deny`. An operation that passed policy but failed at the kernel is `allow` with a non-null `errno`: policy said yes, the OS said no, and both facts are recorded.
- `reason` — `ok`, `no_grant`, `rights_exceeded` (for `narrow`: the requested set names a right the grant does not hold), `not_absolute`, `locked`, `unsupported` (a lock the kernel could not enforce), `unknown_grant` (revoking or narrowing a grant that does not exist), `unsupported_input` (an intercepted request outside the RFC 0004 file-open contract: a relative or non-canonical path, a path that is not UTF-8, a write or other unsupported flag, or an unsupported `openat2` layout or resolve flag), `invalid_memory` (an intercepted request whose arguments could not be copied out of the worker), and for the broker's own decisions (RFC 0011) `peer_refused`, `connection_limit`, `no_thread`, `frame_too_large`, `malformed_frame`, `malformed_request`. Grows with the API.
- `errno` — OS error number when the underlying syscall failed, else `null`.
- `syscall` — for a request intercepted from a worker's syscall ([RFC 0004](0004-filesystem-interception.md)), that syscall: `open`, `openat`, or `openat2`. `null` otherwise. Added within v1.
- `notification` — for an intercepted request, its seccomp notification ID, which ties the event to one blocked syscall; a restarted syscall gets a new ID. `null` otherwise. Added within v1.
- `peer_uid` — for `connect`, and for `request` on a connection `Broker::serve_with` accepted, the peer's effective uid. `null` when it cannot be read, on a connection given to `Broker::serve_conn`, and for every other `op`. Added within v1 ([RFC 0011](0011-audit-broker-refusals.md)).

An intercepted request produces exactly one event, including when it is refused before any grant is matched: then `decision` is `deny`, `reason` is `unsupported_input` or `invalid_memory`, `grant` is `null`, and `path` is the requested path, or `null` when no valid path was copied. A refusal by the seccomp filter alone never reaches the supervisor and is not an event.

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

Signing or tamper-evidence of the log (the embedder's storage problem), rate limiting, and sampling. Nothing in the sink can veto or alter a decision; audit is observation only ([threat model](../threat-model.md#audit-is-observation-not-a-boundary)).
