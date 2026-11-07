# RFC 0005: narrow a grant's rights in place

- Status: proposed
- Date: 2026-11-06
- Roadmap: [M7, after v0.1.0](../../ROADMAP.md#m7--grant-narrowing)
- Resolves: the attenuated-grant open question in [RFC 0001](0001-core-design.md#open-questions)

## Problem

A grant's rights are fixed when it is created, and the only way to give
up authority is `revoke`, which removes the whole grant. A process that
needs write access while it initializes (a migration, a cache warm-up, a
pid file) and only read access afterwards has two bad options:

- Revoke the grant and grant the directory again with fewer rights. That
  opens the directory by name a second time, so a rename or bind mount
  between the two calls changes what the grant reaches. After `lock()`,
  `grant` fails, so this option does not exist at all.
- Keep write access for the life of the process.

RFC 0001 deferred this as "whether `Grant` should be cloneable with
attenuated rights (`grant.narrow(Rights::READ)`)".

## Design

```rust
impl Gate {
    pub fn narrow(&mut self, grant: Grant, rights: Rights) -> Result<(), GateError>;
}
```

- `rights` is the complete set the grant keeps, not the set to drop, and
  it must be a subset of the rights the grant holds. A set that names a
  right the grant does not hold fails with `GateError::WouldWiden`, which
  names the extra rights and the held set; the grant is unchanged. This
  follows Capsicum's `cap_rights_limit(2)`, which refuses to expand
  rights instead of silently intersecting. A caller that asks to keep
  `WRITE` on a read-only grant has the wrong picture of its own
  authority and should hear about it.
- Narrowing to the rights already held is allowed and changes nothing.
  Narrowing to an empty set is allowed: the grant still routes the paths
  beneath it, and every operation there fails with `RightsExceeded`.
  `revoke` instead lets a covering parent grant take over those paths.
- The grant keeps its id, its held descriptor, and its routing position.
  Nothing re-resolves its path.
- Narrowing a revoked grant, or a grant from another gate, fails with
  `GateError::UnknownGrant`.
- `narrow` is allowed before and after `lock()`. It only removes
  authority, so it is not part of the granting phase that `lock()` ends.

### Kernel enforcement

- **Before `lock()`.** The Landlock ruleset is built from the live grants
  and their current rights, so a grant narrowed before the lock is
  enforced by the kernel at its narrowed rights.
- **After `lock()`.** The installed ruleset is fixed. Narrowing then
  binds every operation through this `Gate`, but code that bypasses the
  gate keeps what the ruleset allowed until the process exits. This is
  the same contract as `revoke` after a lock.
- **Nested grants.** Landlock allows an access when any rule on the path
  allows it. Narrowing a grant nested under a broader grant restricts
  gate operations routed to the nested grant, but the kernel still
  allows what the parent grant's rule allows. A nested grant created
  with fewer rights behaves the same way today; narrowing does not
  change that.

### Broker

`Broker::new` takes ownership of the gate, so a serving broker cannot
narrow, just as it cannot revoke. Narrow the gate before passing it to
`Broker::new`. Changing broker policy while it serves is out of scope.

### Audit

One event per decision ([RFC 0002](0002-audit-events.md)), with the new
op `narrow`:

| Outcome | `path` | `grant` | `decision` | `reason` |
|---|---|---|---|---|
| Narrowed | the grant's path | its id | `allow` | `ok` |
| Set names a right the grant lacks | the grant's path | its id | `deny` | `rights_exceeded` |
| Grant already revoked | `null` | the requested id | `deny` | `unknown_grant` |
| Grant from another gate | `null` | `null` | `deny` | `unknown_grant` |

Format v1 has no rights key, so the event records that a narrowing
happened, not the resulting set. `grant` events have the same gap.

### Compatibility

`AuditOp::Narrow` and `GateError::WouldWiden` are new variants of
enums that are not `#[non_exhaustive]`. Code that matches either enum
exhaustively must add an arm, so this is a breaking change: it ships in
0.2.0, not in a 0.1.x patch.

## Alternatives considered

- **`grant.narrow(Rights::READ) -> Grant`, an attenuated copy.**
  Rejected. A `Grant` is a handle for managing the gate's table, not a
  capability presented on each operation: `Gate::open` takes a path and
  routing picks the grant. A second, narrower entry for the same
  directory adds nothing to the gate's authority, and routing between
  duplicates picks the one granted last. Operations that take a grant
  token are a larger API change and would need their own RFC.
- **Silent intersection (`held & rights`).** Rejected. It never widens,
  but narrowing a write-only grant to `READ` would leave no rights, and
  the caller would find out only from later denials.
- **A drop set (`narrow(grant, Rights::WRITE)` removes `WRITE`).**
  Rejected. A kept set reads as the resulting policy at the call site,
  matches `grant(path, rights)`, and matches `cap_rights_limit(2)`.
- **Stacking another Landlock ruleset after `lock()`.** Rejected for
  now. Landlock allows a second, narrower layer, but
  `landlock_restrict_self(2)` restricts only the calling thread. Threads
  spawned after the first lock would keep the wider rules, so kernel
  enforcement would differ by thread. `revoke` has the same constraint.
- **Revoke and grant again.** Not possible after `lock()`, and before it
  the path is resolved by name a second time.

## Open questions

- Recording the resulting rights in `grant` and `narrow` audit events.
  A `rights` key would be additive within format v1.
- ~~`Grant` holds only an index, so a grant from one gate passed to
  another gate's `revoke` or `narrow` acts on whichever grant holds that
  index there.~~ Fixed: each `Grant` records the gate that created it, and
  any other gate rejects it with `UnknownGrant`.
