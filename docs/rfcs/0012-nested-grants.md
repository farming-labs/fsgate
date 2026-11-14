# RFC 0012: refuse a nested grant with fewer rights

- Status: accepted
- Date: 2026-11-14
- Roadmap: [M9](../../ROADMAP.md#m9--review-readiness-and-020)
- Builds on: [RFC 0001](0001-core-design.md#resolution) (routing), [RFC 0005](0005-grant-narrowing.md) (narrowing)
- Revisits: RFC 0005's note on nested grants

## Problem

A gate routes a path to the longest grant whose path contains it, then
opens the rest beneath that grant's held directory. Grants may nest, and
until now a nested grant could hold fewer rights than the grant around
it. Take a common policy: the project read-write, its `.git` read-only,
so that nothing can plant a git hook.

```rust
gate.grant("/proj", Rights::READ | Rights::WRITE | Rights::CREATE)?;
gate.grant("/proj/.git", Rights::READ)?;
gate.create("/proj/.git/hooks/pre-commit")?; // RightsExceeded, as intended
gate.create("/proj/link/hooks/pre-commit")?; // succeeds
```

`/proj/link` is a symlink to `.git`. The second request routes to `/proj`,
whose rights allow it, and the symlink stays beneath `/proj`'s handle, so
the open lands in `.git`. On a case-insensitive filesystem, as macOS uses
by default, `/proj/.GIT/hooks/pre-commit` does the same with no symlink.
Anyone who can create a symlink in `/proj`, including a worker served by a
`Broker`, can write into `.git`.

The kernel cannot hold the smaller set either. Landlock allows an access
when any rule allows it, so after `lock()` `/proj`'s rule already allows
writes beneath `.git`. RFC 0005 recorded that, and the threat model listed
it as a gap of the lock alone. The internal review at `ea159a6` found that
the gate is bypassed too.

RFC 0001 says routing "is routing, not security. If it routes to the
wrong grant, the worst outcome is an operation under a directory that was
still deliberately granted." With a nested grant holding fewer rights,
the worst outcome was an operation the policy meant to refuse.

## Goals

- No policy the gate accepts promises rights that a symlink, another
  spelling of a path, or the kernel can get around.
- A refused policy fails before any grant changes, with an error that
  names both grants and how to fix it.
- Nesting is read from the directories, not their names, so a grant named
  through a symlink or in another case is caught.

## Non-goals

- Catching a directory that reaches another grant through a bind mount,
  or one moved into another grant after both were made. Grants record
  where their directories are when they are made.
- Enforcing a nested grant's lesser rights. That needs routing by the
  object a path reaches, which RFC 0001 leaves to the kernel and which
  Landlock does not offer.

## Design

Two grants **nest** when one's directory is the same as the other's or
beneath it. Of a nesting pair, the **inner** grant must hold every right
the **outer** one holds. `Gate::grant` and `Gate::narrow` refuse a change
that breaks this with a new error:

```rust
GateError::NestedGrant {
    inner_path: PathBuf,
    inner: Rights,
    outer_path: PathBuf,
    outer: Rights,
}
```

```text
grant for `/proj/.git` would hold READ within the grant for `/proj`, which
holds READ | WRITE | CREATE; a grant within another must hold every right
the other holds, so give the inner grant more rights or the outer grant
fewer
```

- **`grant`** opens the directory, then checks it against every live
  grant, in the order they were made. It refuses when a grant on the same
  directory or above it holds a right the new one lacks, or when a grant
  on the same directory or beneath it lacks a right the new one holds. So
  the inner grant can come first or second.
- **`narrow`** checks after its existing widening check. It refuses when a
  live grant on the same directory or above it holds a right the narrowed
  set lacks. Narrowing an outer grant never breaks the rule.
- **The same directory twice** must hold the same rights under every name.
  An identical second grant is still accepted.
- **`revoke`** is unchanged. Revoking the outer grant ends the nesting, so
  the inner grant can then be made with fewer rights.

The rule holds after `lock()` too, for `narrow`.

### Reading nesting from the directories

When a grant is made, fsgate records the device and inode numbers of its
directory and of each directory above it, read with `fstatat` on `..`,
`../..`, and so on from the held descriptor until the root, which is its
own `..`. Two grants nest when one's directory is in the other's list.
A symlink in the granted path, or another case on a case-insensitive
filesystem, gives the same list.

`..` at the root of a mount leads to the directory it is mounted on. So a
bind mount of `/proj/.git` at `/mnt/git` lists `/mnt` and `/`, not
`/proj`, and is not caught. A walk deeper than the platform's path limit
fails with `ENAMETOOLONG`, and the grant fails with it.

### Audit

One event per decision ([RFC 0002](0002-audit-events.md)), with the new
reason `nested_grant`:

| Outcome | `path` | `grant` | `rights` | `decision` | `reason` |
|---|---|---|---|---|---|
| Grant refused | the normalized requested path | `null` | `null` | `deny` | `nested_grant` |
| Narrow refused | the grant's path | its id | the unchanged set | `deny` | `nested_grant` |

`AuditReason::NestedGrant` and `GateError::NestedGrant` are new variants of
`#[non_exhaustive]` enums.

### Compatibility

A policy that nests a grant with fewer rights now fails to build. That
breaks callers, so it ships in 0.5.0. `fsgate-broker` refuses such
`--grant` flags at startup with the same message. To keep a part of a
granted directory read-only, grant its siblings instead of the parent, or
grant the parent read-only and the writable parts beneath it.

## What this does not stop

- A directory reached through a bind mount, or moved into another grant
  after both were made.
- A hard link to a file in an inner grant, made inside the outer grant.
  It is a file in the outer grant, with the outer grant's rights.
- Through a symlink that stays in a grant, a path can reach a nested
  grant's directory, which now always holds at least the outer grant's
  rights. The gate gives the outer grant's rights, and the kernel the
  union of the rules, so only the gate refuses there. The threat model
  lists it.

## Testing

- `gate.rs`: a nested grant with fewer rights is refused, whether it
  comes first or second, named through a symlink, or spelled in another
  case on a case-insensitive filesystem. A second grant on the same
  directory needs the same rights. Refused, the gate is unchanged, and
  revoking the outer grant allows the inner one. Narrowing a nested grant
  below the grant around it is refused and keeps its rights; narrowing the
  outer grant is allowed.
- `audit.rs`: each refusal is one `deny` event with `nested_grant`.
- `gate_model.rs`: the model predicts each refusal, with both grants'
  paths and rights, for generated grants and narrows. The kernel test's
  nested-grant gap is now the symlink case above.
- The `gate_paths` fuzz target's nested grant holds the rights of the
  grant around it.

## Alternatives considered

- **Document nested rights as routing only.** No caller breaks, but the
  gate keeps accepting a policy it cannot hold, and fsgate fails closed
  elsewhere. Rejected by the maintainer.
- **Compare paths.** A string or canonical-path comparison misses another
  case on a case-insensitive filesystem, and canonicalizing reads the path
  again, apart from the descriptor the grant holds.
- **Route by the object a path reaches.** Resolve the path first, then pick
  the grant whose directory contains the result. That is a new resolver,
  and the kernel still allows what the outer rule allows after `lock()`.

## Decisions

1. Refuse, in 0.5.0 (maintainer, 2026-11-14).
