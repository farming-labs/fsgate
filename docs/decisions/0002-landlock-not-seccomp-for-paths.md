# ADR 0002: Landlock, not seccomp, mediates filesystem paths

- Status: accepted
- Date: 2026-11-06
- Resolves the "seccomp filter scope" open question in RFC 0001.

## Context

RFC 0001 sketched `lock()` as Landlock plus a seccomp filter denying
path-taking syscalls. Implementing M2 showed the seccomp half of that
sketch does not hold:

- seccomp inspects register values only. It cannot read the path string an
  `open(2)` receives, cannot dereference `openat2(2)`'s `how` struct to see
  `RESOLVE_BENEATH`, and so cannot tell a gated open from an escape.
- Denying the `open`/`openat`/`openat2` family wholesale would also deny
  the gate's own opens — and those of every legitimate library in the
  process (dynamic loading, locale data, `/proc` introspection).

Landlock has neither problem: it is an LSM that mediates the *object* a
path resolves to, whatever syscall carried it, and the ruleset built from
the grants already states exactly what should remain reachable.

## Decision

Filesystem containment in `lock()` is Landlock alone. seccomp is not used
to filter path syscalls, and `seccompiler` (pinned in ADR 0001) is not a
dependency of M2. seccomp remains on the table for later milestones with a
different job: shrinking the non-filesystem syscall surface (for example
blocking `ptrace` or module loading) where register-level matching is the
right tool.

## Consequences

- On kernels without Landlock there is no partial path-filter fallback;
  `lock()` fails closed unless the caller opts into `BestEffort`. This is
  the behavior RFC 0001 already required.
- macOS containment relies entirely on the M3 broker, as planned.
- RFC 0001's containment section is amended to match this ADR.
