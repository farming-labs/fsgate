# Working on fsgate

fsgate is a Rust library (plus a planned broker binary) that scopes a process's filesystem authority to directories granted up front, enforced by the kernel. The repository is in the design/scaffold phase.

## Read first

`README.md`, `ROADMAP.md`, and the RFCs in `docs/rfcs/` before changing design or code. `ROADMAP.md` owns task status.

## Contract

- Fail closed. No silent fallback to ambient filesystem access, ever. Invalid input errors with the fix in the message.
- Enforcement lives at the kernel or the held descriptor, never in a string comparison. Prefix matching is routing, not security.
- Every grant has a reverse (`revoke`); `lock()` is the one documented irreversible operation.
- No new `unsafe` without an isolated module and a written safety contract. `unsafe_code` is denied by default in the crate.
- Keep prototype, implemented, tested, reviewed, and released claims distinct. The README's status section must stay honest.

## Verification

- Bug fixes come with a regression test that failed before the fix.
- Security-relevant tests assert the denied operation *and* the absence of the side effect, against the real filesystem — not a mock of the authorization decision.
- Run before any commit: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --locked`.

## Git

- Conventional commits: `type(scope): lowercase imperative description`. Branches: `<type>/<kebab-topic>`.
- One concern per PR. Squash merges, maintainer-initiated only.
- No assistant or vendor names in branches, PR titles, labels, descriptions, commit messages, or trailers (no `Co-Authored-By` bot lines).
- Never hand-edit versions or tags; releases are explicit maintainer actions with signed tags.
