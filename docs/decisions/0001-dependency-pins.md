# ADR 0001: dependency pins for v1

- Status: accepted
- Date: 2026-11-06

## Decisions

- **Resolver: `cap-std` 4.0.3.** It is the maintained, WASI-adjacent implementation of beneath-handle path resolution (`openat2` + `RESOLVE_BENEATH` on Linux, careful component walk elsewhere). Rejected: forking its resolver (we'd own symlink-race correctness forever) and hand-rolling with raw `rustix` (same problem, fewer reviewers).
- **Errors: `thiserror` 2.0.21.** Library-side error derive per house rules; `anyhow` stays out of the library entirely.
- **Landlock (M2): the `landlock` crate** (maintained by the Landlock kernel developers). Rejected: raw `rustix`/libc syscall wrappers — the ruleset/ABI-versioning logic is exactly what the crate encodes.
- **seccomp (M2): `seccompiler`.** Pure-Rust filter compiler with no libseccomp C dependency, which keeps the build hermetic and cross-compilable. Rejected: `libseccomp` bindings (system library dependency, version skew across distros). Revisit only if `seccompiler`'s filter expressiveness proves insufficient for the M2 syscall list. *Superseded in part by [ADR 0002](0002-landlock-not-seccomp-for-paths.md): seccomp left M2 entirely; the `seccompiler` pick stands for whenever seccomp returns with a non-path job.*
- **Tests: `tempfile` 3.27.0** (dev-dependency only).
- **MSRV: 1.85**, the edition 2024 floor. Raising it later is a minor-version event, not a patch.

M2 crates are decided here but added to `Cargo.toml` only when M2 starts; no dependency ships before the code that uses it.

## Consequences

`cap-std` types appear in the public API (`Metadata`, `ReadDir` re-exports), so a cap-std major bump is a breaking change for fsgate. Accepted: wrapping them would add a conversion layer with no security value.
