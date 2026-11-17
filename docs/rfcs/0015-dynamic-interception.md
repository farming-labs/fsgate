# RFC 0015: intercept dynamically linked programs

- Status: draft; runtime-grant policy awaits a maintainer decision
- Date: 2026-11-17
- Roadmap: [M11](../../ROADMAP.md#m11--interception-for-unmodified-programs)

## Problem and outcome

RFC 0004 refuses every executable with an ELF interpreter. Its static-binary
profile cannot launch an ordinary dynamically linked command such as
`/usr/bin/cat`, even when all requested data files have grants.

The next product milestone is a native Linux x86_64 program that uses the system
glibc loader, starts without linking fsgate, and reads explicitly granted files
through intercepted opens. The first compatibility targets are a dynamically
linked C fixture and unmodified `cat`, `wc`, and `sha256sum`, using absolute data
paths. These are acceptance targets, not claims about current support.

Relative data paths, directory enumeration, writes, scripts, Python/Node
runtimes, musl, other architectures, and arbitrary later execs remain separate
compatibility milestones. The existing static profile stays available.

## Evidence and implications

- ELF describes its interpreter in a `PT_INTERP` program header. That entry names
  a NUL-terminated pathname and may occur only once. The header also supplies
  program-table offsets and sizes. See the [ELF program-header specification](https://gabi.xinuos.com/elf/07-pheader.html) and [ELF header specification](https://gabi.xinuos.com/elf/02-eheader.html).
- Linux executes the interpreter while loading a dynamic ELF. Holding the main
  image descriptor does not, by itself, pin that interpreter's identity. See
  [execve](https://man7.org/linux/man-pages/man2/execve.2.html) and
  [execveat](https://man7.org/linux/man-pages/man2/execveat.2.html).
- The dynamic loader searches runtime paths, configuration/cache files, and
  library dependencies; its behavior can depend on embedded RPATH/RUNPATH and
  environment variables. See [ld.so](https://man7.org/linux/man-pages/man8/ld.so.8.html).
- Landlock constrains filesystem access; seccomp notifications transport the
  requests. Continuing an open after checking mutable arguments is still not an
  authorization mechanism. See [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
  and [seccomp notifications](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).

Design implication: allowing `PT_INTERP` in the existing parser is insufficient.
The loader needs its own execution rule, its file opens need an authority source,
and its metadata/runtime calls need measured compatibility.

## Runtime-grant decision

Two product choices are under consideration:

1. **Explicit runtime grants (recommended).** Callers name the runtime files and
   directories the program may read. Startup may require more configuration, but
   selecting a program does not silently authorize whole system directories.
2. **Automatic system runtime grants.** Reuse the ordinary broker's startup model
   and disclose the selected system directories and support files in the plan.
   Setup is shorter; every file covered by those runtime rules becomes readable
   to the worker, not just files the loader happens to need.

The choice is unresolved. No public option name or automatic path list is settled
in this draft. The image parser can be implemented before that decision; dynamic
execution cannot.

Under either choice, runtime access must be visible in the CLI plan and in audit
records. A runtime rule must not override a narrower data policy. Reject overlap
with data grants using held-object checks, following the existing broker's
approach. Grant lifecycle and audit attribution must be specified before wiring
runtime opens: a caller must know whether a runtime rule is revocable and which
future opens a change affects. Already delivered descriptors remain usable.

## Proposed implementation order

### 1. Inspect the held image

Extract ELF inspection from `Launch::check` into a private parser shared by the
launcher and its tests. It identifies native static and dynamic ELF images and
returns the interpreter path as bytes through `PathBuf`, without executing the
image or invoking `ldd`.

Keep the existing 64-bit little-endian x86_64, executable/static-PIE, and bounded
program-table requirements. Check versions, table ranges and interpreter ranges
without integer overflow. Refuse duplicate interpreters, invalid lengths,
missing or embedded NULs, and non-absolute interpreter paths. Preserve non-UTF-8
path bytes rather than converting them lossily.

This parser is not a complete ELF loader or proof that an image will run. File
kind, set-ID bits, and file-capability checks stay on the held descriptor in the
launcher. A held descriptor pins the file identity, not immutable file contents.
Dynamic images remain refused after inspection until later stages are complete.

### 2. Prepare runtime authority and pin the loader

Resolve and hold the allowed loader before launch, validate it as a supported
regular native ELF without privilege-changing attributes, and give it only the
execution/read authority needed for startup. Execute the already held main image.
A replaced interpreter path must either reach the allowed held object or fail
before target code runs. Never broaden a rule in response to a loader failure.

Runtime-file resolution must preserve a held-directory boundary. Common library
symlinks and `/lib` versus `/usr/lib` aliases need explicit resolver rules and
real distro fixtures; an ambient `canonicalize` followed by an unrelated open is
not sufficient. Keep the data-grant resolver's existing contract separate from
any newly specified runtime symlink behavior.

### 3. Add measured syscall compatibility

Trace disposable dynamically linked fixtures on the declared Linux kernels to
identify startup and command requirements. Compare those traces with the existing
allowlist, then add only the required semantics with focused fixtures.

In particular, inspect descriptor metadata (`newfstatat`/`statx` versus `fstat`),
loader path probes, and resource-limit queries. Path metadata cannot become an
unrestricted allowlist entry: Landlock is not a pathname-metadata filter. A
notification handler must use copied arguments and never continue a checked
pathname syscall. Any worker-memory writes require their own isolated contract,
including partial writes, cancellation, identity, and invalid addresses.

The program starts with the existing empty environment. Do not inherit
`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, or other host configuration as an
implicit compatibility fix. Embedded RPATH/RUNPATH and loader cache lookups still
have to obey the selected runtime grants.

### 4. Expose and verify the complete profile

Extend `Launch` and CLI plan/apply together after the runtime policy is settled.
The plan names the image, interpreter, runtime authority, data grants, and
unsupported operations. Missing support prevents launch. Failure never retries
the program unconfined.

Use the existing supervisor lifetime, cancellation, grant-revocation, and
atomic descriptor-delivery mechanisms. Runtime support must preserve them.

## Acceptance criteria

- The dynamic fixture and unmodified `cat`, `wc`, and `sha256sum` produce exact
  expected output for granted files through both `Launch` and the built CLI.
- Test the release build from the unpacked crate with the repository-only feature
  enabled by the same explicit CI mechanism as the existing interception tests.
  The feature remains unavailable in the published crate.
- Read outside a grant, write/create attempts, missing runtime grants, malformed
  images, and interpreter/library replacement fail as specified, with no denied
  write or creation side effect and no unconfined retry.
- Audit records distinguish runtime and data decisions without losing syscall
  attribution. Revocation, cancellation, supervisor loss, and descriptor cleanup
  retain their existing tested behavior.
- Run the existing static suite unchanged, the dynamic compatibility cases on
  Linux 6.6 and the current CI kernel, and an explicit unsupported-host case.
  Record glibc, command versions, kernel versions, and skips separately.

## Alternatives and rollout

Running the dynamic loader explicitly as the selected executable changes argv,
program discovery, and startup semantics; it is a useful diagnostic but does not
satisfy native dynamic launch. A preload shim misses direct syscalls and is not
this milestone. Granting all of `/` to make the loader work defeats the product's
scope. A broad new syscall allowlist without compatibility fixtures is also
outside this proposal.

Land this work in focused increments: image inspection, the settled runtime
policy and resolver, measured syscall compatibility, then public launcher/CLI
support and the program matrix. Keep roadmap tasks unchecked until their own
acceptance criteria and merge evidence exist. None of these steps constitutes an
independent review or a release.

## Implementation status

The private image inspector is implemented locally with eight passing focused
host tests, also passing from the unpacked crate in release mode. All 145 host
tests pass. Host and Linux x86_64 interception clippy checks pass. The launcher
still refuses dynamic images after inspection. Linux execution of this change,
the runtime policy, and the remaining dynamic profile are not verified or complete.

## Open questions

- Which runtime-grant policy should the product use: explicit or automatic?
- After measuring Linux fixtures, which exact metadata and runtime syscall forms
  are required by the initial glibc target? This is an implementation experiment,
  not permission to allow all path queries.
