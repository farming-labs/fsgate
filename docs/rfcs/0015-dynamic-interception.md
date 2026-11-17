# RFC 0015: intercept dynamically linked programs

- Status: implemented locally; CI and merge pending; explicit runtime grants selected by the maintainer
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

The maintainer selected **explicit runtime grants**. No system directory is
added automatically. `Launch::runtime(path)` and repeated CLI `--runtime <path>`
declare absolute file or directory paths for read-only runtime use. An empty list
keeps the existing static profile. A dynamic image without an explicitly covered
interpreter fails before execution.

A runtime directory reuses `Gate`'s held directory and grant routing. Runtime
opens use `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` followed by the existing
regular-file check and descriptor reopen. Relative symlinks may resolve beneath
that directory; absolute links and links leaving it fail. Explicit file grants
pin one regular file at setup, including a caller-selected symlink target, and
reopen that same object for each request with an independent file offset. They
are useful for the interpreter and loader cache without granting their parents.
No library discovery command or `ldd` executes the selected image.

Setup rejects runtime/data overlap by logical path and by held-directory
ancestry. For a file grant, its resolved parent is checked against the pinned
file identity before comparing ancestry. As with existing grants, keep the
configuration stable during setup; hard-link aliases and later mount/rename
changes are not a general inode-containment proof. The held descriptors remain
the authority for every allowed open.

`Running::revoke_runtime(path)` removes one declared runtime grant and closes its
held descriptor. Other explicitly overlapping runtime grants may still cover
the path. Revocation is serialized with request delivery, as data-grant changes
are. Already delivered descriptors, loaded mappings, and the loader's installed
bootstrap execution rule are not withdrawn. Runtime grants are read-only, so
there is no narrower nonempty right set. Runtime grant, open, and revoke events
use distinct operation names in the existing audit stream.

The first runtime-enabled profile supports one worker process with one thread.
It denies `fork`, `vfork`, `clone`, and `clone3`. This bounds the identity used by
metadata-result writes: only the owned worker PID is accepted, and the launcher
joins its supervisor before reaping that child, including during drop and error
cleanup. Startup requires the parent to retain children (`SIGCHLD` at its default
disposition, without `SA_NOCLDWAIT`). The trusted embedder must not independently
reap this owned child or change that signal policy while it is running.

`newfstatat` is mediated for held descriptors (`""` with `AT_EMPTY_PATH`) and
canonical absolute regular-file paths authorized by a READ grant. The latter is
required by measured GNU wc 9.7 behavior: it reads the input size before opening
it to choose output column widths. Refusing that granted metadata changed output
spacing despite correct counts. Path requests reuse the same strict data/runtime
resolver as opens and perform the metadata copy while the authority lock is held;
no pathname syscall is continued. Relative paths, directories, special files, and
ungranted paths remain refused. The
supervisor pins the target descriptor through procfs, obtains its metadata, and
copies a fully initialized native result with `process_vm_writev`. That syscall
respects the worker's writable mappings; `/proc/pid/mem` writes are not used.
Notification IDs are checked around copying and completion. Partial writes or
bad destinations fail explicitly and are not reported as successful metadata
reads. Cancellation may leave bytes already copied into the worker, as for other
non-atomic kernel copies; it never permits a write to a recycled PID. See
[process_vm_writev](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
and [child waitability](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).

The initial profile reports `ENOSYS` for `statx`, allowing libc's older-syscall
fallback to reach the mediated `newfstatat`; metadata outside READ grants stays refused.
`prlimit64` may only query the calling process, with no new limit supplied.
The static profile keeps its existing thread and syscall behavior. These
runtime-enabled restrictions and their compatibility limits appear in the plan
and public documentation; they are not a claim of support for arbitrary programs.

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

- After measuring Linux fixtures, which exact metadata and runtime syscall forms
  are required by the initial glibc target? This is an implementation experiment,
  not permission to allow all path queries.

## Local verification

On 2026-11-17, the packaged source was extracted outside the repository and built
with `--release --locked --offline --features experimental-intercept`, targeting
`x86_64-unknown-linux-musl` and explicitly setting
`RUSTFLAGS='--cfg fsgate_repository_build'`, as required for repository tests of
the otherwise unavailable published feature. The launcher test host uses musl;
the worker compatibility targets use glibc.

The test VM runs Linux 6.18.60-0-virt from Alpine 3.24.4, under QEMU TCG on an
Apple arm64 host. Its glibc worker environment uses the official Debian packages
`libc6`/`libc6-dev` 2.41-12+deb13u5, coreutils 9.7-3, libssl3t64
3.5.9-1~deb13u1, zlib1g 1.3.dfsg+really1.3.1-1+deb13u1, and libzstd1
1.5.7+dfsg-1. GCC 15.2.0 builds the C fixtures against an isolated glibc sysroot.
This is a mixed test environment, not evidence for a full Debian installation or
musl-linked workers. No package install scripts run for the Debian files.

Results from the unpacked crate: 44 library unit tests, 12 interception tests,
30 static-launch tests, and eight dynamic-launch tests pass. Two tests requiring
a kernel without Landlock remain explicitly ignored. The dynamic cases cover
normal commands through API and CLI, exact output, metadata identity and invalid/
read-only/partial destinations, denied paths and write side effects, runtime
revocation with delivered descriptors retained, refused descendants, parent
SIGCHLD policy, and drop/reap cleanup. The unit tests also replace the interpreter
after its held Landlock rule is built and require `EACCES` before execution.

GNU wc's output-comparison test initially failed because pathname metadata was
refused. Its trace showed a size query before the data open; granting metadata
through the same READ resolver made that unchanged output comparison pass.

Host `cargo test --locked` passes 146 tests; host and Linux x86_64 feature clippy,
formatting, and the CLI argument fuzz target's compile check pass. A fuzz run,
new-profile execution on Linux 6.6 and the current CI kernel, execution without
Landlock, a glibc-linked supervisor, and independent review have not been run for
this change. Existing static cancellation tests pass, as does a deterministic
metadata cancellation test that requires `EINTR` and an untouched result buffer.
The feature remains experimental and unpublished.
