# Threat model

- Status: describes `main` at `f1468f2`, after [#36](https://github.com/farming-labs/fsgate/pull/36). Written from the code and the RFCs; not independently reviewed.
- Roadmap: [M9](../ROADMAP.md#m9--review-readiness-and-020)

fsgate is for a program that runs code it does not fully trust: a plugin, a parser fed hostile input, an agent's tool call, a dependency that may be compromised. The asset is every file the program was not granted. The attacker controls that code once it runs, including native code and raw syscalls. It wants to read, write, create, or list outside the grants, or to keep authority after a grant is narrowed or revoked.

The trusted side is everything that runs before the boundary: the code that calls `grant` and `lock`, the broker process, the launcher's supervisor, and the kernel.

**Each boundary below is a separate guarantee.** The gate alone is not a sandbox, and neither is the broker. The process is contained only after `lock()` on Linux, or when the embedder isolates a broker's worker.

## Reading the tables

Each section names one boundary, what it trusts, what it stops, and what it does not stop. Every row names the test that shows it, or says "none". A "none" row is a claim from the code or the kernel documentation that no fsgate test exercises.

Test names are `file::test`. Files are in `crates/fsgate/tests/` unless they start with `src/`, which marks a unit test. Linux tests run in CI on the runner's kernel (Linux 7.0) and on Linux 6.6.162 booted in a VM; the [roadmap](../ROADMAP.md) records the runs. Tests under `kernel::` re-execute the test binary as a separate locked child, so the lock does not reach the test harness.

## 1. The gate before `lock()`

`Gate` routes an absolute path to the longest covering grant, checks the grant's rights, and opens the rest of the path beneath the grant's held directory handle. On Linux that is `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` through cap-std; elsewhere, or where `openat2` is unavailable, cap-std walks the path one component at a time. Before `lock()` the process keeps its full ambient authority.

**Trusts:** every caller in the process. The gate constrains code that calls it. Code in the same address space can call `std::fs` directly, so the gate is not a boundary against hostile code until `lock()` ([RFC 0001](rfcs/0001-core-design.md#non-goals-v1)).

**Stops**, for operations through the gate:

| Attack | Outcome | Test |
|---|---|---|
| A path with no covering grant | `NoGrant` | `gate.rs::ungranted_path_is_no_grant` |
| `..` that climbs out of a grant | `NoGrant`, nothing opened | `gate.rs::dotdot_cannot_reroute_to_an_ungranted_directory` |
| A symlink inside a grant pointing outside it | Refused during resolution, by `openat2` on Linux | `gate.rs::symlink_to_an_outside_directory_cannot_escape`, `gate.rs::absolute_symlink_target_cannot_escape` |
| A relative path | `NotAbsolute` | `gate.rs::relative_paths_are_rejected` |
| An operation the grant's rights do not allow | `RightsExceeded`, no file created | `gate.rs::read_only_grant_rejects_create_and_leaves_no_file`, `gate.rs::denied_create_leaves_no_file_behind`, `gate.rs::list_requires_the_list_right` |
| Renaming the granted directory away and putting another in its place | The grant still reaches the directory it opened | `gate.rs::narrow_keeps_the_held_directory_instead_of_reopening_the_path` |
| Using a grant after `revoke` or `narrow` | Denied | `gate.rs::revoked_grant_stops_covering_its_paths`, `gate.rs::narrow_drops_rights_and_denied_writes_leave_files_unchanged`, `gate.rs::narrow_cannot_widen_even_back_to_the_original_rights` |
| Passing one gate's `Grant` to another gate | `UnknownGrant`, neither gate changes | `gate.rs::revoking_a_grant_from_another_gate_is_unknown_grant_and_changes_neither_gate`, `gate.rs::narrowing_a_grant_from_another_gate_is_unknown_grant_and_keeps_both_rights` |
| A magic link such as `/proc/self/fd/N` beneath a grant | Refused by `RESOLVE_NO_MAGICLINKS` | none |

**Does not stop:**

| Gap | Why | Test |
|---|---|---|
| Code that uses `std::fs`, libc, or raw syscalls | Nothing is enforced until `lock()` | none; by design |
| A hard link inside a grant to a file elsewhere | Resolution follows the directory tree, and a hard link is an ordinary entry in it. Landlock checks the same tree, so `lock()` does not stop it either. A locked process cannot create such a link itself, but one that exists, or that another process creates, is reachable. | none |
| A file system mounted beneath a grant | cap-std does not pass `RESOLVE_NO_XDEV`, so resolution crosses mount points beneath a grant, including mounts made after `grant()` | none |
| A symlink swapped in while a path resolves | Relies on `openat2` resolving in one call on Linux and on cap-std's component walk elsewhere | none; the symlink tests use static links |

## 2. The locked process (Linux)

`lock()` installs a Landlock ruleset built from the grants and bound to their held descriptors, not to path names. It restricts the calling thread and everything it starts afterwards, and on Linux 7.0 and later every thread of the process. A strict `lock()` needs Landlock ABI v3 (Linux 6.2) and fails without changing anything below it. The [RFC 0006](rfcs/0006-lock-restrictions.md) restrictions are added where the kernel provides them and reported by `Gate::restrictions()`.

**Trusts:** the kernel's Landlock implementation; the grant list; and everything that ran before `lock()`. Code that ran before the lock had full authority. Descriptors it opened, threads it started on older kernels, and connections it made all survive the lock.

**Stops:**

| Attack | Outcome | Test |
|---|---|---|
| A raw open outside the grants that bypasses the gate | `PermissionDenied` from the kernel | `lock.rs::kernel::kernel_blocks_filesystem_access_that_bypasses_the_gate` |
| A raw write or create outside the grants, or beneath a read-only grant | Denied, and no file is left behind | `lock.rs::kernel::kernel_blocks_filesystem_access_that_bypasses_the_gate` |
| A raw write beneath a grant narrowed before the lock | Denied, file unchanged | `lock.rs::kernel::kernel_enforces_rights_narrowed_before_the_lock` |
| A new grant after the lock | `GateError::Locked` | `lock.rs::best_effort_lock_ends_the_granting_phase` |
| An ioctl on a device beneath a grant without `WRITE` (Linux 6.10+) | `EACCES`; with `WRITE`, the device answers | `lock.rs::kernel::kernel_restricts_device_ioctls` |
| A connect to an abstract Unix socket outside the sandbox (6.12+) | `EPERM`, and the listener accepts nothing | `lock.rs::kernel::kernel_scopes_abstract_unix_sockets` |
| A signal to a process outside the sandbox (6.12+) | `EPERM`, and the target stays alive | `lock.rs::kernel::kernel_scopes_signals` |
| A thread started before the lock reading or writing outside the grants (7.0+) | `PermissionDenied`, and no file is created | `lock.rs::kernel::kernel_restricts_threads_that_predate_the_lock` |
| Requiring a restriction the kernel does not provide | `LockUnsupported` naming it; nothing is applied, so a raw read outside still succeeds and the gate stays unlocked | the four tests above on Linux 6.6; `src/containment.rs::a_missing_requirement_names_the_kernel_that_provides_it` |
| A strict lock without Landlock | `LockUnsupported`, and the granting phase continues | `lock.rs::strict_lock_fails_closed_without_kernel_support` (non-Linux only); none on a Linux kernel without Landlock |

**Does not stop:**

| Gap | Why | Test |
|---|---|---|
| Connects to pathname Unix sockets | fsgate does not request `ResolveUnix` (ABI v9, Linux 7.1) yet ([M8](../ROADMAP.md#m8--containment-beyond-file-paths-linux)) | none |
| Abstract socket connects and signals on kernels before 6.12, device ioctls before 6.10, or with the member left out through `LockOptions::restrict` | The kernel cannot restrict them, or the caller dropped them | The control mode of each test above shows the action succeeding, on Linux 7.0 with the member dropped and on Linux 6.6 |
| Threads that already exist at `lock()` on kernels before 7.0, or with `ALL_THREADS` left out | Landlock restricts only the calling thread there | `lock.rs::kernel::kernel_restricts_threads_that_predate_the_lock`, control mode: the earlier thread reads and writes outside the grants |
| An unconfined process acting for the locked one | Through a pathname socket, or an abstract socket or signal on older kernels, the locked process can ask another process to open files for it | none |
| Descriptors opened before the lock, or received over `SCM_RIGHTS` | Landlock does not apply to an open descriptor; it keeps the access it was opened with | none |
| `stat`, `access`, `chdir`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, and `fcntl` on paths outside the grants | Landlock cannot restrict these call families ([kernel documentation](https://docs.kernel.org/userspace-api/landlock.html)). A locked process can learn whether any path exists and read its metadata, and can change the mode, times, or extended attributes of files it owns outside the grants. | none |
| Narrowing or revoking after the lock | The installed ruleset never changes. Only operations through the gate see the change ([RFC 0005](rfcs/0005-grant-narrowing.md#kernel-enforcement)). | `lock.rs::kernel::kernel_enforces_rights_narrowed_before_the_lock` covers the gate side; none shows the raw access that remains |
| A nested grant with fewer rights than its parent | Landlock allows an access when any rule allows it, so the kernel enforces the parent's rights beneath the nested grant | none |
| `LockPolicy::BestEffort` on a kernel below ABI v3 | The caller asked for weaker rules; `LockStatus` reports `PartiallyEnforced` or `LibraryOnly` | `src/containment.rs::status_follows_the_filesystem_floor_alone` |
| Network, memory, environment, and syscalls that are not file operations | Out of scope ([README](../README.md#what-fsgate-does-not-do)) | none |

## 3. The broker and its worker

A trusted broker holds the `Gate` and serves `BrokerGate` requests over a Unix socket, returning opened files over `SCM_RIGHTS` ([RFC 0003](rfcs/0003-broker-protocol.md)). `fsgate-broker` binds a socket path, starts the command with `FSGATE_BROKER_SOCKET` set, and removes the socket when the command exits.

**Trusts:**

- The broker process and its gate.
- Every process that can connect to the socket. The broker does not check who connects, and `Broker::serve` accepts any number of connections. Whoever can connect has the grants.
- The embedder, to isolate the worker. The broker does not remove the worker's ambient filesystem authority. `fsgate-broker` starts the command as the same user, with the same environment and filesystem access as itself.

**Stops:**

| Attack | Outcome | Test |
|---|---|---|
| A request for an ungranted path, or beyond a grant's rights | The typed `GateError` crosses the wire; no side effect | `broker.rs::denials_cross_the_wire_typed_and_leave_no_side_effect` |
| A worker that tries to influence the decision | The request carries only an operation and a path; the broker's gate decides and audits | `audit.rs::broker_decisions_are_audited_server_side` |
| A worker that outlives its broker | Every later operation fails with `GateError::Broker`, with no reconnect | `broker.rs::dead_broker_fails_every_operation_closed`, `broker.rs::broker_binary_serves_and_dies_closed` |
| A delivered file leaking into programs the worker runs | Received descriptors are close-on-exec | `broker.rs::delivered_descriptors_do_not_leak_into_spawned_programs` |
| A frame over 1 MiB | The broker closes the connection | none ([M9](../ROADMAP.md#m9--review-readiness-and-020) fuzzing) |
| A malformed request or unknown operation | The broker closes the connection | none ([M9](../ROADMAP.md#m9--review-readiness-and-020) fuzzing) |
| A path or directory entry name that is not UTF-8 | Refused, never transcoded | none |
| Descriptors the worker attaches to a request | Closed without use | none |

**Does not stop:**

| Gap | Why | Test |
|---|---|---|
| Another process connecting to the socket | It gets the grants. `fsgate-broker` binds with the process umask and checks no peer credentials. | none |
| Many connections at once | Each one gets a thread and buffers up to about 1 MiB, with no limit on connections | none |
| A worker the embedder did not isolate | It can open files directly. As the same user, it can also signal the broker, or trace it where the system's ptrace policy allows. | none; the embedder's job |
| Files already delivered | They stay usable; the broker keeps no way to take them back | none |
| A fork and exec racing a receive on macOS | `FD_CLOEXEC` is set just after `recvmsg`, so a program started in that window inherits the descriptor ([RFC 0003](rfcs/0003-broker-protocol.md#framing)) | none |
| Changing policy while serving | `Broker::new` takes the gate, so a serving broker cannot revoke or narrow | none |

## 4. The experimental launcher (Linux x86_64)

Behind the `experimental-intercept` feature, `intercept::Launch` and `fsgate-broker --experimental-intercept` run a static binary and answer its `open`, `openat`, and `openat2` calls from the grants ([RFC 0004](rfcs/0004-filesystem-interception.md)). It is unreleased, unreviewed, and outside semver. RFC 0004's [syscall boundary and bypass analysis](rfcs/0004-filesystem-interception.md#syscall-boundary-and-bypass-analysis) is the full analysis; this section maps its routes to tests.

**Trusts:** the supervisor, which holds the grants and installs descriptors that Landlock does not check again; the kernel's seccomp user notifications and Landlock ABI v3; and the image check that runs before launch.

**Stops:**

| Route | Outcome | Test |
|---|---|---|
| An ungranted path | Denied and audited by the gate | `launch.rs::ungranted_path_is_denied_and_audited_by_the_gate` |
| Writes and creation | Refused; nothing changes | `launch.rs::write_and_create_requests_are_refused_and_change_nothing`, `launch.rs::unmediated_creat_is_refused_by_the_allowlist` |
| Relative and `..` paths | Refused before authorization | `launch.rs::relative_and_dot_dot_paths_are_refused_before_authorization` |
| A path rewritten in the worker's memory during its request | Never reaches an ungranted file | `launch.rs::a_path_rewritten_during_its_request_never_reaches_an_ungranted_file` |
| Symlinks, directories, FIFOs, devices, and procfs files | Refused, without blocking the supervisor | `launch.rs::symlinks_are_refused_with_eloop_even_inside_the_grant`, `launch.rs::directories_are_refused_with_eisdir`, `launch.rs::a_fifo_is_refused_without_blocking_the_supervisor`, `intercept.rs::devices_and_procfs_files_are_refused` |
| A file or symlink renamed over a checked path | Never opened or followed | `src/intercept/mod.rs::a_symlink_renamed_over_the_checked_path_is_never_followed`, `src/intercept/mod.rs::a_fifo_renamed_over_the_checked_path_is_never_opened` |
| The raw `open` syscall, forked children, and threads | Still mediated | `launch.rs::the_raw_open_syscall_is_mediated_too`, `launch.rs::forked_children_stay_mediated`, `launch.rs::threads_stay_mediated` |
| `execve`, `io_uring`, sockets, `prctl`, namespaces, and unlisted syscalls | Refused by the allowlist | `launch.rs::execve_io_uring_sockets_prctl_and_namespaces_are_refused`, `src/intercept/filters.rs::unlisted_syscalls_are_refused_and_clone3_is_enosys` |
| Calls from another syscall ABI | The process is killed | `src/intercept/filters.rs::non_native_calls_are_killed_by_both_filters` |
| Executing a delivered file or a path through the reserved descriptor | Refused | `launch.rs::a_delivered_file_moved_to_the_reserved_number_cannot_be_executed`, `launch.rs::an_absolute_path_cannot_be_executed_through_the_reserved_number` |
| Inherited descriptors | The worker starts with only stdio | `launch.rs::worker_starts_with_only_stdio_open` |
| Dynamic, script, and set-ID images | Refused before launch | `launch.rs::an_image_that_needs_an_interpreter_is_refused_before_launch`, `launch.rs::scripts_are_refused_before_launch`, `launch.rs::set_id_images_are_refused_before_launch` |
| A kernel without Landlock | Refused before the worker runs | `launch.rs::the_launcher_refuses_to_start_without_landlock`, `launch.rs::the_broker_refuses_to_start_without_landlock`, on Linux 6.6 booted with `lsm=capability` |
| A lost supervisor | Later opens fail with `ENOSYS` | `src/intercept/launch.rs::a_closed_listener_fails_later_opens_with_enosys` |
| A request interrupted after its decision | No descriptor reaches the worker | `src/intercept/launch.rs::an_interrupted_request_delivers_no_descriptor` |
| Opens after a revoke | Denied | `launch.rs::a_revoked_grant_denies_later_opens_but_delivered_files_stay_usable` |

**Does not stop:**

| Gap | Why | Test |
|---|---|---|
| Files delivered before a revoke | They stay usable | `launch.rs::a_revoked_grant_denies_later_opens_but_delivered_files_stay_usable` |
| Dynamic binaries, scripts, other architectures, and opens outside the read-only subset | Not mediated; refused instead | the refusal tests above |
| A compromised supervisor | It holds the grants | none; trusted by design |
| Kernels between 6.6 and the runner's, kernels without seccomp user notifications, and Landlock ABI below v3 | Untested ([M6](../ROADMAP.md#m6--linux-filesystem-interception-experimental)) | none |

## Audit is observation, not a boundary

- Every decision through a gate or a broker emits one event, including a denial the caller discards: `audit.rs::swallowed_denial_is_still_observed`. A kernel refusal after a policy allow is recorded with its errno: `audit.rs::kernel_refusal_is_allow_with_errno`.
- The kernel's refusals of raw syscalls in a locked process are not events, because fsgate never sees them. Only the launcher turns intercepted opens into events. Before `lock()`, code that bypasses the gate leaves no event at all.
- The sink is trusted embedder code that runs synchronously in the calling thread. A sink that blocks stalls the operation, and nothing in it can veto a decision ([RFC 0002](rfcs/0002-audit-events.md#delivery)).
- Events are not signed. Tamper evidence is the embedder's storage problem.

## Outside this model

- Attackers already privileged outside the sandbox (root, `CAP_SYS_ADMIN`), and bugs in the kernel.
- Memory-safety bugs in fsgate's dependencies: cap-std, rustix, `landlock`, and serde_json.
- Denial of service, beyond the broker rows above.
- Release integrity, covered by [the release procedure](RELEASING.md).
- Windows, network access, and macOS containment, which exists only through the broker.
