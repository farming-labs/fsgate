# Threat model

- Status: written against `main` at `f1468f2`, after [#36](https://github.com/farming-labs/fsgate/pull/36), and updated with later changes. Written from the code and the RFCs; not independently reviewed.
- Roadmap: [M9](../ROADMAP.md#m9--review-readiness-and-020)

fsgate is for a program that runs code it does not fully trust: a plugin, a parser fed hostile input, an agent's tool call, a dependency that may be compromised. The asset is every file the program was not granted. The attacker controls that code once it runs, including native code and raw syscalls. It wants to read, write, create, or list outside the grants, or to keep authority after a grant is narrowed or revoked.

The trusted side is everything that runs before the boundary: the code that calls `grant` and `lock`, the broker process, the launcher's supervisor, and the kernel.

**Each boundary below is a separate guarantee.** The gate alone is not a sandbox, and neither is the broker. The process is contained only after `lock()` on Linux, when `fsgate-broker` confines its worker on Linux, or when the embedder isolates a worker it serves.

## Reading the tables

Each section names one boundary, what it trusts, what it stops, and what it does not stop. Every row names the test that shows it, or says "none". A "none" row is a claim from the code or the kernel documentation that no fsgate test exercises.

Test names are `file::test`. Files are in `crates/fsgate/tests/` unless they start with `src/`, which marks a unit test. Linux tests run in CI on the runner's kernel (Linux 7.0), on x86_64 and arm64, and on Linux 6.6.162, 6.12.117, and 7.3.3, each booted in a VM on x86_64. Linux 6.1.192, whose Landlock is below fsgate's floor, runs only the tests that show it failing closed. The [roadmap](../ROADMAP.md) records the runs. Tests under `kernel::` re-execute the test binary as a separate locked child, so the lock does not reach the test harness.

## 1. The gate before `lock()`

`Gate` routes an absolute path to the longest covering grant, checks the grant's rights, and opens the rest of the path beneath the grant's held directory handle. On Linux that is `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` through cap-std; elsewhere, or where `openat2` is unavailable, cap-std walks the path one component at a time. Before `lock()` the process keeps its full ambient authority.

**Trusts:** every caller in the process. The gate constrains code that calls it. Code in the same address space can call `std::fs` directly, so the gate is not a boundary against hostile code until `lock()` ([RFC 0001](rfcs/0001-core-design.md#non-goals-v1)).

**Stops**, for operations through the gate:

| Attack | Outcome | Test |
|---|---|---|
| A path with no covering grant | `NoGrant` | `gate.rs::ungranted_path_is_no_grant` |
| `..` that climbs out of a grant | `NoGrant`, nothing opened | `gate.rs::dotdot_cannot_reroute_to_an_ungranted_directory` |
| A symlink inside a grant pointing outside it | Refused during resolution with `EXDEV`, by `openat2` on Linux and by cap-std's component walk elsewhere, and audited as `allow` with that errno | `gate.rs::symlink_to_an_outside_directory_cannot_escape`, `gate.rs::absolute_symlink_target_cannot_escape`, `audit.rs::an_escape_is_audited_with_its_errno` |
| A relative path | `NotAbsolute` | `gate.rs::relative_paths_are_rejected` |
| An operation the grant's rights do not allow | `RightsExceeded`, no file created | `gate.rs::read_only_grant_rejects_create_and_leaves_no_file`, `gate.rs::denied_create_leaves_no_file_behind`, `gate.rs::list_requires_the_list_right` |
| Renaming the granted directory away and putting another in its place | The grant still reaches the directory it opened | `gate.rs::narrow_keeps_the_held_directory_instead_of_reopening_the_path` |
| Opening a directory through `open` | `EISDIR`, checked on the opened descriptor, so listing still needs `LIST` | `gate.rs::open_refuses_a_directory` |
| A FIFO beneath a grant, with nothing on its other end | `open` returns it without waiting for a writer, and `create` fails with `ENXIO` while it has no reader, so neither holds the caller or a broker's serve thread | `gate.rs::a_fifo_does_not_block_open_or_create` |
| Using a grant after `revoke` or `narrow` | Denied | `gate.rs::revoked_grant_stops_covering_its_paths`, `gate.rs::narrow_drops_rights_and_denied_writes_leave_files_unchanged`, `gate.rs::narrow_cannot_widen_even_back_to_the_original_rights` |
| Passing one gate's `Grant` to another gate | `UnknownGrant`, neither gate changes | `gate.rs::revoking_a_grant_from_another_gate_is_unknown_grant_and_changes_neither_gate`, `gate.rs::narrowing_a_grant_from_another_gate_is_unknown_grant_and_keeps_both_rights` |
| A magic link such as `/proc/self/fd/N` beneath a grant | Refused by `RESOLVE_NO_MAGICLINKS` with `ELOOP` | `gate.rs::a_magic_link_beneath_a_grant_is_refused` (Linux only) |
| Arbitrary paths beneath nested grants, through symlinks that stay inside, climb out, are absolute, dangle, or loop | In the recorded fuzzing runs on macOS and Linux, no success reached an object outside the grant the path routes to, no refusal differed from the one the routing calls for, and nothing changed but the file a `create` returned | the [`gate_paths` fuzz target](../fuzz/README.md), not a test; runs recorded in [M10](../ROADMAP.md#m10--battle-tested-tests) |

Beyond these chosen cases, `gate_model.rs::the_gate_matches_the_model_and_never_leaves_its_grants` runs generated trees and requests through the gate on Linux and macOS. It checks each answer and audit event against a reference model of the resolution above, that a success stays beneath its grant by inode, and that a failure changes nothing. It can show a defect, not prove there is none.

**Does not stop:**

| Gap | Why | Test |
|---|---|---|
| Code that uses `std::fs`, libc, or raw syscalls | Nothing is enforced until `lock()` | none; by design |
| A hard link inside a grant to a file elsewhere | Resolution follows the directory tree, and a hard link is an ordinary entry in it. Landlock checks the same tree, so `lock()` does not stop it either. A locked process cannot create such a link itself, but one that exists, or that another process creates, is reachable. | `gate.rs::a_hard_link_beneath_a_grant_reaches_the_file_elsewhere`, `lock.rs::kernel::a_locked_process_keeps_hard_links_but_cannot_make_them` |
| A file system mounted beneath a grant | cap-std does not pass `RESOLVE_NO_XDEV`, so resolution crosses mount points beneath a grant, including mounts made after `grant()` | none; mounting needs privileges the tests do not have |
| A symlink swapped in while a path resolves | Relies on `openat2` resolving in one call on Linux and on cap-std's component walk elsewhere. cap-std also falls back to the walk on Linux when `openat2` keeps failing with `EAGAIN`, which a rename anywhere on the host can cause. On ext4 CI runners, a symlink being replaced made `openat2` return the link's parent directory, which is beneath the grant, and `open` refuses that with `EISDIR`. | `gate.rs::a_symlink_swapped_during_resolution_never_reaches_outside`, a stress test on Linux and macOS that could show an escape but cannot rule one out |

## 2. The locked process (Linux)

`lock()` installs a Landlock ruleset built from the grants and bound to their held descriptors, not to path names. It restricts the calling thread and everything it starts afterwards, and on Linux 7.0 and later every thread of the process. A strict `lock()` needs Landlock ABI v3 (Linux 6.2) and fails without changing anything below it. The [RFC 0006](rfcs/0006-lock-restrictions.md) restrictions are added where the kernel provides them and reported by `Gate::restrictions()`.

**Trusts:** the kernel's Landlock implementation; the grant list; and everything that ran before `lock()`. Code that ran before the lock had full authority. Descriptors it opened, threads it started on older kernels, and connections it made all survive the lock.

**Stops:**

| Attack | Outcome | Test |
|---|---|---|
| A raw open outside the grants that bypasses the gate | `PermissionDenied` from the kernel | `lock.rs::kernel::kernel_blocks_filesystem_access_that_bypasses_the_gate` |
| A raw write or create outside the grants, or beneath a read-only grant | Denied, and no file is left behind | `lock.rs::kernel::kernel_blocks_filesystem_access_that_bypasses_the_gate` |
| A raw open, create, or listing, by any route through generated trees of symlinks, `.`, and `..`, of an object no grant at `lock()` gives the right it needs | Refused by the kernel, and the tree is unchanged | `gate_model.rs::kernel::raw_calls_differ_from_the_gate_only_where_documented` |
| A raw write beneath a grant narrowed before the lock | Denied, file unchanged | `lock.rs::kernel::kernel_enforces_rights_narrowed_before_the_lock` |
| A raw read beneath a grant that holds no rights | Denied: the grant adds no rule, and the lock still succeeds | `lock.rs::kernel::a_grant_with_no_rights_locks_and_reaches_nothing` |
| A new grant after the lock | `GateError::Locked` | `lock.rs::best_effort_lock_ends_the_granting_phase` |
| An ioctl on a device beneath a grant without `WRITE` (Linux 6.10+) | `EACCES`; with `WRITE`, the device answers | `lock.rs::kernel::kernel_restricts_device_ioctls` |
| A connect to an abstract Unix socket outside the sandbox (6.12+) | `EPERM`, and the listener accepts nothing | `lock.rs::kernel::kernel_scopes_abstract_unix_sockets` |
| A connect or datagram to a pathname Unix socket created outside the sandbox (7.1+), even beneath a grant holding every right | `EACCES`, the listener accepts nothing, and a connection made before the lock keeps working | `lock.rs::kernel::kernel_restricts_pathname_unix_sockets`, `lock.rs::kernel::a_worker_keeps_the_broker_it_connected_to_before_locking` |
| A signal to a process outside the sandbox (6.12+) | `EPERM`, and the target stays alive | `lock.rs::kernel::kernel_scopes_signals` |
| A thread started before the lock reading or writing outside the grants (7.0+) | `PermissionDenied`, and no file is created | `lock.rs::kernel::kernel_restricts_threads_that_predate_the_lock` |
| Requiring a restriction the kernel does not provide | `LockUnsupported` naming it; nothing is applied, so a raw read outside still succeeds and the gate stays unlocked | the restriction tests above on a kernel without each one (Linux 6.6, and the runner's for `RESOLVE_UNIX`); `src/containment.rs::a_missing_requirement_names_the_kernel_that_provides_it` |
| A strict lock without Landlock | `LockUnsupported`, and the granting phase continues | `lock.rs::strict_lock_fails_closed_without_kernel_support` (non-Linux), `lock.rs::without_landlock::strict_lock_fails_closed` (Linux booted without Landlock) |
| A strict lock on a kernel below Landlock ABI v3 | `LockUnsupported`; nothing is applied, so a raw read outside still succeeds, and the granting phase continues | `lock.rs::kernel::below_landlock_v3::strict_lock_fails_closed` (Linux 6.1, ABI v2) |

**Does not stop:**

| Gap | Why | Test |
|---|---|---|
| Pathname socket connects on kernels before 7.1, abstract socket connects and signals before 6.12, device ioctls before 6.10, or any of these with the member left out through `LockOptions::restrict` | The kernel cannot restrict them, or the caller dropped them | The control and `unsupported` modes of each test above show the action succeeding, with the member dropped and on kernels without it |
| Threads that already exist at `lock()` on kernels before 7.0, or with `ALL_THREADS` left out | Landlock restricts only the calling thread there | `lock.rs::kernel::kernel_restricts_threads_that_predate_the_lock`, control mode: the earlier thread reads and writes outside the grants |
| An unconfined process acting for the locked one | Over a connection made before the lock, through a pathname socket before Linux 7.1, or through an abstract socket or signal before 6.12, the locked process can ask another process to open files for it | `lock.rs::kernel::a_descriptor_received_after_the_lock_keeps_its_access`, over a connection made before the lock; none for the other routes |
| Descriptors opened before the lock, or received over `SCM_RIGHTS` | Landlock does not apply to an open descriptor; it keeps the access it was opened with. An `io_uring` ring set up before the lock with `SQPOLL`, or a personality registered before it, also keeps the credentials it had, so opens submitted through it after the lock are not restricted. | `lock.rs::kernel::a_descriptor_opened_before_the_lock_keeps_its_access`, `lock.rs::kernel::a_descriptor_received_after_the_lock_keeps_its_access`; none for `io_uring`, which is from the kernel's `io_uring` code, not run |
| `stat`, `access`, `chdir`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, and `fcntl` on paths outside the grants | Landlock cannot restrict these call families ([kernel documentation](https://docs.kernel.org/userspace-api/landlock.html)). A locked process can learn whether any path exists and read its metadata, and can change the mode, times, or extended attributes of files it owns outside the grants. | `lock.rs::kernel::metadata_and_modes_outside_the_grants_are_not_restricted`, for `stat` and `chmod`; `gate_model.rs::kernel::raw_calls_differ_from_the_gate_only_where_documented` and `gate_model.rs::kernel::known_gaps_are_classified`, for `stat` on generated trees; the other families are from the kernel documentation |
| Narrowing or revoking after the lock | The installed ruleset never changes. Only operations through the gate see the change ([RFC 0005](rfcs/0005-grant-narrowing.md#kernel-enforcement)). | `lock.rs::kernel::narrowing_or_revoking_after_the_lock_changes_only_the_gate`, `gate_model.rs::kernel::raw_calls_differ_from_the_gate_only_where_documented`, `gate_model.rs::kernel::known_gaps_are_classified` |
| A nested grant with fewer rights than its parent | Landlock allows an access when any rule allows it, so the kernel enforces the parent's rights beneath the nested grant | `lock.rs::kernel::a_nested_grant_with_fewer_rights_binds_only_the_gate`, `gate_model.rs::kernel::raw_calls_differ_from_the_gate_only_where_documented`, `gate_model.rs::kernel::known_gaps_are_classified` |
| A raw path that reaches an object the rules cover by a route the gate refuses: a symlink from one grant into another or from outside the grants into one, or a `.` or `..` | Landlock checks the object a path resolves to, not the path. The gate removes `.` and `..` lexically and resolves the rest beneath the grant the path names ([RFC 0001](rfcs/0001-core-design.md)), so it refuses these routes, and for it `file/.` names `file`, where the kernel fails with `ENOTDIR`. No route reaches an object the rules do not give the right. | `gate_model.rs::kernel::raw_calls_differ_from_the_gate_only_where_documented`, `gate_model.rs::kernel::known_gaps_are_classified` |
| A raw create beneath rules that give `CREATE` but not `WRITE` | Landlock checks `MakeReg` when the kernel makes the file and `WriteFile` only when it opens it, so the open fails with `EACCES` and leaves an empty file. The gate's `create` needs both rights. | `gate_model.rs::kernel::raw_calls_differ_from_the_gate_only_where_documented`, `gate_model.rs::kernel::known_gaps_are_classified` |
| `LockPolicy::BestEffort` on a kernel below ABI v3 | The caller asked for weaker rules; `LockStatus` reports `PartiallyEnforced` or `LibraryOnly`. On ABI v2 the kernel refuses reads and creates outside the grants but not truncation, so a file beneath a read-only grant can be emptied. | `src/containment.rs::status_follows_the_filesystem_floor_alone`, `lock.rs::kernel::below_landlock_v3::best_effort_lock_enforces_only_the_abi_v2_rules` (Linux 6.1) |
| Network, memory, environment, and syscalls that are not file operations | Out of scope ([README](../README.md#what-fsgate-does-not-do)) | none |

## 3. The broker and its worker

A trusted broker holds the `Gate` and serves `BrokerGate` requests over a Unix socket, returning opened files over `SCM_RIGHTS` ([RFC 0003](rfcs/0003-broker-protocol.md)). Without `--socket`, `fsgate-broker` passes the command an inherited connection and names it in `FSGATE_BROKER_FD`. With `--unconfined --socket`, it binds an owner-only socket at that path, starts the command with `FSGATE_BROKER_SOCKET` set, and removes the socket when the command exits. Unless given `--unconfined`, it confines the command on Linux ([RFC 0008](rfcs/0008-confine-broker-worker.md)) and refuses to start it elsewhere.

**Trusts:**

- The broker process and its gate.
- Every process of an admitted user that can connect to a socket. `Broker::serve` admits the broker's own user by default, and at most 64 connections. `serve_conn` checks nothing, because its caller chose the stream. Whoever is admitted has the grants.
- The embedder, to isolate a worker it serves through the library. `Broker` does not remove a worker's ambient filesystem authority. `fsgate-broker --unconfined` starts the command as the same user, with the same environment and filesystem access as itself.

**Stops:**

| Attack | Outcome | Test |
|---|---|---|
| A request for an ungranted path, or beyond a grant's rights | The typed `GateError` crosses the wire; no side effect | `broker.rs::denials_cross_the_wire_typed_and_leave_no_side_effect` |
| A worker that tries to influence the decision | The request carries only an operation and a path; the broker's gate decides and audits | `audit.rs::broker_decisions_are_audited_server_side` |
| A worker that outlives its broker | Every later operation fails with `GateError::Broker`, with no reconnect | `broker.rs::dead_broker_fails_every_operation_closed`, `broker.rs::broker_binary_serves_and_dies_closed` |
| A response that is lost, as to a read timeout on the worker's stream | Every later request on that connection fails with `GateError::Broker`, because answers can no longer be matched to requests | `broker.rs::a_lost_response_fails_every_later_request_closed` |
| A worker asking for a directory's descriptor | `EISDIR` crosses the wire and nothing is delivered. A directory descriptor would move authority into the worker ([RFC 0003](rfcs/0003-broker-protocol.md#alternatives-considered)). | `broker.rs::a_directory_is_never_delivered` |
| A delivered file leaking into programs the worker runs | Received descriptors are close-on-exec | `broker.rs::delivered_descriptors_do_not_leak_into_spawned_programs` |
| A frame over 1 MiB | The broker closes the connection before reading the body, and audits it as `request` with `frame_too_large` | `broker.rs::a_prefix_over_the_size_limit_fails_the_connection_closed`, `broker_serve.rs::a_request_that_breaks_the_protocol_is_audited` |
| A request or response that would not fit in 1 MiB, such as a listing of a very large directory | Only that request fails, with `GateError::Broker`, and the connection keeps serving | `broker.rs::a_response_over_the_size_limit_fails_only_its_request`, `broker.rs::a_request_over_the_size_limit_fails_only_itself` |
| A length prefix shorter than the bytes that follow it | The broker closes the connection without acting, and audits it as `request` with `malformed_frame` | `broker.rs::bytes_beyond_the_declared_length_fail_the_connection_closed`, `broker_serve.rs::a_request_that_breaks_the_protocol_is_audited` |
| A malformed request, an unknown or missing operation, or a request path that is not UTF-8 | The broker closes the connection without acting, and audits it as `request` with `malformed_request` | `broker.rs::a_malformed_request_fails_the_connection_closed`, `broker_serve.rs::a_request_that_breaks_the_protocol_is_audited` |
| A directory entry name that is not UTF-8 | Refused, never transcoded | `broker.rs::a_directory_entry_name_that_is_not_utf8_is_refused` (Linux only; APFS refuses such names) |
| Arbitrary bytes from the worker | No panic, hang, sanitizer report, or delivered descriptor outside the grant in the recorded fuzzing runs on macOS and Linux | the [`broker_requests` fuzz target](../fuzz/README.md), not a test; runs recorded in [M9](../ROADMAP.md#m9--review-readiness-and-020) |
| Descriptors the worker attaches to a request, even split across many messages | The broker closes the connection without acting at the first one, and closes what it received, even as many as one message can carry. A message the kernel reports truncated, as when the broker's descriptor table is full, fails the connection closed. Either is audited as `request` with `malformed_frame`. | `broker_attached_descriptors.rs::a_request_that_carries_descriptors_fails_the_connection_closed`, `broker_attached_descriptors.rs::the_first_descriptor_ends_a_request_split_across_messages`, `broker_attached_descriptors.rs::a_request_whose_descriptors_cannot_be_received_fails_the_connection_closed` (Linux only), `broker_serve.rs::a_request_that_breaks_the_protocol_is_audited` for one descriptor |
| Another process connecting to an inherited connection | It has no name in the filesystem, so there is nothing to connect to | `broker_inherited.rs::a_worker_is_served_over_an_inherited_connection` |
| Another user connecting to an `fsgate-broker --socket` path, whatever the umask | The socket is `0600` before it accepts connections | `broker.rs::a_socket_is_owner_only_whatever_the_umask` |
| Another user replacing an `fsgate-broker --socket` path with their own socket | The broker refuses a path through a directory another user owns, or can write to without the sticky bit, and starts nothing | `broker.rs::a_socket_path_others_could_replace_is_refused` |
| A peer of another user connecting through `Broker::serve` | Closed with no answer and no side effect, unless the embedder admits that uid. Audited as `connect` with `peer_refused` and the peer's uid. | `broker_serve.rs::a_peer_of_another_user_gets_no_answer`, `broker_serve.rs::a_refused_peer_is_audited_with_its_uid` |
| More connections than the limit through `Broker::serve` | Each one past the limit (64 by default) is closed at once, audited as `connect` with `connection_limit`, and served again once a slot frees | `broker_serve.rs::connections_past_the_limit_are_closed_until_one_ends`, `broker_serve.rs::a_connection_past_the_limit_is_audited` |
| A confined worker, or a program it starts, opening files directly (Linux) | `EACCES`, and no file is created. The grants never become worker rules, so a granted file is refused too. A grant that overlaps a runtime path or a `--direct` path is refused before the worker starts (see below). | `broker_confined.rs::kernel::a_confined_worker_cannot_reach_files_on_its_own`, `broker_confined.rs::kernel::a_granted_file_comes_only_through_the_broker`, `broker_confined.rs::kernel::a_direct_path_can_be_read_and_nothing_beside_it` |
| A worker that cannot be confined | It does not start unless the command line says `--unconfined` | `broker_confined.rs::the_broker_refuses_to_start_a_worker_without_landlock` (on Linux booted with `lsm=capability`), `broker_confined.rs::the_broker_refuses_to_start_a_worker_below_landlock_v3` (Linux 6.1, ABI v2), `broker_confined.rs::a_platform_that_cannot_confine_refuses_to_start_the_worker` (macOS) |
| Descriptors the broker's parent left open reaching a confined worker | Closed when the worker starts, since Landlock does not restrict what was opened before it | `broker_confined.rs::kernel::a_descriptor_the_parent_left_open_is_closed_in_the_worker` |
| Secrets in the broker's environment reaching a confined worker | It gets only the names given with `--env` | `broker_confined.rs::kernel::a_confined_worker_inherits_only_the_named_variables` |
| A confined worker typing into the user's terminal with `TIOCSTI` | It leads its own session, so it has no controlling terminal | `broker_confined.rs::kernel::a_confined_worker_leads_its_own_session`, which checks the session and not the ioctl |
| A confined worker inspecting its broker | The kernel's ptrace check refuses it, and `no_new_privs` keeps set-ID programs from helping | `broker_confined.rs::kernel::a_confined_worker_cannot_inspect_its_broker`, through `/proc/<pid>/environ` and not `PTRACE_ATTACH` |
| A confined worker that keeps its death signal outliving a killed broker | The kernel kills it | `broker_confined.rs::kernel::killing_the_broker_kills_a_confined_worker` |
| A program a confined worker leaves running when it exits | The broker kills the worker's process group before it exits, and still exits with the worker's code ([RFC 0010](rfcs/0010-worker-process-group.md)) | `broker_confined.rs::kernel::a_program_a_confined_worker_leaves_running_ends_with_it`; with `--unconfined` nothing is killed: `broker_confined.rs::kernel::an_unconfined_worker_leaves_its_program_running` |
| A confined worker, or a program it starts, reaching a Unix socket outside its confinement, by path or by abstract name, with a connect or a datagram | `EACCES` or `EPERM`, and nothing reaches the socket. Before Linux 7.1 a seccomp filter refuses `socket(AF_UNIX)` and datagram pairs with `EACCES`; from 7.1 Landlock refuses the connects and sends ([RFC 0009](rfcs/0009-worker-unix-sockets.md)) | `broker_confined.rs::kernel::a_confined_worker_cannot_reach_a_unix_socket`, with a control run that reaches all three sockets with `--unconfined` |
| A confined worker making sockets through `io_uring` before Linux 7.1 | `ENOSYS` for `io_uring_setup`, `io_uring_enter`, and `io_uring_register`, as on a kernel without it | `broker_confined.rs::kernel::below_linux_7_1_a_confined_worker_cannot_create_a_unix_socket` |
| A confined worker making an x32 call, or a call from another architecture, before Linux 7.1 | The filter kills the process, since it knows only the native call numbers. On an architecture fsgate has no filter for, the worker does not start. | `broker_confined.rs::kernel::below_linux_7_1_a_confined_worker_cannot_create_a_unix_socket`, for x32 on x86_64; none for another architecture |
| A confined worker and its programs when the broker gets `SIGINT`, `SIGTERM`, or `SIGHUP` | The broker kills the worker's process group, then dies by that signal. The worker can still be stopped by those signals itself. | `broker_confined.rs::kernel::stopping_the_broker_ends_a_confined_worker_and_its_programs`, `broker_confined.rs::kernel::a_confined_worker_can_still_be_stopped_by_a_signal` |

**Does not stop:**

| Gap | Why | Test |
|---|---|---|
| Another process of an admitted user connecting to a socket path | It gets the grants: `Broker::serve` checks the peer's user, not its program, and `serve_conn` checks nothing because its caller chose the stream. An inherited connection does not have this gap. | `broker_serve.rs::another_process_of_the_admitted_user_gets_the_grants` |
| A peer in another user namespace whose uid does not map into the broker's | Linux reports an unmapped uid as the overflow uid ([`user_namespaces(7)`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)), 65534 by default, so a broker running as that uid would admit it | none; from the man page, not run |
| Programs the command starts before adopting an inherited connection | They inherit it and get the grants. `from_inherited` marks it close-on-exec only when it runs. | `broker_inherited.rs::a_program_started_before_adopting_inherits_the_connection` |
| A process allowed to trace the worker or the broker | It can copy an inherited connection, as with `pidfd_getfd`, where the system's ptrace policy allows | none; it depends on the system's ptrace policy |
| A full descriptor table when accepting | New connections wait in the listen backlog, with no error, until a descriptor frees. The broker keeps serving the connections it has. | `broker_serve.rs::a_full_descriptor_table_does_not_stop_the_broker` |
| No thread for a new connection | That connection is closed, audited as `connect` with `no_thread`, and the broker keeps accepting. At startup, `fsgate-broker` exits 1 with an error and removes its socket. | `broker_serve.rs::a_connection_without_a_thread_is_closed_and_serving_continues`, `broker_serve.rs::a_connection_without_a_thread_is_audited`, `broker_serve.rs::a_broker_that_cannot_start_its_serve_thread_exits_with_an_error`, all Linux only |
| Idle connections up to the limit | An admitted peer can hold every slot. There is no idle timeout, because a worker may be idle between requests. | `broker_serve.rs::connections_past_the_limit_are_closed_until_one_ends`, where an idle connection holds the only slot |
| A worker started with `--unconfined`, or served through the library and not isolated | It can open files directly. As the same user, it can also signal the broker, or trace it where the system's ptrace policy allows. | `broker_confined.rs::kernel::a_confined_worker_cannot_reach_files_on_its_own`, control run with `--unconfined`; the rest is the operator's or embedder's job |
| A compromised confined worker using its own connection | It gets whatever the grants allow; the broker cannot tell it from a healthy worker | none; by design |
| A confined worker reading its runtime paths | Anything beneath `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/nix/store`, and `--direct` paths is readable, as are `/etc/ld.so.cache` and OpenSSL's configuration, and those opens are not audited. A grant that overlaps one of those directories or a `--direct` path in either direction, such as `--grant /usr/local/share/app:rw` or `--direct /opt/app:r --grant /opt/app/data:r`, is refused before the worker starts when it gives `READ` or `LIST` there, compared after resolving symlinks. The single files hold no data and are not compared, so `--grant /etc:r` is accepted. A hard link or a mount can still make a granted file reachable through a runtime path. | `broker_confined.rs::kernel::a_grant_the_worker_could_read_directly_is_refused` |
| A confined worker, beyond files | It keeps the network, can read file metadata anywhere, and can change the mode, times, and extended attributes of the user's files, which Landlock cannot restrict ([section 2](#2-the-locked-process-linux)), so a TCP service on `localhost` that acts for its callers is reachable. Before Linux 6.12 it can signal the broker. It keeps Unix sockets it inherited, such as standard streams that are sockets, and makes stream and seqpacket pairs, which reach only each other. | `broker_confined.rs::kernel::below_linux_7_1_a_confined_worker_cannot_create_a_unix_socket`, for the pairs and a TCP socket; none for signals, see [section 2](#2-the-locked-process-linux) |
| A confined worker that clears its death signal, or a program it starts, when the broker gets `SIGKILL` | Either can outlive the broker. `PR_SET_PDEATHSIG` binds only a process that keeps it: the worker can clear its own on its main thread, and a forked child never has one. Nothing runs in the broker after `SIGKILL` to end them. The survivor stays confined, and keeps the network, its delivered files, and the terminal. | `broker_confined.rs::kernel::a_program_a_confined_worker_starts_outlives_its_broker`; clearing the signal is from `prctl(2)`, not run |
| A program a confined worker starts that leaves its process group with `setsid` or `setpgid` | It outlives the worker and the broker, still confined | `broker_confined.rs::kernel::a_program_that_leaves_the_group_outlives_its_worker` |
| A confined worker using the terminal it inherited | It keeps the user's terminal on its standard streams. Because it leads its own session, job control does not cover it: Ctrl-Z stops only the broker, and the worker can read the terminal while the shell is in the foreground, including after the broker exits. | none; from the kernel's job-control rules, not run |
| Files already delivered | They stay usable; the broker keeps no way to take them back | `broker.rs::a_delivered_file_stays_usable_after_its_broker_is_gone` |
| A fork and exec racing a receive on macOS | `FD_CLOEXEC` is set just after `recvmsg`, so a program started in that window inherits the descriptor ([RFC 0003](rfcs/0003-broker-protocol.md#framing)) | none; the window is too narrow to hit reliably |
| Changing policy while serving | `Broker::new` takes the gate, so a serving broker cannot revoke or narrow | none; the compiler enforces it |

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
| Kernels other than 6.6.162, 6.12.117, 7.3.3, and the runner's, kernels without seccomp user notifications, and Landlock ABI below v3 | Untested ([M6](../ROADMAP.md#m6--linux-filesystem-interception-experimental)) | none |

## Audit is observation, not a boundary

- Every decision through a gate or a broker emits one event, including a denial the caller discards: `audit.rs::swallowed_denial_is_still_observed`. A kernel refusal after a policy allow is recorded with its errno: `audit.rs::kernel_refusal_is_allow_with_errno`.
- What a broker refuses before its gate is an event too ([RFC 0011](rfcs/0011-audit-broker-refusals.md)): each connection `Broker::serve_with` accepts is one `connect` event with the peer's uid, and a request that breaks the protocol is one `request` event. The `allow` for a connection comes before its requests' events: `broker_serve.rs::an_admitted_connection_is_audited_before_its_requests`. A connection given to `serve_conn` has no `connect` event and no uid: `broker_serve.rs::a_connection_given_to_serve_conn_is_audited_without_a_uid`. Events for `open` and the other operations do not name the peer.
- The kernel's refusals of raw syscalls in a locked process are not events, because fsgate never sees them. Only the launcher turns intercepted opens into events. Before `lock()`, code that bypasses the gate leaves no event at all.
- The sink is trusted embedder code that runs synchronously in the calling thread. A sink that blocks stalls the operation, and nothing in it can veto a decision ([RFC 0002](rfcs/0002-audit-events.md#delivery)).
- Events are not signed. Tamper evidence is the embedder's storage problem.

## Outside this model

- Attackers already privileged outside the sandbox (root, `CAP_SYS_ADMIN`), and bugs in the kernel.
- Memory-safety bugs in fsgate's dependencies: cap-std, rustix, `landlock`, and serde_json.
- Denial of service, beyond the broker rows above.
- Release integrity, covered by [the release procedure](RELEASING.md).
- Windows, network access, and macOS containment, which exists only through the broker.
