# Run an unmodified program with explicit runtime grants

**Experimental Linux x86_64 interception from this repository.** This profile is
not released or independently reviewed. It supports read-only absolute file
opens; it is not a general-purpose program sandbox. Landlock ABI 3 and seccomp
user notifications are required. Missing support prevents startup.

Build from the repository:

```sh
cargo build --locked --release --features experimental-intercept --bin fsgate-broker
```

For a glibc program on Debian/Ubuntu, name its interpreter and library directory
explicitly. These paths are examples for that layout, not built-in defaults.
Inspect the program with `readelf -l /usr/bin/cat` to find its interpreter; inspect
`readelf -d /usr/bin/cat` for declared library dependencies. Neither command
executes the selected program.

```sh
target/release/fsgate-broker --experimental-intercept \
  --grant /srv/data:r \
  --runtime /lib64/ld-linux-x86-64.so.2 \
  --runtime /lib/x86_64-linux-gnu \
  -- /usr/bin/cat /srv/data/input.txt
```

This prints the worker, interpreter, runtime/data grants, and compatibility
limits without starting the worker. Add `--apply` to run it and `--audit` for JSON
Lines decisions on standard error. Missing library dependencies cause an explicit
loader failure; add only the paths the program needs. The loader cache is optional
and needs its own `--runtime /etc/ld.so.cache` if wanted. The environment is empty,
including `LD_PRELOAD`, `LD_AUDIT`, and `LD_LIBRARY_PATH`.

The equivalent library call is:

```rust,no_run
use fsgate::{Gate, Rights};
use fsgate::intercept::Launch;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gate = Gate::new();
gate.grant("/srv/data", Rights::READ)?;
let outcome = Launch::new("/usr/bin/cat")
    .runtime("/lib64/ld-linux-x86-64.so.2")
    .runtime("/lib/x86_64-linux-gnu")
    .arg("/srv/data/input.txt")
    .run(gate)?;
assert!(outcome.status.success());
# Ok(())
# }
```

Runtime files are readable by the worker, not just by its loader. File grants pin
one object at setup and reopen it with a fresh offset for each request. Directory
grants resolve beneath a held directory; relative symlinks may stay inside it,
but absolute or escaping links fail. `O_NOFOLLOW` and `RESOLVE_NO_SYMLINKS` are
honored for directory resolution. An exact file grant is a pinned alias, including
when its initial path was a symlink. Runtime and data grants cannot overlap by
path or held-directory ancestry. Hard-link aliases and later mount/rename changes
are outside the overlap proof; keep the trusted configuration stable at setup.

`Launch::spawn` returns `Running`. `revoke_runtime(path)` removes a declared
runtime grant for future opens, serialized with request delivery. Other explicit
overlapping runtime grants may still authorize the file. Already delivered
files, loaded mappings, and the loader's installed execution rule remain usable.
Data `revoke` and `narrow` keep their existing behavior.

A nonempty runtime list selects the single-process, single-thread profile,
including for a static main image. `fork`, `vfork`, `clone`, and `clone3` fail.
`newfstatat` supports held descriptors with `AT_EMPTY_PATH` and canonical
absolute regular-file paths covered by READ grants. It uses the same resolver as
opens; relative paths and metadata outside a grant remain refused. `statx` reports `ENOSYS` so libc may use the mediated
fallback. `prlimit64` may query only the caller's limits. Relative data paths,
directory listing, writes, creation, scripts, and arbitrary later execs remain
outside the profile. Without runtime grants, the original static profile remains.

An embedder must leave `SIGCHLD` at its default disposition without
`SA_NOCLDWAIT`, and must not independently reap the owned worker. Startup checks
that signal policy. Runtime cleanup joins the supervisor before reaping, keeping
its PID reserved until all metadata copies finish. Dropping `Running` kills and
reaps its worker. The supervisor still fails pending requests after 30 seconds
without a request or worker exit.

The first compatibility targets are a dynamic C fixture and unmodified GNU
`cat`, `wc`, and `sha256sum`. The roadmap records execution and CI evidence;
this is not a claim of support for Python, Node, musl workers, other architectures,
or arbitrary dynamically linked applications.
