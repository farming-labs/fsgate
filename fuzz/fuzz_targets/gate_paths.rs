//! Resolves arbitrary paths through a gate whose grants cover a fixed tree,
//! and checks that nothing outside them is reached or changed.
//!
//! Each input line is one operation. Its first byte picks `open` (`o`),
//! `create` (`c`), `metadata` (`m`), or `read_dir` (`d`), and the rest is
//! the path, as bytes, relative to the fixture tree. In upper case, the
//! letter takes the rest as the whole path instead, so it can be relative
//! or name anything on the system. Other lines are skipped.
//!
//! The target fails on a panic, a hang, or a sanitizer report, and when an
//! operation
//!
//! - succeeds on an object, found by device and inode, that is not beneath
//!   the grant the path routes to, or lists a directory that is not;
//! - succeeds without the grant holding the operation's right, or fails
//!   with another error than the one the routing calls for;
//! - opens a directory; or
//! - changes the tree anywhere but beneath a grant that holds `CREATE`, or
//!   changes it there in any way but creating or truncating the file that
//!   it returns.
//!
//! The target compares the tree after each `create`, which it then puts
//! back, and once after the input. The tree's symlinks stay inside it, so
//! whatever following them reaches is in what it compares.

#![no_main]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use cap_std::fs::MetadataExt as _;
use fsgate::{Gate, GateError, Rights};
use libfuzzer_sys::fuzz_target;

/// The fixture root `broker_requests` also uses; it must be private.
const ROOT: &str = "/tmp/fsgate-fuzz";
/// A fixed path, so seeds can name files beneath it.
const TREE: &str = "/tmp/fsgate-fuzz/paths";
const MAX_OPS: usize = 32;

/// Directories, relative to [`TREE`].
const DIRS: [&str; 9] = [
    "outside",
    "outside/dir",
    "granted-evil",
    "granted",
    "granted/sub",
    "granted/sub/deep",
    "granted/nested",
    "granted/w",
    "granted/w/wsub",
];

/// Regular files and their contents.
const FILES: [(&str, &str); 10] = [
    ("outside/secret.txt", "secret"),
    ("outside/dir/x.txt", "outside"),
    ("granted-evil/e.txt", "beside the grant"),
    ("granted/a.txt", "inside"),
    ("granted/sub/b.txt", "inside"),
    ("granted/sub/deep/c.txt", "inside"),
    ("granted/nested/n.txt", "nested"),
    ("granted/w/data.txt", "writable"),
    ("granted/w/wsub/f.txt", "writable"),
    ("granted/w/wsub/g.txt", "writable"),
];

const FIFOS: [&str; 2] = ["granted/fifo", "granted/w/fifo"];

/// Symlinks and their targets. None leads out of [`TREE`].
const LINKS: [(&str, &str); 19] = [
    ("granted/inner", "a.txt"),
    ("granted/subdir", "sub"),
    ("granted/up", "../outside/secret.txt"),
    ("granted/updir", "../outside"),
    ("granted/dotdot", ".."),
    ("granted/abs", "/tmp/fsgate-fuzz/paths/outside/secret.txt"),
    ("granted/absin", "/tmp/fsgate-fuzz/paths/granted/a.txt"),
    ("granted/dangling", "missing"),
    ("granted/loop", "loop"),
    ("granted/sub/back", "../a.txt"),
    ("granted/sub/escape", "../../outside/secret.txt"),
    ("granted/nested/nup", "../a.txt"),
    ("granted/w/made", "new.txt"),
    ("granted/w/wsub/up", "../data.txt"),
    ("granted/w/wup", "../a.txt"),
    ("granted/w/wmade", "../made.txt"),
    ("granted/w/wout", "../../outside"),
    ("granted/w/wabs", "/tmp/fsgate-fuzz/paths/outside/made.txt"),
    ("granted/w/wdots", "../.."),
];

/// Grants, relative to [`TREE`]. The other two are nested in the first,
/// so a symlink out of either reaches files the first one covers.
fn grants() -> [(&'static str, Rights); 3] {
    [
        ("granted", Rights::READ | Rights::LIST),
        ("granted/nested", Rights::READ),
        (
            "granted/w",
            Rights::READ | Rights::WRITE | Rights::CREATE | Rights::LIST,
        ),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
    Symlink,
    Fifo,
    Other,
}

/// What the target compares of each entry. A directory's size is left out,
/// because some file systems keep it after an entry is removed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    kind: Kind,
    id: (u64, u64),
    len: u64,
    target: Option<PathBuf>,
}

type Snapshot = BTreeMap<PathBuf, Entry>;
type Listing = BTreeSet<(OsString, (u64, u64))>;

struct Covered {
    path: PathBuf,
    rights: Rights,
    /// Every object beneath the grant, its own directory included.
    ids: BTreeSet<(u64, u64)>,
    /// What listing each directory beneath the grant gives.
    listings: BTreeSet<Listing>,
}

struct Fixture {
    gate: Gate,
    grants: Vec<Covered>,
    snapshot: Snapshot,
}

fn kind_of(meta: &fs::Metadata) -> Kind {
    let kind = meta.file_type();
    if kind.is_dir() {
        Kind::Dir
    } else if kind.is_file() {
        Kind::File
    } else if kind.is_symlink() {
        Kind::Symlink
    } else if kind.is_fifo() {
        Kind::Fifo
    } else {
        Kind::Other
    }
}

/// Every entry beneath `TREE`, without following symlinks.
fn snapshot() -> Snapshot {
    fn walk(dir: &Path, rel: &Path, out: &mut Snapshot) {
        for entry in fs::read_dir(dir).expect("list the fixture") {
            let entry = entry.expect("read a fixture entry");
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).expect("stat a fixture entry");
            let kind = kind_of(&meta);
            let rel = rel.join(entry.file_name());
            out.insert(
                rel.clone(),
                Entry {
                    kind,
                    id: (meta.dev(), meta.ino()),
                    len: if kind == Kind::Dir { 0 } else { meta.len() },
                    target: (kind == Kind::Symlink)
                        .then(|| fs::read_link(&path).expect("read a fixture link")),
                },
            );
            if kind == Kind::Dir {
                walk(&path, &rel, out);
            }
        }
    }
    let mut out = Snapshot::new();
    walk(Path::new(TREE), Path::new(""), &mut out);
    out
}

fn id_of(path: &Path) -> (u64, u64) {
    let meta = fs::symlink_metadata(path).expect("stat a fixture entry");
    (meta.dev(), meta.ino())
}

fn listing_of(dir: &Path) -> Listing {
    fs::read_dir(dir)
        .expect("list the fixture")
        .map(|entry| {
            let entry = entry.expect("read a fixture entry");
            (entry.file_name(), id_of(&entry.path()))
        })
        .collect()
}

fn covered(rel: &str, rights: Rights, snapshot: &Snapshot) -> Covered {
    let path = Path::new(TREE).join(rel);
    let mut ids = BTreeSet::from([id_of(&path)]);
    let mut listings = BTreeSet::from([listing_of(&path)]);
    for (entry_rel, entry) in snapshot {
        if entry_rel.starts_with(rel) {
            ids.insert(entry.id);
            if entry.kind == Kind::Dir {
                listings.insert(listing_of(&Path::new(TREE).join(entry_rel)));
            }
        }
    }
    // An empty listing would match a listing of any empty directory.
    assert!(
        listings.iter().all(|listing| !listing.is_empty()),
        "every directory beneath a grant has an entry"
    );
    Covered {
        path,
        rights,
        ids,
        listings,
    }
}

fn build() {
    let root = Path::new(ROOT);
    match fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => panic!("creating {ROOT} failed: {err}"),
    }
    // /tmp is shared: use the directory only if it is a real directory that
    // this user owns and nobody else can write.
    let meta = fs::symlink_metadata(root).expect("stat the fixture root");
    assert!(
        meta.is_dir()
            && meta.uid() == rustix::process::getuid().as_raw()
            && meta.permissions().mode() & 0o022 == 0,
        "{ROOT} is not a private directory owned by this user; remove it"
    );

    let tree = Path::new(TREE);
    match fs::remove_dir_all(tree) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => panic!("clearing {TREE} failed: {err}"),
    }
    fs::create_dir(tree).expect("create the tree");
    for dir in DIRS {
        fs::create_dir(tree.join(dir)).expect("create a fixture directory");
    }
    for (file, contents) in FILES {
        fs::write(tree.join(file), contents).expect("write a fixture file");
    }
    for fifo in FIFOS {
        let made = Command::new("mkfifo").arg(tree.join(fifo)).status();
        assert!(made.is_ok_and(|status| status.success()), "mkfifo failed");
    }
    for (link, target) in LINKS {
        symlink(target, tree.join(link)).expect("create a fixture link");
    }
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        build();
        let snapshot = snapshot();
        let mut gate = Gate::new();
        let grants = grants()
            .into_iter()
            .map(|(rel, rights)| {
                gate.grant(Path::new(TREE).join(rel), rights)
                    .expect("grant the fixture");
                covered(rel, rights, &snapshot)
            })
            .collect();
        Fixture {
            gate,
            grants,
            snapshot,
        }
    })
}

/// `path` with `.` and `..` resolved by name, as RFC 0001 routes it, or
/// `None` for a relative path.
fn normalize(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
        }
    }
    Some(out)
}

/// The grant with the longest path that contains `path`.
fn route<'a>(grants: &'a [Covered], path: &Path) -> Option<&'a Covered> {
    grants
        .iter()
        .filter(|grant| path.starts_with(&grant.path))
        .max_by_key(|grant| grant.path.components().count())
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Open,
    Create,
    Metadata,
    ReadDir,
}

impl Op {
    fn needs(self) -> Rights {
        match self {
            Op::Open | Op::Metadata => Rights::READ,
            Op::Create => Rights::CREATE | Rights::WRITE,
            Op::ReadDir => Rights::LIST,
        }
    }
}

/// What a successful operation reached.
enum Reached {
    Object { id: (u64, u64), dir: bool },
    Listing(Listing),
}

fn run(gate: &Gate, op: Op, path: &Path) -> Result<Reached, GateError> {
    Ok(match op {
        Op::Open | Op::Create => {
            let file = if matches!(op, Op::Open) {
                gate.open(path)?
            } else {
                gate.create(path)?
            };
            let meta = file.metadata().expect("stat a returned file");
            Reached::Object {
                id: (meta.dev(), meta.ino()),
                dir: meta.is_dir(),
            }
        }
        Op::Metadata => {
            let meta = gate.metadata(path)?;
            Reached::Object {
                id: (meta.dev(), meta.ino()),
                dir: meta.is_dir(),
            }
        }
        Op::ReadDir => Reached::Listing(
            gate.read_dir(path)?
                .map(|entry| {
                    let entry = entry.expect("read a listed entry");
                    let meta = entry.metadata().expect("stat a listed entry");
                    (entry.file_name(), (meta.dev(), meta.ino()))
                })
                .collect(),
        ),
    })
}

/// Puts the tree back after a `create` that succeeded.
fn restore(fixture: &Fixture, after: &Snapshot) {
    for (rel, entry) in after {
        match fixture.snapshot.get(rel) {
            None => fs::remove_file(Path::new(TREE).join(rel)).expect("remove a created file"),
            Some(before) if before != entry => {
                let (_, contents) = FILES
                    .iter()
                    .find(|(file, _)| Path::new(file) == rel)
                    .expect("only a fixture file can change");
                fs::write(Path::new(TREE).join(rel), contents).expect("restore a file");
            }
            Some(_) => {}
        }
    }
    assert_eq!(snapshot(), fixture.snapshot, "the tree was not restored");
}

fn check(fixture: &Fixture, op: Op, raw: &[u8]) {
    let path = Path::new(OsStr::from_bytes(raw));
    let result = run(&fixture.gate, op, path);
    let full = normalize(path);
    let grant = full
        .as_deref()
        .and_then(|full| route(&fixture.grants, full));
    let allowed = grant.filter(|grant| grant.rights.contains(op.needs()));

    match (&result, full.as_ref(), grant, allowed) {
        (Err(GateError::NotAbsolute { .. }), None, _, _)
        | (Err(GateError::NoGrant { .. }), Some(_), None, _)
        | (Err(GateError::RightsExceeded { .. }), Some(_), Some(_), None)
        | (Err(GateError::Io { .. }), Some(_), Some(_), Some(_)) => {
            if matches!(op, Op::Create) {
                assert_eq!(
                    snapshot(),
                    fixture.snapshot,
                    "{op:?} {path:?} failed and changed the tree"
                );
            }
            return;
        }
        (Ok(_), Some(_), Some(_), Some(_)) => {}
        (Ok(_), ..) => panic!(
            "{op:?} {path:?} succeeded; it routes to {grant:?}",
            grant = grant.map(|grant| &grant.path)
        ),
        (Err(err), ..) => panic!(
            "{op:?} {path:?} failed with {err:?}; it routes to {grant:?}",
            grant = grant.map(|grant| &grant.path)
        ),
    }
    let (Ok(reached), Some(grant)) = (result, allowed) else {
        unreachable!("matched above");
    };

    match reached {
        Reached::Object { id, dir } => {
            assert!(
                !(dir && matches!(op, Op::Open | Op::Create)),
                "{op:?} {path:?} returned a directory"
            );
            if matches!(op, Op::Create) {
                let after = snapshot();
                check_created(fixture, path, grant, id, &after);
                restore(fixture, &after);
                return;
            }
            assert!(
                grant.ids.contains(&id),
                "{op:?} {path:?} reached an object outside {grant:?}",
                grant = grant.path
            );
        }
        Reached::Listing(listing) => assert!(
            grant.listings.contains(&listing),
            "read_dir {path:?} listed a directory outside {grant:?}: {listing:?}",
            grant = grant.path
        ),
    }
}

/// A `create` may change one entry beneath its grant: the regular file it
/// returns, new or truncated.
fn check_created(
    fixture: &Fixture,
    path: &Path,
    grant: &Covered,
    id: (u64, u64),
    after: &Snapshot,
) {
    let beneath = grant
        .path
        .strip_prefix(TREE)
        .expect("grants are in the tree");
    let changed: Vec<_> = after
        .iter()
        .filter(|(rel, entry)| fixture.snapshot.get(*rel) != Some(entry))
        .collect();
    let removed = fixture.snapshot.keys().any(|rel| !after.contains_key(rel));
    assert!(!removed, "create {path:?} removed an entry");
    // The fixture has no empty file, so creating or truncating one changes
    // exactly one entry.
    match changed.as_slice() {
        [(rel, entry)] => assert!(
            rel.starts_with(beneath)
                && entry.kind == Kind::File
                && entry.id == id
                && entry.len == 0,
            "create {path:?} changed {rel:?} ({entry:?}), not a file beneath {beneath:?} it returned"
        ),
        _ => panic!("create {path:?} changed {changed:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    for line in data.split(|byte| *byte == b'\n').take(MAX_OPS) {
        let Some((&letter, rest)) = line.split_first() else {
            continue;
        };
        let op = match letter.to_ascii_lowercase() {
            b'o' => Op::Open,
            b'c' => Op::Create,
            b'm' => Op::Metadata,
            b'd' => Op::ReadDir,
            _ => continue,
        };
        if letter.is_ascii_uppercase() {
            check(fixture, op, rest);
        } else {
            check(fixture, op, &[TREE.as_bytes(), b"/", rest].concat());
        }
    }
    assert_eq!(snapshot(), fixture.snapshot, "the input changed the tree");
});
