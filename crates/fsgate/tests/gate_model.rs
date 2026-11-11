//! Model-based tests of the gate (ROADMAP M10).
//!
//! Each case builds a generated tree on the real filesystem. It holds
//! directories, files, and symlinks that stay inside, climb out, point at
//! absolute paths, dangle, or loop. Beside the tree is a directory no grant
//! covers, holding a secret. The case grants some of the tree's directories
//! and runs a generated sequence of operations through the gate.
//!
//! Every answer is checked three ways:
//!
//! - Against a reference model of RFC 0001's resolution. Routing is the
//!   lexical rule the RFC states. The rest of the path is walked here one
//!   component at a time with `symlink_metadata` and `read_link`, refusing
//!   anything that leaves the grant, as `RESOLVE_BENEATH` does.
//! - By what a success reached. Its inode must be one beneath the grant the
//!   request was routed to.
//! - By the tree. A failure leaves every entry unchanged, inside the grants
//!   and outside them, and a create changes only the file it created.
//!
//! An audit sink also checks that each decision emits exactly one event, with
//! the routed grant and the normalized path RFC 0002 specifies.
//!
//! proptest shrinks a failing case and prints it, and
//! `known_cases_match_the_model` keeps each one found so far. Set
//! `PROPTEST_CASES` for a longer run.
#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use cap_std::fs::MetadataExt as CapMetadataExt;
use fsgate::{
    AuditDecision, AuditEvent, AuditOp, AuditReason, AuditSink, Gate, GateError, Grant, Rights,
};
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestRunner};
use tempfile::TempDir;

/// Entry names in the tree. There are few, so generated paths often name
/// entries that exist.
const NAMES: [&str; 4] = ["a", "b", "c", "d"];
const WORLD: &str = "world";
const SECRET_DIR: &str = "secret";
const SECRET_FILE: &str = "s";

/// Linux follows at most 40 symlinks in one resolution. Generated chains
/// without a loop are far shorter, so the exact limit only decides how fast
/// a loop fails.
const MAX_HOPS: usize = 40;

#[derive(Clone, Debug)]
enum NodeSpec {
    Dir,
    File,
    Link(LinkSpec),
}

/// Where a symlink points. Node numbers wrap around the nodes that exist.
#[derive(Clone, Debug)]
enum LinkSpec {
    /// The shortest relative path to a node.
    To(usize),
    /// A relative path to a node through the tree's root. It climbs above any
    /// grant deeper than the root on the way, even when the node is inside.
    Detour(usize),
    /// The node's absolute path.
    Absolute(usize),
    /// A relative path that climbs out of the tree to the secret.
    Secret,
    /// A name that exists nowhere.
    Dangling,
    /// A missing name beside the secret, by a relative path. A create that
    /// follows it would write outside every grant.
    OutsideMissing,
    /// The same, by its absolute path.
    OutsideMissingAbsolute,
    /// The link itself.
    Loop,
    Dot,
    DotDot,
}

/// A pick among the directories made so far, a pick among the names, and
/// what to make there.
type EntrySpec = (usize, usize, NodeSpec);

#[derive(Clone, Debug)]
enum Comp {
    Name(usize),
    Dot,
    DotDot,
    World,
    SecretDir,
    SecretFile,
}

/// A path beneath the tree's root, or, rarely, a relative path. Half start
/// at an entry that exists, picked by number, so that more requests reach
/// files.
#[derive(Clone, Debug)]
struct PathSpec {
    relative: bool,
    start: Option<usize>,
    comps: Vec<Comp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FsOp {
    Open,
    Create,
    Metadata,
    ReadDir,
}

impl FsOp {
    fn needed(self) -> Rights {
        match self {
            FsOp::Open | FsOp::Metadata => Rights::READ,
            FsOp::Create => Rights::CREATE | Rights::WRITE,
            FsOp::ReadDir => Rights::LIST,
        }
    }

    fn audit(self) -> AuditOp {
        match self {
            FsOp::Open => AuditOp::Open,
            FsOp::Create => AuditOp::Create,
            FsOp::Metadata => AuditOp::Metadata,
            FsOp::ReadDir => AuditOp::ReadDir,
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Fs(FsOp, PathSpec),
    /// Grants one of the tree's directories, picked by number.
    Grant(usize, u8),
    /// Narrows a grant handle, picked by number.
    Narrow(usize, u8),
    /// Revokes a grant handle, picked by number. A handle stays in the list
    /// after it is revoked, so later picks try it again.
    Revoke(usize),
}

#[derive(Clone, Debug)]
struct Case {
    tree: Vec<EntrySpec>,
    grants: Vec<(usize, u8)>,
    ops: Vec<Op>,
}

fn rights() -> impl Strategy<Value = u8> {
    // Every right half the time, so that most operations reach the
    // filesystem.
    prop_oneof![1 => Just(0b1111_u8), 1 => 0..16_u8]
}

fn link_spec() -> impl Strategy<Value = LinkSpec> {
    prop_oneof![
        3 => (0..32_usize).prop_map(LinkSpec::To),
        2 => (0..32_usize).prop_map(LinkSpec::Detour),
        1 => (0..32_usize).prop_map(LinkSpec::Absolute),
        2 => Just(LinkSpec::Secret),
        2 => Just(LinkSpec::Dangling),
        2 => Just(LinkSpec::OutsideMissing),
        1 => Just(LinkSpec::OutsideMissingAbsolute),
        1 => Just(LinkSpec::Loop),
        1 => Just(LinkSpec::Dot),
        1 => Just(LinkSpec::DotDot),
    ]
}

fn node_spec() -> impl Strategy<Value = NodeSpec> {
    prop_oneof![
        3 => Just(NodeSpec::Dir),
        2 => Just(NodeSpec::File),
        3 => link_spec().prop_map(NodeSpec::Link),
    ]
}

fn comp() -> impl Strategy<Value = Comp> {
    prop_oneof![
        8 => (0..NAMES.len()).prop_map(Comp::Name),
        1 => Just(Comp::Dot),
        2 => Just(Comp::DotDot),
        1 => Just(Comp::World),
        1 => Just(Comp::SecretDir),
        1 => Just(Comp::SecretFile),
    ]
}

fn path_spec() -> impl Strategy<Value = PathSpec> {
    let from_world = prop::collection::vec(comp(), 0..6).prop_map(|comps| (None, comps));
    let from_entry = (0..32_usize, prop::collection::vec(comp(), 0..2))
        .prop_map(|(number, comps)| (Some(number), comps));
    (
        prop::bool::weighted(0.03),
        prop_oneof![from_world, from_entry],
    )
        .prop_map(|(relative, (start, comps))| PathSpec {
            relative,
            start,
            comps,
        })
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => path_spec().prop_map(|path| Op::Fs(FsOp::Open, path)),
        3 => path_spec().prop_map(|path| Op::Fs(FsOp::Create, path)),
        2 => path_spec().prop_map(|path| Op::Fs(FsOp::Metadata, path)),
        2 => path_spec().prop_map(|path| Op::Fs(FsOp::ReadDir, path)),
        1 => (0..16_usize, rights()).prop_map(|(dir, bits)| Op::Grant(dir, bits)),
        1 => (0..8_usize, 0..16_u8).prop_map(|(grant, bits)| Op::Narrow(grant, bits)),
        1 => (0..8_usize).prop_map(Op::Revoke),
    ]
}

fn case() -> impl Strategy<Value = Case> {
    (
        prop::collection::vec((0..16_usize, 0..NAMES.len(), node_spec()), 0..14),
        prop::collection::vec((0..16_usize, rights()), 1..4),
        prop::collection::vec(op(), 1..24),
    )
        .prop_map(|(tree, grants, ops)| Case { tree, grants, ops })
}

struct Tree {
    _temp: TempDir,
    root: PathBuf,
    world: PathBuf,
    /// The tree's real directories, as names beneath `world`. The first is
    /// `world` itself. No symlink is on the way to any of them.
    dirs: Vec<Vec<String>>,
    /// Every entry made, as names beneath `world`, `world` first.
    nodes: Vec<Vec<String>>,
}

fn join<S: AsRef<Path>>(base: &Path, names: &[S]) -> PathBuf {
    names
        .iter()
        .fold(base.to_path_buf(), |path, name| path.join(name))
}

/// A relative path from parts, or `.` when there are none.
fn relative<S: AsRef<Path>>(parts: impl IntoIterator<Item = S>) -> PathBuf {
    let path: PathBuf = parts.into_iter().collect();
    if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path
    }
}

fn build(entries: &[EntrySpec]) -> Tree {
    let temp = tempfile::tempdir().expect("create a temporary directory");
    let root = temp.path().to_path_buf();
    let world = root.join(WORLD);
    fs::create_dir(&world).unwrap();
    fs::create_dir(root.join(SECRET_DIR)).unwrap();
    fs::write(root.join(SECRET_DIR).join(SECRET_FILE), b"secret").unwrap();

    let mut dirs: Vec<Vec<String>> = vec![Vec::new()];
    let mut nodes: Vec<Vec<String>> = vec![Vec::new()];
    let mut links = Vec::new();
    for (number, (parent, name, kind)) in entries.iter().enumerate() {
        let mut names = dirs[parent % dirs.len()].clone();
        names.push(NAMES[name % NAMES.len()].to_string());
        if nodes.contains(&names) {
            continue;
        }
        let path = join(&world, &names);
        match kind {
            NodeSpec::Dir => {
                fs::create_dir(&path).unwrap();
                dirs.push(names.clone());
            }
            NodeSpec::File => fs::write(&path, format!("file {number}")).unwrap(),
            NodeSpec::Link(target) => links.push((names.clone(), target.clone())),
        }
        nodes.push(names);
    }
    // Links come last, so that they can point at any node.
    for (names, spec) in links {
        let target = link_target(&world, &nodes, &names, &spec);
        symlink(target, join(&world, &names)).unwrap();
    }
    Tree {
        _temp: temp,
        root,
        world,
        dirs,
        nodes,
    }
}

fn link_target(world: &Path, nodes: &[Vec<String>], link: &[String], spec: &LinkSpec) -> PathBuf {
    let parent = &link[..link.len() - 1];
    let up = |count: usize| std::iter::repeat_n("..", count);
    let node = |number: &usize| &nodes[number % nodes.len()];
    match spec {
        LinkSpec::To(number) => {
            let target = node(number);
            let common = parent
                .iter()
                .zip(target)
                .take_while(|(left, right)| left == right)
                .count();
            relative(up(parent.len() - common).chain(target[common..].iter().map(String::as_str)))
        }
        LinkSpec::Detour(number) => {
            relative(up(parent.len()).chain(node(number).iter().map(String::as_str)))
        }
        LinkSpec::Absolute(number) => join(world, node(number)),
        LinkSpec::Secret => relative(up(parent.len() + 1).chain([SECRET_DIR, SECRET_FILE])),
        LinkSpec::Dangling => PathBuf::from("nowhere"),
        LinkSpec::OutsideMissing => relative(up(parent.len() + 1).chain([SECRET_DIR, "new"])),
        LinkSpec::OutsideMissingAbsolute => world
            .parent()
            .expect("the tree has a root")
            .join(SECRET_DIR)
            .join("new"),
        LinkSpec::Loop => PathBuf::from(link.last().expect("a link has a name")),
        LinkSpec::Dot => PathBuf::from("."),
        LinkSpec::DotDot => PathBuf::from(".."),
    }
}

fn render(tree: &Tree, spec: &PathSpec) -> PathBuf {
    let parts = spec.comps.iter().map(|comp| match comp {
        Comp::Name(number) => NAMES[number % NAMES.len()],
        Comp::Dot => ".",
        Comp::DotDot => "..",
        Comp::World => WORLD,
        Comp::SecretDir => SECRET_DIR,
        Comp::SecretFile => SECRET_FILE,
    });
    if spec.relative {
        return relative(parts);
    }
    let start = match spec.start {
        Some(number) => join(&tree.world, &tree.nodes[number % tree.nodes.len()]),
        None => tree.world.clone(),
    };
    parts.fold(start, |path, part| path.join(part))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Dir,
    File(Vec<u8>),
    Link(PathBuf),
}

/// Every entry beneath `root`, without following symlinks.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    let mut out = BTreeMap::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(root.join(&dir)).unwrap() {
            let rel = dir.join(entry.unwrap().file_name());
            let path = root.join(&rel);
            let kind = fs::symlink_metadata(&path).unwrap().file_type();
            let value = if kind.is_symlink() {
                Entry::Link(fs::read_link(&path).unwrap())
            } else if kind.is_dir() {
                pending.push(rel.clone());
                Entry::Dir
            } else {
                Entry::File(fs::read(&path).unwrap())
            };
            out.insert(rel, value);
        }
    }
    out
}

type Id = (u64, u64);

fn id_of(path: &Path) -> Id {
    let meta = fs::symlink_metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

/// The device and inode of everything physically beneath `dir`, including
/// `dir`, without following symlinks.
fn ids_beneath(dir: &Path) -> BTreeSet<Id> {
    let mut out = BTreeSet::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        out.insert(id_of(&dir));
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                pending.push(path);
            } else {
                out.insert(id_of(&path));
            }
        }
    }
    out
}

fn is_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Why the model refused a walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// A `..` above the grant.
    Escape,
    /// An absolute symlink.
    Absolute,
    /// A missing directory on the way.
    Missing,
    /// A file used as a directory.
    NotDir,
    Loop,
}

/// Where a walk beneath a grant ended.
#[derive(Debug)]
enum Walk {
    /// An existing entry, as a path beneath the grant.
    Found(PathBuf),
    /// The last component is missing: the directory it would be in, and its
    /// name.
    MissingLast(PathBuf, OsString),
    Refused(Refusal),
}

fn parts(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::ParentDir => Some(OsString::from("..")),
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect()
}

/// Walks `rel` beneath `base` one component at a time, refusing what
/// `RESOLVE_BENEATH` refuses: a `..` above `base` at any point, even one that
/// would come back, and any absolute symlink.
fn walk(base: &Path, rel: &Path, follow_last: bool) -> Walk {
    let mut stack: Vec<OsString> = Vec::new();
    let mut queue: VecDeque<OsString> = parts(rel).into();
    let mut hops = 0;
    while let Some(name) = queue.pop_front() {
        if name == ".." {
            if stack.pop().is_none() {
                return Walk::Refused(Refusal::Escape);
            }
            continue;
        }
        let here = join(base, &stack);
        let path = here.join(&name);
        let last = queue.is_empty();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            return if last {
                Walk::MissingLast(here, name)
            } else {
                Walk::Refused(Refusal::Missing)
            };
        };
        if meta.file_type().is_symlink() && (!last || follow_last) {
            hops += 1;
            if hops > MAX_HOPS {
                return Walk::Refused(Refusal::Loop);
            }
            let target = fs::read_link(&path).unwrap();
            if target.is_absolute() {
                return Walk::Refused(Refusal::Absolute);
            }
            for part in parts(&target).into_iter().rev() {
                queue.push_front(part);
            }
            continue;
        }
        if !last && !meta.is_dir() {
            return Walk::Refused(Refusal::NotDir);
        }
        stack.push(name);
    }
    Walk::Found(join(base, &stack))
}

/// What the model says an operation that passed policy does.
#[derive(Debug)]
enum Expect {
    /// Succeeds and reaches this entry.
    Reach(PathBuf),
    /// Fails in the filesystem.
    Fail(Option<Refusal>),
    /// Creating through a symlink whose target does not exist. Linux's
    /// `O_CREAT` creates the target, and the component walk elsewhere may
    /// refuse. Either is safe, and the checks on the tree still apply.
    Either(PathBuf),
}

fn expect(op: FsOp, base: &Path, rel: &Path) -> Expect {
    let refused = |walk: Walk| match walk {
        Walk::Refused(why) => Expect::Fail(Some(why)),
        _ => Expect::Fail(None),
    };
    match op {
        FsOp::Open => match walk(base, rel, true) {
            Walk::Found(path) if !is_dir(&path) => Expect::Reach(path),
            other => refused(other),
        },
        FsOp::Metadata => match walk(base, rel, true) {
            Walk::Found(path) => Expect::Reach(path),
            other => refused(other),
        },
        FsOp::ReadDir => match walk(base, rel, true) {
            Walk::Found(path) if is_dir(&path) => Expect::Reach(path),
            other => refused(other),
        },
        FsOp::Create => match walk(base, rel, false) {
            Walk::Found(path) if is_symlink(&path) => match walk(base, rel, true) {
                Walk::Found(target) if !is_dir(&target) => Expect::Reach(target),
                Walk::MissingLast(dir, name) => Expect::Either(dir.join(name)),
                other => refused(other),
            },
            Walk::Found(path) if is_dir(&path) => Expect::Fail(None),
            Walk::Found(path) => Expect::Reach(path),
            Walk::MissingLast(dir, name) => Expect::Reach(dir.join(name)),
            other => refused(other),
        },
    }
}

/// The lexical normalization RFC 0001 specifies: `.` dropped, `..` removes
/// the previous component, and nothing touches the filesystem.
fn normalize(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
            _ => {}
        }
    }
    Some(out)
}

#[derive(Default)]
struct Events(Mutex<Vec<AuditEvent>>);

impl AuditSink for Events {
    fn event(&self, event: &AuditEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

impl Events {
    fn take(&self) -> Vec<AuditEvent> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

/// How often each kind of answer came up across a run. A run that never
/// reaches one proves nothing about it.
#[derive(Debug, Default)]
struct Coverage {
    not_absolute: usize,
    no_grant: usize,
    rights_exceeded: usize,
    reached: BTreeMap<&'static str, usize>,
    refused: BTreeMap<String, usize>,
    /// Successes that followed a symlink, by operation.
    through_link: BTreeMap<&'static str, usize>,
    /// Creates through a symlink to a missing entry, which created it or were
    /// refused.
    either_created: usize,
    either_refused: usize,
    /// Creates refused for leaving the grant, through `..` or an absolute
    /// symlink.
    create_escape_refused: usize,
    unknown_grant: usize,
    would_widen: usize,
    narrowed: usize,
    revoked: usize,
}

impl Coverage {
    /// The kinds of answer this run has not reached yet.
    fn missing(&self) -> Vec<String> {
        let mut missing = Vec::new();
        for (name, count) in [
            ("NotAbsolute", self.not_absolute),
            ("NoGrant", self.no_grant),
            ("RightsExceeded", self.rights_exceeded),
            ("UnknownGrant", self.unknown_grant),
            ("WouldWiden", self.would_widen),
            ("narrow", self.narrowed),
            ("revoke", self.revoked),
            (
                "a create through a dangling symlink",
                self.either_created + self.either_refused,
            ),
            (
                "a create refused for leaving its grant",
                self.create_escape_refused,
            ),
        ] {
            if count == 0 {
                missing.push(name.to_string());
            }
        }
        for op in ["open", "create", "metadata", "read_dir"] {
            if !self.reached.contains_key(op) {
                missing.push(format!("a successful {op}"));
            }
            if !self.through_link.contains_key(op) {
                missing.push(format!("a successful {op} through a symlink"));
            }
        }
        for why in [Refusal::Escape, Refusal::Absolute, Refusal::Loop] {
            if !self.refused.contains_key(&format!("{why:?}")) {
                missing.push(format!("a refusal for {why:?}"));
            }
        }
        missing
    }
}

struct ModelGrant {
    path: PathBuf,
    rights: Rights,
}

struct Run<'a> {
    tree: Tree,
    gate: Gate,
    events: Arc<Events>,
    handles: Vec<Grant>,
    /// The model's grant table. Indexes match the gate's, and both keep a
    /// revoked grant's slot.
    grants: Vec<Option<ModelGrant>>,
    coverage: &'a Mutex<Coverage>,
}

fn ensure(condition: bool, message: impl FnOnce() -> String) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message()) }
}

fn one_event(context: &str, events: Vec<AuditEvent>) -> Result<AuditEvent, String> {
    match <[AuditEvent; 1]>::try_from(events) {
        Ok([event]) => Ok(event),
        Err(events) => Err(format!(
            "{context}: expected exactly one audit event, got {}: {events:?}",
            events.len()
        )),
    }
}

fn expect_event(
    context: &str,
    event: &AuditEvent,
    op: AuditOp,
    decision: AuditDecision,
    reason: AuditReason,
    grant: Option<usize>,
) -> Result<(), String> {
    ensure(
        event.op == op
            && event.decision == decision
            && event.reason == reason
            && event.grant == grant,
        || {
            format!(
                "{context}: expected a {op:?} event with {decision:?}, {reason:?}, grant {grant:?}; \
                 got {event:?}"
            )
        },
    )
}

fn unchanged(context: &str, before: &BTreeMap<PathBuf, Entry>, root: &Path) -> Result<(), String> {
    let after = snapshot(root);
    ensure(&after == before, || {
        format!("{context}: the tree changed\nbefore: {before:?}\nafter:  {after:?}")
    })
}

fn result_text<T>(result: &Result<T, GateError>) -> String {
    match result {
        Ok(_) => "success".to_string(),
        Err(err) => format!("{err:?}"),
    }
}

impl Run<'_> {
    fn cover(&self, update: impl FnOnce(&mut Coverage)) {
        update(&mut self.coverage.lock().unwrap());
    }

    fn grant(&mut self, step: usize, pick: usize, bits: u8) -> Result<(), String> {
        let path = join(
            &self.tree.world,
            &self.tree.dirs[pick % self.tree.dirs.len()],
        );
        let rights = Rights::from_bits_truncate(bits);
        let context = format!("step {step}: grant `{}` {rights:?}", path.display());
        let handle = self
            .gate
            .grant(&path, rights)
            .map_err(|err| format!("{context}: {err}"))?;
        let event = one_event(&context, self.events.take())?;
        let index = self.grants.len();
        expect_event(
            &context,
            &event,
            AuditOp::Grant,
            AuditDecision::Allow,
            AuditReason::Ok,
            Some(index),
        )?;
        self.grants.push(Some(ModelGrant {
            path: normalize(&path).expect("tree paths are absolute"),
            rights,
        }));
        self.handles.push(handle);
        Ok(())
    }

    fn narrow(&mut self, step: usize, pick: usize, bits: u8) -> Result<(), String> {
        let index = pick % self.handles.len();
        let rights = Rights::from_bits_truncate(bits);
        let context = format!("step {step}: narrow grant {index} to {rights:?}");
        let result = self.gate.narrow(self.handles[index], rights);
        let event = one_event(&context, self.events.take())?;
        ensure(
            event.op == AuditOp::Narrow && event.grant == Some(index),
            || format!("{context}: got {event:?}"),
        )?;
        match &mut self.grants[index] {
            None => {
                ensure(matches!(result, Err(GateError::UnknownGrant)), || {
                    format!("{context}: the grant was revoked, got {result:?}")
                })?;
                expect_event(
                    &context,
                    &event,
                    AuditOp::Narrow,
                    AuditDecision::Deny,
                    AuditReason::UnknownGrant,
                    Some(index),
                )?;
                self.cover(|coverage| coverage.unknown_grant += 1);
            }
            Some(grant) if !grant.rights.contains(rights) => {
                let (held, extra) = (grant.rights, rights.missing_from(grant.rights));
                ensure(
                    matches!(
                        &result,
                        Err(GateError::WouldWiden { grant_path, held: got_held, extra: got_extra })
                            if grant_path == &grant.path && *got_held == held && *got_extra == extra
                    ),
                    || format!("{context}: expected WouldWiden {held:?} {extra:?}, got {result:?}"),
                )?;
                expect_event(
                    &context,
                    &event,
                    AuditOp::Narrow,
                    AuditDecision::Deny,
                    AuditReason::RightsExceeded,
                    Some(index),
                )?;
                self.cover(|coverage| coverage.would_widen += 1);
            }
            Some(grant) => {
                ensure(result.is_ok(), || format!("{context}: got {result:?}"))?;
                expect_event(
                    &context,
                    &event,
                    AuditOp::Narrow,
                    AuditDecision::Allow,
                    AuditReason::Ok,
                    Some(index),
                )?;
                grant.rights = rights;
                self.cover(|coverage| coverage.narrowed += 1);
            }
        }
        Ok(())
    }

    fn revoke(&mut self, step: usize, pick: usize) -> Result<(), String> {
        let index = pick % self.handles.len();
        let context = format!("step {step}: revoke grant {index}");
        let result = self.gate.revoke(self.handles[index]);
        let event = one_event(&context, self.events.take())?;
        if self.grants[index].take().is_some() {
            ensure(result.is_ok(), || format!("{context}: got {result:?}"))?;
            expect_event(
                &context,
                &event,
                AuditOp::Revoke,
                AuditDecision::Allow,
                AuditReason::Ok,
                Some(index),
            )?;
            self.cover(|coverage| coverage.revoked += 1);
        } else {
            ensure(matches!(result, Err(GateError::UnknownGrant)), || {
                format!("{context}: the grant was revoked, got {result:?}")
            })?;
            expect_event(
                &context,
                &event,
                AuditOp::Revoke,
                AuditDecision::Deny,
                AuditReason::UnknownGrant,
                Some(index),
            )?;
            self.cover(|coverage| coverage.unknown_grant += 1);
        }
        Ok(())
    }

    /// The live grant RFC 0001 routes `full` to: the longest covering path,
    /// and of equal ones, the later grant, as `Iterator::max_by_key` picks.
    fn route(&self, full: &Path) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for (index, grant) in self.grants.iter().enumerate() {
            let Some(grant) = grant else { continue };
            if !full.starts_with(&grant.path) {
                continue;
            }
            let depth = grant.path.components().count();
            if best.is_none_or(|(_, longest)| depth >= longest) {
                best = Some((index, depth));
            }
        }
        best.map(|(index, _)| index)
    }

    /// What the model predicts for a request, decided from the tree before
    /// the gate runs, so that a create cannot change the prediction.
    fn predict(&self, op: FsOp, requested: &Path) -> Predicted {
        let Some(full) = normalize(requested) else {
            return Predicted::NotAbsolute;
        };
        let Some(index) = self.route(&full) else {
            return Predicted::NoGrant { full };
        };
        let grant = self.grants[index]
            .as_ref()
            .expect("route returns live grants");
        let needed = op.needed();
        if !grant.rights.contains(needed) {
            return Predicted::RightsExceeded {
                full,
                index,
                grant_path: grant.path.clone(),
                missing: needed.missing_from(grant.rights),
            };
        }
        let base = grant.path.clone();
        let rel = full
            .strip_prefix(&base)
            .expect("routing checked the prefix");
        let rel = if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel.to_path_buf()
        };
        let expected = expect(op, &base, &rel);
        Predicted::Allowed {
            full,
            index,
            base,
            rel,
            expected,
        }
    }

    fn fs_op(&mut self, step: usize, op: FsOp, spec: &PathSpec) -> Result<(), String> {
        let requested = render(&self.tree, spec);
        let context = format!("step {step}: {op:?} `{}`", requested.display());
        let before = snapshot(&self.tree.root);
        let predicted = self.predict(op, &requested);
        let result = match op {
            FsOp::Open => self.gate.open(&requested).map(Reached::File),
            FsOp::Create => self.gate.create(&requested).map(Reached::Created),
            FsOp::Metadata => self.gate.metadata(&requested).map(Reached::Metadata),
            FsOp::ReadDir => self.gate.read_dir(&requested).map(Reached::Dir),
        };
        let event = one_event(&context, self.events.take())?;

        let (full, index, base, rel, expected) = match predicted {
            Predicted::NotAbsolute => {
                ensure(
                    matches!(&result, Err(GateError::NotAbsolute { path }) if path == &requested),
                    || {
                        format!(
                            "{context}: expected NotAbsolute, got {}",
                            result_text(&result)
                        )
                    },
                )?;
                expect_event(
                    &context,
                    &event,
                    op.audit(),
                    AuditDecision::Deny,
                    AuditReason::NotAbsolute,
                    None,
                )?;
                self.cover(|coverage| coverage.not_absolute += 1);
                return unchanged(&context, &before, &self.tree.root);
            }
            Predicted::NoGrant { full } => {
                ensure(
                    matches!(&result, Err(GateError::NoGrant { path }) if path == &full),
                    || format!("{context}: expected NoGrant, got {}", result_text(&result)),
                )?;
                expect_event(
                    &context,
                    &event,
                    op.audit(),
                    AuditDecision::Deny,
                    AuditReason::NoGrant,
                    None,
                )?;
                normalized_path(&context, &event, &full)?;
                self.cover(|coverage| coverage.no_grant += 1);
                return unchanged(&context, &before, &self.tree.root);
            }
            Predicted::RightsExceeded {
                full,
                index,
                grant_path,
                missing,
            } => {
                ensure(
                    matches!(
                        &result,
                        Err(GateError::RightsExceeded { path, grant_path: got_grant, missing: got, op: name })
                            if path == &full && got_grant == &grant_path && *got == missing
                                && name == op.audit().as_str()
                    ),
                    || {
                        format!(
                            "{context}: expected RightsExceeded for grant {index} missing \
                             {missing:?}, got {}",
                            result_text(&result)
                        )
                    },
                )?;
                expect_event(
                    &context,
                    &event,
                    op.audit(),
                    AuditDecision::Deny,
                    AuditReason::RightsExceeded,
                    Some(index),
                )?;
                normalized_path(&context, &event, &full)?;
                self.cover(|coverage| coverage.rights_exceeded += 1);
                return unchanged(&context, &before, &self.tree.root);
            }
            Predicted::Allowed {
                full,
                index,
                base,
                rel,
                expected,
            } => (full, index, base, rel, expected),
        };
        normalized_path(&context, &event, &full)?;

        let context = format!(
            "{context} (grant {index} `{}`, model {expected:?})",
            base.display()
        );
        match result {
            Err(GateError::Io { path, source }) => {
                ensure(path == full, || {
                    format!("{context}: Io names `{}`", path.display())
                })?;
                ensure(
                    event.decision == AuditDecision::Allow
                        && event.reason == AuditReason::Ok
                        && event.grant == Some(index)
                        && event.errno.is_some()
                        && event.errno == source.raw_os_error(),
                    || format!("{context}: failed with {source}, got {event:?}"),
                )?;
                match &expected {
                    Expect::Fail(why) => {
                        let label = why.map_or("other".to_string(), |why| format!("{why:?}"));
                        let escape = matches!(why, Some(Refusal::Escape | Refusal::Absolute));
                        self.cover(|coverage| {
                            *coverage.refused.entry(label).or_default() += 1;
                            if op == FsOp::Create && escape {
                                coverage.create_escape_refused += 1;
                            }
                        });
                    }
                    Expect::Either(_) => self.cover(|coverage| coverage.either_refused += 1),
                    Expect::Reach(_) => {
                        return Err(format!("{context}: the gate failed with {source}"));
                    }
                }
                unchanged(&context, &before, &self.tree.root)
            }
            Ok(reached) => {
                expect_event(
                    &context,
                    &event,
                    op.audit(),
                    AuditDecision::Allow,
                    AuditReason::Ok,
                    Some(index),
                )?;
                ensure(event.errno.is_none(), || {
                    format!("{context}: got {event:?}")
                })?;
                let target = match expected {
                    Expect::Reach(target) => target,
                    Expect::Either(target) => {
                        self.cover(|coverage| coverage.either_created += 1);
                        target
                    }
                    Expect::Fail(_) => return Err(format!("{context}: the gate succeeded")),
                };
                // The model reaches the lexical path unless it followed a
                // symlink on the way.
                let through_link = target != base.join(&rel);
                self.cover(|coverage| {
                    *coverage.reached.entry(op.audit().as_str()).or_default() += 1;
                    if through_link {
                        *coverage
                            .through_link
                            .entry(op.audit().as_str())
                            .or_default() += 1;
                    }
                });
                self.check_reached(&context, step, reached, &target, &base, &before)
            }
            Err(other) => Err(format!("{context}: got {other:?}")),
        }
    }

    /// Checks that a success reached `target`, which is beneath the grant at
    /// `base`, by device and inode, and that only a create changed the tree.
    fn check_reached(
        &self,
        context: &str,
        step: usize,
        reached: Reached,
        target: &Path,
        base: &Path,
        before: &BTreeMap<PathBuf, Entry>,
    ) -> Result<(), String> {
        let root = &self.tree.root;
        let created = matches!(reached, Reached::Created(_));
        let got = match reached {
            Reached::File(file) => {
                let meta = file.metadata().unwrap();
                (meta.dev(), meta.ino())
            }
            Reached::Metadata(meta) => (CapMetadataExt::dev(&meta), CapMetadataExt::ino(&meta)),
            Reached::Dir(entries) => {
                let mut listed = BTreeMap::new();
                for entry in entries {
                    let entry = entry.unwrap();
                    let is_link = entry.file_type().unwrap().is_symlink();
                    let meta = entry.metadata().unwrap();
                    let id = (CapMetadataExt::dev(&meta), CapMetadataExt::ino(&meta));
                    listed.insert(entry.file_name(), (!is_link).then_some(id));
                }
                let mut expected = BTreeMap::new();
                for entry in fs::read_dir(target).unwrap() {
                    let entry = entry.unwrap();
                    let is_link = entry.file_type().unwrap().is_symlink();
                    expected.insert(entry.file_name(), (!is_link).then(|| id_of(&entry.path())));
                }
                ensure(listed == expected, || {
                    format!("{context}: listed {listed:?}, expected {expected:?}")
                })?;
                id_of(target)
            }
            Reached::Created(mut file) => {
                let marker = format!("created at step {step}").into_bytes();
                file.write_all(&marker).unwrap();
                let meta = file.metadata().unwrap();
                drop(file);
                let mut expected = before.clone();
                let key = target.strip_prefix(root).expect("targets are in the tree");
                expected.insert(key.to_path_buf(), Entry::File(marker));
                let after = snapshot(root);
                ensure(after == expected, || {
                    format!(
                        "{context}: the create should change only `{}`\nexpected: {expected:?}\n\
                         after:    {after:?}",
                        key.display()
                    )
                })?;
                (meta.dev(), meta.ino())
            }
        };
        ensure(got == id_of(target), || {
            format!("{context}: reached {got:?}, not `{}`", target.display())
        })?;
        ensure(ids_beneath(base).contains(&got), || {
            format!("{context}: reached {got:?}, which is not beneath the grant")
        })?;
        if created {
            Ok(())
        } else {
            unchanged(context, before, root)
        }
    }
}

/// The model's answer for a request, from the tree before it ran.
enum Predicted {
    NotAbsolute,
    NoGrant {
        full: PathBuf,
    },
    RightsExceeded {
        full: PathBuf,
        index: usize,
        grant_path: PathBuf,
        missing: Rights,
    },
    Allowed {
        full: PathBuf,
        index: usize,
        base: PathBuf,
        rel: PathBuf,
        expected: Expect,
    },
}

/// RFC 0002: an event's path is the normalized requested path.
fn normalized_path(context: &str, event: &AuditEvent, full: &Path) -> Result<(), String> {
    ensure(event.path.as_deref() == Some(full), || {
        format!(
            "{context}: the audit event's path is {:?}, not the normalized `{}`",
            event.path,
            full.display()
        )
    })
}

enum Reached {
    File(fs::File),
    Created(fs::File),
    Metadata(fsgate::Metadata),
    Dir(fsgate::ReadDir),
}

fn run(case: &Case, coverage: &Mutex<Coverage>) -> Result<(), String> {
    let tree = build(&case.tree);
    let events = Arc::new(Events::default());
    let mut gate = Gate::new();
    gate.set_audit_sink(events.clone());
    let mut run = Run {
        tree,
        gate,
        events,
        handles: Vec::new(),
        grants: Vec::new(),
        coverage,
    };
    for (step, (dir, bits)) in case.grants.iter().enumerate() {
        run.grant(step, *dir, *bits)?;
    }
    let offset = case.grants.len();
    for (step, op) in case.ops.iter().enumerate() {
        let step = offset + step;
        match op {
            Op::Fs(op, spec) => run.fs_op(step, *op, spec)?,
            Op::Grant(dir, bits) => run.grant(step, *dir, *bits)?,
            Op::Narrow(grant, bits) => run.narrow(step, *grant, *bits)?,
            Op::Revoke(grant) => run.revoke(step, *grant)?,
        }
    }
    Ok(())
}

fn config() -> ProptestConfig {
    // `ProptestConfig::default` reads `PROPTEST_CASES`.
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = 512;
    }
    // A failure prints its shrunk case. Keep it by adding it to
    // `known_cases_match_the_model`, not as a seed file in the source tree.
    config.failure_persistence = None;
    config
}

/// The model test. It also requires that the run reached every kind of
/// answer, so that a change to the generator cannot quietly make it test
/// nothing. A few answers are rare enough that 512 cases miss one now and
/// then, so a run that misses one goes on with another 512, up to `RUNS`
/// in all. An answer the generator can no longer reach still fails.
#[test]
fn the_gate_matches_the_model_and_never_leaves_its_grants() {
    const RUNS: usize = 4;
    let coverage = Mutex::new(Coverage::default());
    let mut first = TestRunner::new(config());
    let mut missing = Vec::new();
    for _ in 0..RUNS {
        // A runner stops once it has passed `cases`, so each run takes a new
        // one. Its generator comes from the first runner's, so a fixed
        // `PROPTEST_RNG_SEED` still repeats the whole test.
        let mut runner = TestRunner::new_with_rng(config(), first.new_rng());
        if let Err(err) = runner.run(&case(), |case| {
            run(&case, &coverage).map_err(TestCaseError::fail)
        }) {
            panic!("{err}");
        }
        missing = coverage.lock().unwrap().missing();
        if missing.is_empty() {
            break;
        }
    }
    let coverage = coverage.into_inner().unwrap();
    assert!(
        missing.is_empty(),
        "{RUNS} runs never reached: {missing:?}\n{coverage:?}"
    );
    eprintln!("{coverage:?}");
}

fn path(start: Option<usize>, comps: Vec<Comp>) -> PathSpec {
    PathSpec {
        relative: false,
        start,
        comps,
    }
}

/// Minimal cases kept as regressions, and cases the generator reaches too
/// rarely to rely on, run through the same checks.
#[test]
fn known_cases_match_the_model() {
    let coverage = Mutex::new(Coverage::default());
    let dangling = |spec: LinkSpec| Case {
        tree: vec![(0, 0, NodeSpec::Link(spec))],
        grants: vec![(0, 0b1111)],
        ops: vec![Op::Fs(FsOp::Create, path(Some(1), vec![]))],
    };
    let cases = [
        // Found by the model: a request no grant covers recorded its path
        // with the `..` in it.
        Case {
            tree: vec![],
            grants: vec![(0, 0b1111)],
            ops: vec![Op::Fs(FsOp::Open, path(None, vec![Comp::DotDot]))],
        },
        // Found by the model: cap-std's refusal of a `..` symlink out of the
        // grant had no errno, so its event read as a success.
        Case {
            tree: vec![
                (0, 2, NodeSpec::Dir),
                (6, 1, NodeSpec::Link(LinkSpec::DotDot)),
            ],
            grants: vec![(2, 0b1111)],
            ops: vec![Op::Fs(FsOp::Open, path(None, vec![Comp::Name(1)]))],
        },
        // Creates through a symlink to a missing name, beside the link and
        // outside every grant.
        dangling(LinkSpec::Dangling),
        dangling(LinkSpec::OutsideMissing),
        dangling(LinkSpec::OutsideMissingAbsolute),
    ];
    for (number, case) in cases.iter().enumerate() {
        if let Err(err) = run(case, &coverage) {
            panic!("case {number}: {err}\n{case:?}");
        }
    }
    let coverage = coverage.into_inner().unwrap();
    eprintln!("{coverage:?}");
    assert_eq!(
        coverage.either_created + coverage.either_refused,
        1,
        "{coverage:?}"
    );
    assert_eq!(coverage.create_escape_refused, 2, "{coverage:?}");
}
