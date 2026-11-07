# Releasing fsgate

Each release is a signed Git tag `vX.Y.Z`, and the crate published to
crates.io is built from exactly that tagged commit. Publishing needs an
explicit maintainer request for each release. A version bump or merged
release-preparation PR is not a completed release.

The commands below set `version` once; use the release's version.

```sh
version=X.Y.Z
```

v0.1.0 was tagged while the manifest still had `publish = false`, so it was
never published. 0.1.1 is the first crates.io release.

## Prepare the version

Start in a clean worktree on `release/v$version`, based on current
`origin/main`. Use [cargo-edit](https://github.com/killercup/cargo-edit#cargo-set-version)
to update the manifest and lockfile together:

```sh
cargo install cargo-edit --version 0.13.13 --locked --no-default-features --features set-version
cargo set-version --package fsgate "$version" --dry-run --offline
cargo set-version --package fsgate "$version" --offline
git diff -- crates/fsgate/Cargo.toml Cargo.lock
```

Only fsgate's version should change in the lockfile. Keep dependencies
and the Rust minimum unchanged. Prepare the changelog under
`$version (unreleased)` until the tag exists. Mark roadmap items complete
only with merged PR evidence.

## Verify the candidate

Run from the workspace root:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo +1.85.0 test --locked
cargo deny check
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps
```

Commit the preparation on the release branch, then package the clean
checkout and test the archive outside the repository. In a separate shell:

```sh
set -eu
cargo package --locked
package_dir=$(mktemp -d)
trap 'rm -rf "$package_dir"' EXIT
tar -xzf "target/package/fsgate-$version.crate" -C "$package_dir"
test -f "$package_dir/fsgate-$version/LICENSE"
test -f "$package_dir/fsgate-$version/README.md"
cargo test --locked --manifest-path "$package_dir/fsgate-$version/Cargo.toml"
cargo +1.85.0 test --locked --manifest-path "$package_dir/fsgate-$version/Cargo.toml"
```

The README and LICENSE links in the checkout must become regular files in
the archive. Verify Linux containment in CI as well as local macOS checks;
a passing macOS run does not exercise Landlock. Check every CI row and all
review threads on the exact release PR head, then squash-merge when the
maintainer requests it. Never bypass a failed or pending check.

## Create the signed tag

Do this only after an explicit release request, from clean, current
`main`. Verify the merged commit's CI and package again; record its full
SHA. Confirm `v$version` does not exist locally or on `origin`:

```sh
git fetch origin --tags
git status --short --branch
git rev-parse HEAD origin/main
git tag --list "v$version"
git ls-remote --tags origin "refs/tags/v$version"
```

The two commit IDs must match. Both tag queries must return no tag. Use the
maintainer's configured signing key; do not substitute an unsigned tag:

```sh
set -eu
release_sha=$(git rev-parse HEAD)
git tag -s "v$version" "$release_sha" -m "fsgate $version"
git verify-tag "v$version"
git push origin "refs/tags/v$version"
git ls-remote --tags origin "refs/tags/v$version*"
```

Signature verification requires a trusted public key; SSH signing uses
Git's `gpg.ssh.allowedSignersFile`. Stop if signing or verification fails.
Never move a tag or reuse a version. Retry a failed tag push without
changing the signed tag.

## Publish to crates.io

Publishing cannot be undone: a version can be yanked but never deleted or
replaced. Publish only on an explicit request, from a clean checkout of the
verified tag, after the remote tag points to the recorded commit:

```sh
set -eu
git checkout --detach "v$version"
test "$(git rev-parse HEAD)" = "$release_sha"
git status --short
cargo publish --locked --dry-run
cargo publish --locked
```

`git status --short` must print nothing; never pass `--allow-dirty`. The
dry run builds the archive and checks the manifest without uploading.
Cargo needs a crates.io token for the first release of the crate: either
`cargo login`, which stores it in `~/.cargo/credentials.toml`, or
`CARGO_REGISTRY_TOKEN` for that one command. Never put the token in a
commit, a CI log, or a shell history entry. Later releases should move to
crates.io trusted publishing from CI once it is configured for the crate.

After the upload, confirm the published version and its recorded commit:

```sh
curl -sf -A "fsgate-release-check" "https://crates.io/api/v1/crates/fsgate/$version" \
  | python3 -c 'import json,sys; v=json.load(sys.stdin)["version"]; print(v["num"], v["checksum"])'
```

The checksum must match `shasum -a 256 "target/package/fsgate-$version.crate"`,
the archive `cargo publish` just built and uploaded from the tagged checkout.
If a publish fails, fix the cause and retry the same version without bumping
again; if it succeeded with a defect, yank it and release a new version.

## Record the release

After verifying the remote tag (and the published crate, when there is
one), update the changelog's release date, the README status, and the
roadmap's release checkbox with the tag and merged PR links. The tag does
not create a GitHub release or binary asset. Those channels require their
own explicit request and verification.
