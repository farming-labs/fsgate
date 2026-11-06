# Releasing fsgate

The planned v0.1.0 release uses a signed Git tag. The crate remains `publish = false`;
publishing to crates.io requires a separate maintainer decision. A version
bump or merged release-preparation PR is not a completed release.

## Prepare the version

Start in a clean worktree on `release/v0.1.0`, based on current
`origin/main`. Use [cargo-edit](https://github.com/killercup/cargo-edit#cargo-set-version)
to update the manifest and lockfile together:

```sh
cargo install cargo-edit --version 0.13.13 --locked --no-default-features --features set-version
cargo set-version --package fsgate 0.1.0 --dry-run --offline
cargo set-version --package fsgate 0.1.0 --offline
git diff -- crates/fsgate/Cargo.toml Cargo.lock
```

Only fsgate's version should change in the lockfile. Keep dependencies,
the Rust minimum, and `publish = false` unchanged. Prepare the changelog
under `0.1.0 (unreleased)` until the tag exists. Mark roadmap items complete
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
tar -xzf target/package/fsgate-0.1.0.crate -C "$package_dir"
test -f "$package_dir/fsgate-0.1.0/LICENSE"
test -f "$package_dir/fsgate-0.1.0/README.md"
cargo test --locked --manifest-path "$package_dir/fsgate-0.1.0/Cargo.toml"
cargo +1.85.0 test --locked --manifest-path "$package_dir/fsgate-0.1.0/Cargo.toml"
```

The README and LICENSE links in the checkout must become regular files in
the archive. Verify Linux containment in CI as well as local macOS checks;
a passing macOS run does not exercise Landlock. Check every CI row and all
review threads on the exact release PR head, then squash-merge when the
maintainer requests it. Never bypass a failed or pending check.

## Create the signed tag

Do this only after an explicit release request, from clean, current
`main`. Verify the merged commit's CI and package again; record its full
SHA. Confirm `v0.1.0` does not exist locally or on `origin`:

```sh
git fetch origin --tags
git status --short --branch
git rev-parse HEAD origin/main
git tag --list v0.1.0
git ls-remote --tags origin refs/tags/v0.1.0
```

The two commit IDs must match. Both tag queries must return no tag. Use the
maintainer's configured signing key; do not substitute an unsigned tag:

```sh
set -eu
release_sha=$(git rev-parse HEAD)
git tag -s v0.1.0 "$release_sha" -m "fsgate 0.1.0"
git verify-tag v0.1.0
git push origin refs/tags/v0.1.0
git ls-remote --tags origin 'refs/tags/v0.1.0*'
```

Signature verification requires a trusted public key; SSH signing uses
Git's `gpg.ssh.allowedSignersFile`. Stop if signing or verification fails.
Never move a tag or reuse a version. Retry a failed tag push without
changing the signed tag.

After verifying the remote tag points to the recorded commit, update the
changelog's release date, README status, and M5 release checkbox with the
tag and merged PR links. The tag does not publish a crate, binary asset, or
GitHub release. Those distribution channels require their own explicit
request and verification.
