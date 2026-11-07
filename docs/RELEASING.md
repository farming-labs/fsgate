# Releasing fsgate

Each release is a signed Git tag `vX.Y.Z`, and the crate published to
crates.io is built from exactly that tagged commit. Pushing a release tag
publishes it from CI, so push one only on an explicit maintainer request.
A version bump or merged release-preparation PR is not a completed release.

The commands below set `version` once; use the release's version.

```sh
version=X.Y.Z
```

v0.1.0 was tagged while the manifest still had `publish = false`, so it was
never published. 0.1.1, the first crates.io release, was published from a
local checkout with a token; later releases publish from CI.

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

Run from the workspace root. The workspace also holds `intercept-probe`,
an unpublished Linux test crate, so packaging and publishing name
`-p fsgate` explicitly; the checks below cover both crates.

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
cargo package --locked -p fsgate
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
changing the signed tag. The push starts the publish workflow below.

## Publish to crates.io

Publishing cannot be undone: a version can be yanked but never deleted or
replaced. Pushing the signed tag starts
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
publishes that tag through crates.io trusted publishing. No long-lived
token is stored. The workflow:

1. Refuses a tag that is not annotated, does not point to a commit on
   `main`, or does not match the manifest version, with the fix in the
   error.
2. Runs `cargo test --locked` and `cargo publish --locked -p fsgate --dry-run`.
3. Exchanges the job's GitHub OIDC identity for a short-lived crates.io
   token with `rust-lang/crates-io-auth-action`, which revokes it when the
   job ends, and runs `cargo publish --locked -p fsgate`.
4. Checks that the uploaded archive, the crates.io checksum, and the
   crate downloaded from `static.crates.io` agree, and that the crate's
   `.cargo_vcs_info.json` records the tagged commit.

Watch the run with `gh run watch` and confirm the verification step passed
before recording the release. If a publish fails, fix the cause and re-run
the workflow for the same tag; never bump again or move the tag. If it
succeeded with a defect, yank it and release a new version.

### One-time setup

Until both are configured, the token exchange fails and nothing is
published:

- On crates.io, under `fsgate` → Settings → Trusted Publishing, add a
  GitHub publisher: owner `farming-labs`, repository `fsgate`, workflow
  `release.yml`, environment `crates-io`.
- On GitHub, under Settings → Environments → `crates-io`, add required
  reviewers so a pushed tag waits for approval before it publishes, and
  restrict deployments to tags matching `v*`.

### Manual fallback

Use a local token only on an explicit maintainer request when CI
publishing is unavailable. Publish from a clean checkout of the verified
tag; `git status --short` must print nothing, and never pass
`--allow-dirty`:

```sh
set -eu
git checkout --detach "v$version"
test "$(git rev-parse HEAD)" = "$release_sha"
git status --short
cargo publish --locked -p fsgate --dry-run
cargo publish --locked -p fsgate
```

Cargo reads the token from `cargo login` (`~/.cargo/credentials.toml`) or
`CARGO_REGISTRY_TOKEN` for that one command. Never put a token in a commit,
a CI log, or a shell history entry. Then run the workflow's checks by hand.
Cargo 1.99 leaves the uploaded archive at
`target/package/tmp-crate/fsgate-$version.crate` (older cargo:
`target/package/fsgate-$version.crate`); its checksum must equal the
crates.io checksum and the downloaded crate's:

```sh
curl -sf -A "fsgate-release-check" "https://crates.io/api/v1/crates/fsgate/$version" \
  | python3 -c 'import json,sys; v=json.load(sys.stdin)["version"]; print(v["num"], v["checksum"])'
curl -sfL -A "fsgate-release-check" -o "fsgate-$version.crate" \
  "https://static.crates.io/crates/fsgate/fsgate-$version.crate"
shasum -a 256 "fsgate-$version.crate"
tar -xzOf "fsgate-$version.crate" "fsgate-$version/.cargo_vcs_info.json"
```

The `sha1` in `.cargo_vcs_info.json` must equal `$release_sha`.

## Record the release

After verifying the remote tag (and the published crate, when there is
one), update the changelog's release date, the README status, and the
roadmap's release checkbox with the tag and merged PR links. The tag does
not create a GitHub release or binary asset. Those channels require their
own explicit request and verification.
