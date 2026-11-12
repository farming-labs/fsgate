#!/bin/sh
# Fails when a development shell in flake.nix has a different version of a
# tool than the workflow that pins it, so that passing in `nix develop`
# means passing with CI's tools. Run from the repository root wherever
# `nix` can build the shells. Uses no sed: the nixos/nix image has none.
set -eu

nix() {
    command nix --extra-experimental-features 'nix-command flakes' "$@"
}

status=0
err=$(mktemp)
trap 'rm -f "$err"' EXIT

# Prints the version in the one match of an extended regular expression in
# a workflow, or exits if there is not exactly one.
pin() {
    file=.github/workflows/$1
    matches=$(grep -oE "$2" "$file") || {
        echo "no pin matching '$2' in $file; update $0" >&2
        exit 1
    }
    if [ "$(printf '%s\n' "$matches" | wc -l)" -ne 1 ]; then
        echo "more than one pin matching '$2' in $file; update $0" >&2
        exit 1
    fi
    printf '%s\n' "$matches" | grep -oE "$3"
}

# Runs a command in a shell and requires its output to name a version as a
# whole word.
check() {
    shell=$1 want=$2
    shift 2
    # Only the command's own output: Nix reports its downloads on stderr,
    # and their store paths name versions too.
    got=$(nix develop --no-update-lock-file ".#$shell" --command "$@" 2>"$err") || {
        cat "$err" >&2
        echo "\`$*\` failed in .#$shell" >&2
        exit 1
    }
    got=$(printf '%s\n' "$got" | head -n 1)
    if [ -n "$got" ] && printf '%s\n' "$got" | grep -Fqw -- "$want"; then
        echo "ok: \`$*\` in .#$shell: $got"
    else
        echo "\`$*\` in .#$shell reports '$got', but CI pins $want" >&2
        status=1
    fi
}

msrv=$(pin ci.yml 'toolchain: [0-9]+\.[0-9]+\.[0-9]+' '[0-9.]+$')
nightly=$(pin fuzz.yml 'toolchain: nightly-[0-9-]+' '[0-9]{4}-[0-9]{2}-[0-9]{2}$')
cargo_fuzz=$(pin fuzz.yml 'cargo-fuzz --locked --version [0-9.]+' '[0-9.]+$')
cargo_mutants=$(pin mutants.yml 'cargo-mutants --locked --version [0-9.]+' '[0-9.]+$')
# actionlint-py's fourth number is its own packaging release.
actionlint=$(pin ci.yml 'actionlint-py==[0-9.]+' '[0-9]+\.[0-9]+\.[0-9]+')
zizmor=$(pin ci.yml 'zizmor==[0-9.]+' '[0-9.]+$')

# Every system's shells must evaluate, not only this one's.
nix flake check --no-update-lock-file --all-systems --no-build

check msrv "$msrv" rustc --version
check fuzz "$cargo_fuzz" cargo fuzz --version
check default "$cargo_mutants" cargo mutants --version
check default "$actionlint" actionlint --version
check default "$zizmor" zizmor --version

# A nightly's rustc reports its commit date, which is not the nightly's
# date, so check the toolchain the shell was built from.
system=$(nix eval --impure --raw --expr builtins.currentSystem)
toolchain=$(nix eval --no-update-lock-file --raw ".#devShells.$system.fuzz" \
    --apply 's: builtins.concatStringsSep " " (map (p: p.name) s.nativeBuildInputs)')
if printf '%s\n' "$toolchain" | grep -Fqw -- "nightly-$nightly"; then
    echo "ok: .#fuzz has $toolchain"
else
    echo ".#fuzz has $toolchain, but CI pins nightly-$nightly" >&2
    status=1
fi
check fuzz nightly rustc --version

# Unpinned in CI, so only shown: CI's `stable` is the current release,
# and CI uses the runner's shellcheck.
for command in 'rustc --version' 'cargo fmt --version' 'cargo clippy --version' 'shellcheck --version'; do
    # shellcheck disable=SC2086
    printf '.#default: %s\n' "$(nix develop --no-update-lock-file .#default --command $command | head -n 2 | tr '\n' ' ')"
done

exit "$status"
