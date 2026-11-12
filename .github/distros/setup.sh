#!/bin/sh
# Runs as root inside the container that CI's `distros` job starts, before
# test.sh: setup.sh <system>
#
# Installs a Rust toolchain and a C compiler from the system's own packages,
# so the test binaries link the way that system's programs do: against its
# libc, and through its dynamic loader.
set -eu

if [ $# -ne 1 ]; then
    echo "usage: setup.sh <debian|fedora|arch|alpine|nix>" >&2
    exit 2
fi

case $1 in
debian)
    apt-get update
    apt-get install --yes --no-install-recommends \
        ca-certificates cargo gcc libc6-dev rustc
    ;;
fedora)
    dnf install --assumeyes cargo gcc rust
    ;;
arch)
    pacman -Syu --noconfirm gcc rust
    ;;
alpine)
    # Alpine's own rustc links against musl dynamically, through
    # /lib/ld-musl-x86_64.so.1. The musl target from rustup links statically
    # instead, which would not test the loader.
    apk add --no-cache cargo gcc musl-dev rust
    ;;
nix)
    # The `nixos/nix` image lays programs out as NixOS does: each one, its
    # loader, and its libraries are in /nix/store, and /bin/sh links there.
    # The image has no Rust toolchain, so build one from a pinned nixpkgs
    # release and name its directories in /etc/fsgate-test-path for test.sh,
    # which runs as a user with no profile.
    nixpkgs=github:NixOS/nixpkgs/ac588ef1c914865dad517b337ea0eb9694a4021c
    nix --extra-experimental-features 'nix-command flakes' build \
        --no-link --print-out-paths \
        "$nixpkgs#cargo" "$nixpkgs#rustc" "$nixpkgs#gcc" \
        "$nixpkgs#binutils" "$nixpkgs#coreutils" >/tmp/outputs
    path=
    while read -r output; do
        if [ -d "$output/bin" ]; then
            path=${path:+$path:}$output/bin
        fi
    done </tmp/outputs
    echo "$path:/bin:/usr/bin" >/etc/fsgate-test-path
    ;;
*)
    echo "setup.sh: unknown system '$1'; use debian, fedora, arch, alpine, or nix" >&2
    exit 2
    ;;
esac
