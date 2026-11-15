#!/bin/sh
# Probe only, never merged. Runs as root in the container: setup.sh <system>
# Installs the system's own toolchain and programs, builds fsgate-broker
# into /opt/target, adds the unprivileged user `probe` where it can, and
# writes the PATH the probe runs with to /etc/fsgate-probe-path.
set -eu
echo /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin >/etc/fsgate-probe-path
case $1 in
debian)
    apt-get update
    apt-get install --yes --no-install-recommends ca-certificates cargo rustc gcc \
        libc6-dev strace nodejs git curl python3
    useradd -m -u 2000 probe
    ;;
fedora)
    dnf install --assumeyes cargo rust gcc strace nodejs git curl python3 shadow-utils \
        openssl
    useradd -m -u 2000 probe
    ;;
arch)
    pacman -Syu --noconfirm rust gcc strace nodejs git curl python
    useradd -m -u 2000 probe
    ;;
alpine)
    apk add --no-cache cargo rust gcc musl-dev strace nodejs git curl python3 bash \
        ca-certificates
    adduser -D -u 2000 probe
    ;;
nix)
    # The same nixpkgs as CI's distros job. Every program, and the probe's
    # own tools, come from /nix/store.
    nixpkgs=github:NixOS/nixpkgs/ac588ef1c914865dad517b337ea0eb9694a4021c
    nix --extra-experimental-features 'nix-command flakes' build \
        --no-link --print-out-paths \
        "$nixpkgs#cargo" "$nixpkgs#rustc" "$nixpkgs#gcc" "$nixpkgs#binutils" \
        "$nixpkgs#coreutils" "$nixpkgs#gnused" "$nixpkgs#gnugrep" \
        "$nixpkgs#bashInteractive" "$nixpkgs#strace" "$nixpkgs#nodejs" \
        "$nixpkgs#git" "$nixpkgs#curl" "$nixpkgs#python3" "$nixpkgs#getent" \
        >/tmp/outputs
    path=
    while read -r output; do
        if [ -d "$output/bin" ]; then
            path=${path:+$path:}$output/bin
        fi
    done </tmp/outputs
    echo "$path:/bin:/usr/bin" >/etc/fsgate-probe-path
    PATH=$path:$PATH
    export PATH
    mkdir -p /opt
    echo "/etc/passwd -> $(readlink -f /etc/passwd)"
    grep '^nobody:' /etc/passwd
    ls -la /etc
    ;;
*)
    echo "setup.sh: unknown system '$1'" >&2
    exit 2
    ;;
esac
CARGO_TARGET_DIR=/opt/target cargo build --locked --bin fsgate-broker
chmod -R a+rX /opt/target
