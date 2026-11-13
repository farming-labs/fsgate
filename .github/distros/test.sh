#!/bin/sh
# Runs inside the container that CI's `distros` job starts, as the runner's
# own user, after setup.sh: test.sh
#
# Runs tests/broker_confined.rs, whose confined workers start the test
# executable and /bin/sh under the worker's default rules (RFC 0008), with
# no `--direct`. The checkout is the working directory.
set -eu

if [ -f /etc/fsgate-test-path ]; then
    PATH=$(cat /etc/fsgate-test-path)
    export PATH
fi
# The runner's user has no entry in the container's /etc/passwd.
HOME=$(mktemp -d)
export HOME

if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    echo "system: $PRETTY_NAME"
else
    # The nixos/nix image has none.
    echo "system: no /etc/os-release"
fi
uname -m -r
rustc --version
cargo --version

# The loader and the libraries the worker must be able to open, which is
# what the default rules have to cover on this system.
if ! cargo test --locked --test broker_confined --no-run 2>"$HOME/build"; then
    cat "$HOME/build" >&2
    exit 1
fi
cat "$HOME/build"
test_exe=$(sed -n 's/.*Executable tests\/broker_confined\.rs (\(.*\))$/\1/p' "$HOME/build")
if [ -z "$test_exe" ]; then
    echo "test.sh: cargo printed no tests/broker_confined.rs executable" >&2
    exit 1
fi
for program in "$test_exe" /bin/sh; do
    resolved=$(readlink -f "$program")
    echo "$program -> $resolved"
    readelf --string-dump=.interp "$resolved" | sed -n 's/^ *\[ *[0-9a-f]*\] *//p'
    readelf --dynamic "$resolved" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/  needs \1/p'
done

cargo test --locked --test broker_confined
