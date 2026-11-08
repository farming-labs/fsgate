#!/usr/bin/env bash
# Runs inside the virtme-ng guest that CI's `kernels` job boots, as the
# runner's own user: guest-tests.sh <results-dir> <mode>
#
# <results-dir> is shared read-write with the host. The host writes
# `manifest-dir` (the unpacked crate), `tests` (every test executable, one
# per line), and `no-landlock-tests` (the tests/launch.rs and tests/lock.rs
# executables). This script
# writes `<mode>.kernel` (the guest's kernel release) first and
# `<mode>.passed` last. The host requires both, so a guest that stops early
# fails the job even if virtme-ng reports success.
#
# Modes:
#   supported    every test executable, as `cargo test` would run them
#   no-landlock  the ignored `*_without_landlock` tests, on a kernel booted
#                with `lsm=capability`
set -euo pipefail

results=$1
mode=$2

uname -r >"$results/$mode.kernel"
# cargo runs test executables from the package root.
cd "$(cat "$results/manifest-dir")"

case $mode in
supported)
    mapfile -t tests <"$results/tests"
    for test in "${tests[@]}"; do
        "$test"
    done
    ;;
no-landlock)
    # A filter that matched nothing would pass, so require the exact count:
    # two launcher tests and three lock tests.
    expected=5
    passed=0
    mapfile -t tests <"$results/no-landlock-tests"
    for test in "${tests[@]}"; do
        output=$("$test" --ignored without_landlock)
        printf '%s\n' "$output"
        count=$(sed --quiet 's/^test result: ok\. \([0-9]*\) passed;.*/\1/p' <<<"$output")
        passed=$((passed + ${count:-0}))
    done
    if [ "$passed" -ne "$expected" ]; then
        echo "expected $expected passing *_without_landlock tests, got $passed" >&2
        exit 1
    fi
    ;;
*)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac

touch "$results/$mode.passed"
