#!/usr/bin/env bash
# Runs inside the virtme-ng guest that CI's `kernels` job boots, as the
# runner's own user: guest-tests.sh <results-dir> <mode>
#
# <results-dir> is shared read-write with the host. The host writes
# `manifest-dir` (the unpacked crate), `tests` (every test executable, one
# per line), and `ignored-tests` (the tests/launch.rs, tests/lock.rs, and
# tests/broker_confined.rs executables, which hold the ignored tests the
# modes below run). This script writes `<mode>.kernel` (the guest's kernel
# release) first and `<mode>.passed` last. The host requires both, so a guest
# that stops early fails the job even if virtme-ng reports success.
#
# Modes:
#   supported    every test executable, as `cargo test` would run them
#   no-landlock  the ignored `without_landlock` tests, on a kernel booted
#                with `lsm=capability`
#   below-floor  the ignored `below_landlock_v3` tests, on a kernel whose
#                Landlock ABI is below v3 (Linux 6.1)
set -euo pipefail

results=$1
mode=$2

# Runs the ignored tests whose names contain <filter> and requires exactly
# <expected> of them to pass, because a filter that matched nothing would
# pass too: run_ignored <filter> <expected>
run_ignored() {
    local filter=$1 expected=$2 passed=0 test output count
    local -a tests
    mapfile -t tests <"$results/ignored-tests"
    for test in "${tests[@]}"; do
        output=$("$test" --ignored "$filter")
        printf '%s\n' "$output"
        # A test that runs this executable again as a child prints the
        # child's summary first, so only the last summary is this run's.
        count=$(sed --quiet 's/^test result: ok\. \([0-9]*\) passed;.*/\1/p' <<<"$output" | tail -n 1)
        # Bash abandons the whole `case` below on an arithmetic error and
        # goes on to write `<mode>.passed`, so check the count first.
        if ! [[ $count =~ ^[0-9]+$ ]]; then
            echo "$test printed no passing summary" >&2
            exit 1
        fi
        passed=$((passed + count))
    done
    if [ "$passed" -ne "$expected" ]; then
        echo "expected $expected passing *$filter* tests, got $passed" >&2
        exit 1
    fi
}

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
    # Two launcher tests, three lock tests, and one confined broker test.
    run_ignored without_landlock 6
    ;;
below-floor)
    # Two lock tests and one confined broker test.
    run_ignored below_landlock_v3 3
    ;;
*)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac

touch "$results/$mode.passed"
