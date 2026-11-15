#!/usr/bin/env bash
# Probe only, never merged: etc.sh <broker>
#
# Starts common programs as a confined worker. A program that fails is run
# again with `--direct` for every file under /etc it was refused, until it
# passes or is refused nothing new, so each system shows the set it needs.
set -u
broker=$1
data=$(mktemp -d)
out=$(mktemp -d)
# The nixos/nix image's `nobody` has /var/empty for a home.
HOME=$(mktemp -d)
export HOME
cd /

# run <trace> [broker flags...] -- <command...>; sets `code`.
run() {
    local trace=$1
    shift
    local flags=()
    while [ "$1" != -- ]; do
        flags+=("$1")
        shift
    done
    shift
    strace -f -qq -Z -e trace=%file,%network -o "$trace" \
        "$broker" "${flags[@]}" --grant "$data:r" -- "$@" >"$trace.out" 2>"$trace.err"
    code=$?
}

# Paths the trace shows refused with EACCES whose name or target is under
# /etc.
refused_etc() {
    grep -E '= -1 EACCES' "$1" \
        | sed -nE 's/^[0-9]+ +[a-z0-9_]+\([^"]*"([^"]+)".*/\1/p' \
        | sort -u \
        | while read -r path; do
            real=$(readlink -f "$path" 2>/dev/null || echo "$path")
            case "$path:$real" in
            /etc/* | *:/etc/*) echo "$path" ;;
            esac
        done
}

show() {
    echo "--- $1: exit $code"
    head -c 400 "$2.out"
    head -c 800 "$2.err"
    echo "refused:"
    grep -E '= -1 (EACCES|EPERM)' "$2" \
        | sed -nE 's/^[0-9]+ +([a-z0-9_]+)\(([^"]*"([^"]+)")?.*= -1 (E[A-Z]+).*/  \1 \3 \4/p' \
        | sort -u
}

rows=()
probe() {
    local name=$1
    shift
    echo "::group::$name"
    run "$out/$name.u" --unconfined -- "$@"
    show "$name unconfined" "$out/$name.u"
    local unconfined=$code first='' round=0 direct=() names=()
    while :; do
        run "$out/$name.$round" "${direct[@]}" -- "$@"
        show "$name confined, round $round: ${names[*]:-defaults}" "$out/$name.$round"
        [ -z "$first" ] && first=$code
        if [ "$code" = 0 ] || [ "$round" -ge 8 ]; then
            break
        fi
        local added=0 path letters
        while read -r path; do
            [ -n "$path" ] || continue
            case " ${names[*]:-} " in *" $path "*) continue ;; esac
            letters=r
            [ -d "$(readlink -f "$path")" ] && letters=rl
            direct+=(--direct "$path:$letters")
            names+=("$path")
            added=1
        done < <(refused_etc "$out/$name.$round")
        [ "$added" = 1 ] || break
        round=$((round + 1))
    done
    echo "::endgroup::"
    rows+=("| \`$name\` | $unconfined | $first | $code | ${names[*]:-} |")
}

# shellcheck source=/dev/null
echo "system: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
uname -m -r
id
for f in /etc/ssl/openssl.cnf /usr/lib/ssl/openssl.cnf /etc/pki/tls/openssl.cnf \
    /etc/pki/tls/openssl3.cnf /etc/resolv.conf /etc/nsswitch.conf /etc/hosts \
    /etc/gitconfig /etc/localtime /etc/passwd /etc/group \
    /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-bundle.crt; do
    if [ -e "$f" ] || [ -L "$f" ]; then
        ls -l "$f"
    fi
done
node=$(command -v node || command -v nodejs || true)
if [ -n "$node" ]; then
    echo "node $("$node" --version)"
fi
git --version
curl --version | head -n 1
python3 --version

probe date "$(command -v date)" +%Z
probe id "$(command -v id)" -un
if command -v getent >/dev/null; then
    probe getent-hosts "$(command -v getent)" hosts github.com
fi
probe curl "$(command -v curl)" -sS -o /dev/null -w '%{http_code}\n' https://github.com
probe python-https "$(command -v python3)" -c \
    'import urllib.request; print(urllib.request.urlopen("https://github.com").status)'
probe git-ls-remote "$(command -v git)" ls-remote https://github.com/farming-labs/fsgate HEAD
if [ -n "$node" ]; then
    probe node-start "$node" -e 'console.log(1)'
    probe node-fetch "$node" -e 'fetch("https://github.com").then(r => console.log(r.status))'
fi

echo
echo "| Program | Unconfined | Defaults | Final | --direct added |"
echo "|---|---|---|---|---|"
printf '%s\n' "${rows[@]}"
