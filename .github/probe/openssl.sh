#!/usr/bin/env bash
# Probe only, never merged: openssl.sh <broker>
#
# On Fedora, whether OpenSSL's configuration still applies to a confined
# worker that can read /etc/pki/tls/openssl3.cnf but not what it includes.
set -u
broker=$1
data=$(mktemp -d)
out=$(mktemp -d)
HOME=$(mktemp -d)
export HOME
cd /

echo "## /etc/pki/tls/openssl3.cnf without comments"
grep -Ev '^[[:space:]]*(#|$)' /etc/pki/tls/openssl3.cnf
ls -la /etc/pki/tls /etc/pki/tls/openssl.d
for f in /etc/pki/tls/openssl.d/*; do
    if [ -f "$f" ]; then
        echo "## $f -> $(readlink -f "$f")"
        cat "$f"
    fi
done
echo "## /etc/crypto-policies"
cat /etc/crypto-policies/config
ls -la /etc/crypto-policies/back-ends
echo "## openssl.config backend"
cat /etc/crypto-policies/back-ends/openssl.config
echo "## opensslcnf.config backend"
cat /etc/crypto-policies/back-ends/opensslcnf.config

python=$(command -v python3)
node=$(command -v node)
openssl=$(command -v openssl)
py='import ssl; c = ssl.create_default_context(); print("python", len(c.get_ciphers()), c.minimum_version, "seclevel", c.security_level)'
js='console.log("node", require("tls").getCiphers().length, require("tls").DEFAULT_MIN_VERSION)'

variant() {
    local name=$1
    shift
    echo "### $name"
    run "$name.py" "$@" -- "$python" -c "$py"
    run "$name.js" "$@" -- "$node" -e "$js"
    run "$name.ossl" "$@" -- "$openssl" ciphers -s
}

run() {
    local trace=$out/$1
    shift
    local flags=()
    while [ "$1" != -- ]; do
        flags+=("$1")
        shift
    done
    shift
    strace -f -qq -Z -e trace=%file -o "$trace" \
        "$broker" "${flags[@]}" --grant "$data:r" -- "$@" >"$trace.out" 2>"$trace.err"
    local code=$?
    echo "-- ${trace##*/}: exit $code"
    if [[ $trace == *.ossl ]]; then
        tr ':' '\n' <"$trace.out" | wc -l | sed 's/^/ciphers: /'
    else
        head -c 400 "$trace.out"
    fi
    head -c 600 "$trace.err"
    grep -E '= -1 EACCES' "$trace" \
        | sed -nE 's/^[0-9]+ +([a-z0-9_]+)\([^"]*"([^"]+)".*/  refused \1 \2/p' \
        | grep -v ' /proc/' | sort -u
}

variant unconfined --unconfined
variant defaults
variant openssl.d --direct /etc/pki/tls/openssl.d:rl
variant openssl.d+policies --direct /etc/pki/tls/openssl.d:rl \
    --direct /etc/crypto-policies:rl
