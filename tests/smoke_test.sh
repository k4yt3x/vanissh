#!/bin/sh
# Generates a key with a trivial pattern and checks that the result is a valid,
# matching and properly protected key.
#
# Usage: smoke_test.sh <vanissh binary> [extra vanissh arguments...]
set -eu

vanissh=$1
shift

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

output=$("$vanissh" "$@" -s A -o "$workdir/key")
public_key=$(printf '%s\n' "$output" | grep '^ssh-ed25519 ')

case $public_key in
    *A) ;;
    *)
        printf 'public key does not end with the requested suffix: %s\n' "$public_key"
        exit 1
        ;;
esac

mode=$(stat -c %a "$workdir/key")
if [ "$mode" != 600 ]; then
    printf 'private key file has mode %s, expected 600\n' "$mode"
    exit 1
fi

if command -v ssh-keygen >/dev/null 2>&1; then
    derived=$(ssh-keygen -y -f "$workdir/key")
    if [ "$derived" != "$public_key" ]; then
        printf 'ssh-keygen derives a different public key:\n  %s\n  %s\n' "$derived" "$public_key"
        exit 1
    fi
fi
