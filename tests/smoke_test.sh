#!/bin/sh
# Generates keys with trivial public key and fingerprint patterns and checks
# that each result is a valid, matching and properly protected key.
#
# Usage: smoke_test.sh <vanissh binary> [extra vanissh arguments...]
set -eu

vanissh=$1
shift
backend_args=$*

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
run=0

# check_key <key suffix> <fingerprint suffix> <vanissh pattern options...>
check_key() {
    key_suffix=$1
    fingerprint_suffix=$2
    shift 2
    run=$((run + 1))
    keyfile="$workdir/key$run"

    # shellcheck disable=SC2086 # the backend arguments are meant to be split
    output=$("$vanissh" $backend_args "$@" -o "$keyfile")
    public_key=$(printf '%s\n' "$output" | grep '^ssh-ed25519 ')
    fingerprint=$(printf '%s\n' "$output" | grep '^SHA256:')

    case $public_key in
        *"$key_suffix") ;;
        *)
            printf 'public key does not end with "%s": %s\n' "$key_suffix" "$public_key"
            exit 1
            ;;
    esac
    case $fingerprint in
        *"$fingerprint_suffix") ;;
        *)
            printf 'fingerprint does not end with "%s": %s\n' "$fingerprint_suffix" "$fingerprint"
            exit 1
            ;;
    esac

    mode=$(stat -c %a "$keyfile")
    if [ "$mode" != 600 ]; then
        printf 'private key file has mode %s, expected 600\n' "$mode"
        exit 1
    fi

    if command -v ssh-keygen >/dev/null 2>&1; then
        derived=$(ssh-keygen -y -f "$keyfile")
        if [ "$derived" != "$public_key" ]; then
            printf 'ssh-keygen derives a different public key:\n  %s\n  %s\n' \
                "$derived" "$public_key"
            exit 1
        fi
        derived=$(ssh-keygen -l -E sha256 -f "$keyfile" | cut -d ' ' -f 2)
        if [ "$derived" != "$fingerprint" ]; then
            printf 'ssh-keygen computes a different fingerprint:\n  %s\n  %s\n' \
                "$derived" "$fingerprint"
            exit 1
        fi
    fi
}

check_key A '' -s A
check_key '' A -S A
check_key A A -s A -S A
