#!/bin/sh
# Runs a search for every combination of target (public key, fingerprint,
# both), pattern kind (prefix, suffix, contains and their combinations) and
# case mode, plus a few special cases, and checks every result independently:
# the public key and fingerprint are recomputed with ssh-keygen and the
# patterns are matched with shell string operations.
#
# Usage: matrix_test.sh <vanissh binary> [extra vanissh arguments...]
set -eu

vanissh=$1
shift
backend_args=$*

if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "ssh-keygen is required"
    exit 77
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
runs=0

lower() {
    printf '%s' "$1" | tr 'A-Z' 'a-z'
}

# matches <text> <prefix offset> <prefix> <suffix> <contains> <ignore case>
matches() {
    text=$1
    offset=$2
    prefix=$3
    suffix=$4
    contains=$5
    if [ "$6" = 1 ]; then
        text=$(lower "$text")
        prefix=$(lower "$prefix")
        suffix=$(lower "$suffix")
        contains=$(lower "$contains")
    fi
    if [ -n "$prefix" ]; then
        rest=$(printf '%s' "$text" | cut -c "$((offset + 1))-")
        case $rest in
            "$prefix"*) ;;
            *) return 1 ;;
        esac
    fi
    if [ -n "$suffix" ]; then
        case $text in
            *"$suffix") ;;
            *) return 1 ;;
        esac
    fi
    if [ -n "$contains" ]; then
        case $text in
            *"$contains"*) ;;
            *) return 1 ;;
        esac
    fi
    return 0
}

# run_case <key prefix> <key suffix> <key contains> <fp prefix> <fp suffix> <fp contains> <ignore case>
# The variables are prefixed because POSIX sh has no locals.
run_case() {
    r_kp=$1 r_ks=$2 r_kc=$3 r_fp=$4 r_fs=$5 r_fc=$6 r_ci=$7
    set --
    [ -n "$r_kp" ] && set -- "$@" -p "$r_kp"
    [ -n "$r_ks" ] && set -- "$@" -s "$r_ks"
    [ -n "$r_kc" ] && set -- "$@" -c "$r_kc"
    [ -n "$r_fp" ] && set -- "$@" -P "$r_fp"
    [ -n "$r_fs" ] && set -- "$@" -S "$r_fs"
    [ -n "$r_fc" ] && set -- "$@" -C "$r_fc"
    [ "$r_ci" = 1 ] && set -- "$@" -i

    runs=$((runs + 1))
    keyfile="$workdir/key$runs"
    # shellcheck disable=SC2086 # the backend arguments are meant to be split
    if ! output=$("$vanissh" $backend_args "$@" -o "$keyfile"); then
        printf 'vanissh failed for: %s\n' "$*"
        exit 1
    fi
    public_key=$(printf '%s\n' "$output" | grep '^ssh-ed25519 ')
    fingerprint=$(printf '%s\n' "$output" | grep '^SHA256:')

    derived=$(ssh-keygen -y -f "$keyfile")
    if [ "$derived" != "$public_key" ]; then
        printf 'ssh-keygen derives a different public key for %s:\n  %s\n  %s\n' \
            "$*" "$derived" "$public_key"
        exit 1
    fi
    derived=$(ssh-keygen -l -E sha256 -f "$keyfile" | cut -d ' ' -f 2)
    if [ "$derived" != "$fingerprint" ]; then
        printf 'ssh-keygen computes a different fingerprint for %s:\n  %s\n  %s\n' \
            "$*" "$derived" "$fingerprint"
        exit 1
    fi

    if ! matches "${public_key#ssh-ed25519 }" 25 "$r_kp" "$r_ks" "$r_kc" "$r_ci"; then
        printf 'public key does not match %s: %s\n' "$*" "$public_key"
        exit 1
    fi
    if ! matches "${fingerprint#SHA256:}" 0 "$r_fp" "$r_fs" "$r_fc" "$r_ci"; then
        printf 'fingerprint does not match %s: %s\n' "$*" "$fingerprint"
        exit 1
    fi
    printf 'ok: %s\n' "$*"
}

# Every combination of kinds for the key alone, the fingerprint alone and
# both, case-sensitively and (with letters of the other case) insensitively.
# The patterns are short so that every search finishes quickly.
for ci in 0 1; do
    if [ "$ci" = 0 ]; then
        p=A s=A c=A P=A S=A C=A
    else
        p=a s=b c=1 P=c S=e C=2
    fi
    for kinds in 1 2 3 4 5 6 7; do
        kp='' ks='' kc='' fp='' fs='' fc=''
        [ $((kinds & 1)) -ne 0 ] && kp=$p && fp=$P
        [ $((kinds & 2)) -ne 0 ] && ks=$s && fs=$S
        [ $((kinds & 4)) -ne 0 ] && kc=$c && fc=$C
        run_case "$kp" "$ks" "$kc" '' '' '' "$ci"
        run_case '' '' '' "$fp" "$fs" "$fc" "$ci"
        run_case "$kp" "$ks" "$kc" "$fp" "$fs" "$fc" "$ci"
    done
done

# Special cases: the constant part of the key, '+' and '/', multi-character
# and mixed-case patterns, and an allowed last fingerprint character
run_case '' '' 'AAAAC3NzaC1lZDI1NTE5AAAAI' '' '' '' 0
run_case '' '' '+' '' '' '/' 0
run_case 'Ab' '' '' '' '' '' 1
run_case '' '' '' '' 'cA' '' 0
run_case '' 'k4' '' '' 'Y' '' 1

# A pasted "SHA256:" prefix is ignored
runs=$((runs + 1))
# shellcheck disable=SC2086
output=$("$vanissh" $backend_args -P SHA256:A -o "$workdir/key$runs")
case $(printf '%s\n' "$output" | grep '^SHA256:') in
    SHA256:A*) printf 'ok: -P SHA256:A\n' ;;
    *)
        printf 'fingerprint does not start with A after stripping SHA256:\n'
        exit 1
        ;;
esac

printf '%d searches verified\n' "$runs"
