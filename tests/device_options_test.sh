#!/bin/sh
# Device-list parsing is checked with CUDA hidden, so no GPU is required.
set -eu
export LC_ALL=C
vanissh=$1

run_failure() {
    if output=$(CUDA_VISIBLE_DEVICES='' "$vanissh" -s A "$@" 2>&1); then
        printf 'unexpected success for device options: %s\n' "$*"
        exit 1
    fi
}

expect_error() {
    expected=$1
    shift
    run_failure "$@"
    case $output in
        *"$expected"*) ;;
        *) printf 'unexpected error for %s:\n%s\n' "$*" "$output"; exit 1 ;;
    esac
}

# A CUDA build may run on CI without an NVIDIA driver installed. Valid selectors
# must reach device discovery, which then reports either no devices or a driver error.
expect_backend_error() {
    run_failure "$@"
    case $output in
        *'no CUDA devices are available'*|*'CUDA error (cudaGetDeviceCount):'*|*'does not include CUDA support'*) ;;
        *) printf 'unexpected error for %s:\n%s\n' "$*" "$output"; exit 1 ;;
    esac
}

for value in '' ',' ',0' '0,' '0,,1' '-1' '0,-1' '1x' '0,1x' '2147483648' 'all,0' '0,all' 'ALL'; do
    expect_error "GPUs must be 'all' or a comma-separated list of non-negative indices" -g "$value"
done
expect_error 'selected more than once' -g 0,0
expect_error 'selected more than once' --gpus=0,1,0
expect_error 'requires an argument' -g
expect_error 'requires an argument' --gpus
expect_error 'invalid option' -d 0
expect_error 'unrecognized option' --device 0
expect_error 'Unexpected argument: 1' -g 0 1

# Well-formed lists should reach backend selection in CUDA and CPU-only builds.
expect_backend_error -g all
expect_backend_error -g 0
expect_backend_error -g 0,1
expect_backend_error --gpus all
expect_backend_error --gpus=0,1
expect_backend_error -g0,1
expect_backend_error -g 0 -g 0
expect_backend_error -g 0 -g all
expect_backend_error -g all -g 0
printf 'device selection options verified\n'
