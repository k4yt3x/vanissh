# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-09-20

### Added

- Multi-GPU search with `-g`/`--gpus` accepting `all` or a list of device indices.

### Changed

- **Breaking:** `-g` now requires a selector; `-d`/`--device` has been removed.
- CUDA scalar multiplication folds Ed25519's fixed bits into the precomputed table.

### Fixed

- CUDA startup reports driver errors instead of treating them as missing GPUs.

## [2.1.0] - 2026-09-15

### Added

- `-P`/`-S`/`-C` match the key's SHA-256 fingerprint, alone or together with the public key.
- The fingerprint of the generated key is printed next to the public key.

## [2.0.0] - 2026-09-15

### Added

- `-g`/`--gpu` searches on an NVIDIA GPU with CUDA, hundreds of times faster than the CPU.
- `-d`/`--device` selects which GPU to use.
- Every key found on the GPU is re-derived with OpenSSL before it is accepted.
- Patterns that can never match, such as a prefix starting with `Z`, are rejected up front.
- `-j`/`--threads` and `-d`/`--device` reject values that are not numbers.
- Pre-built Linux x86-64 binaries are published on GitHub Releases for every version.
- The `enable_cuda`, `gpu_arch` and `gpu_window` build options configure the GPU backend.

### Changed

- **Breaking:** `-o`/`--output` refuses to overwrite an existing file and prints the key instead.
- Private key files are created readable by their owner only.
- `SIGTERM` stops the search the same way `SIGINT` does.

### Removed

- **Breaking:** the `enable_fast_math` build option; it never had an effect.
- libssh is no longer required to build or run VaniSSH.

### Fixed

- The private key was written as an empty file on systems with libssh 0.10, such as Ubuntu 24.04.
- Pressing Ctrl-C while progress was being printed could hang the program instead of stopping it.
- The attempt counter started at 5000 per thread before any key had been generated.

## [1.0.0] - 2025-09-21

### Added

- Searches for Ed25519 keys whose public key starts with, ends with or contains a string.
- Case-insensitive matching with `-i`, and private key output to a file with `-o`.
