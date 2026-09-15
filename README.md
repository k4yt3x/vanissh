# VaniSSH

> [!WARNING]
> VaniSSH generates keys with OpenSSL, but it has not been independently audited. Other vanity key generators have shipped serious vulnerabilities before, such as [Profanity](https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool/). Understand the risks before using a vanity key for anything important.

VaniSSH generates Ed25519 SSH keys whose public key starts with, ends with, or contains a string of your choice. It keeps generating random keys until one matches, so the result is an ordinary, fully random key that just happens to look the way you want.

<img width="1058" height="808" alt="VaniSSH screenshot" src="https://github.com/user-attachments/assets/0ae27b70-0f3f-411b-853b-8bb801bcc40c" />

## Features

- **Prefix, suffix and substring matching**, case-sensitive or not, in any combination.
- **CPU backend** built on OpenSSL, using every core.
- **CUDA backend** that runs the whole key derivation on the GPU: about 250 million keys per second on an NVIDIA RTX A6000, roughly 500 times a 16-core Ryzen 9 5950X.
- **Verified results**: every key found on the GPU is re-derived with OpenSSL before it is accepted.
- **OpenSSH key format** output, written with owner-only permissions and ready for `~/.ssh`.

## Usage

```console
Usage: vanissh [OPTIONS]

Generate vanity SSH public keys that start/end with specified strings.

Options:
  -p, --prefix PREFIX    Desired prefix for the base64 public key
  -s, --suffix SUFFIX    Desired suffix for the base64 public key
  -c, --contains STRING  String that must appear anywhere in the base64 public key
  -j, --threads NUM      Number of threads to use (default: auto)
  -g, --gpu              Search on the GPU with CUDA instead of the CPU
  -d, --device NUM       CUDA device index to use; implies --gpu (default: 0)
  -o, --output FILE      Output private key to file (default: stdout)
  -i, --ignore-case      Case-insensitive matching
  -h, --help             Show this help message

Notes:
  - At least one of --prefix, --suffix, or --contains must be specified.
  - Ed25519 public keys will always start with 'AAAAC3NzaC1lZDI1NTE5AAAAI',
      which will be skipped when matching prefixes.
  - The first character after that prefix is always one of A-P.

Examples:
  vanissh -s TEST
  vanissh -c 1337 -i
  vanissh -p abc -i -o id_ed25519
  vanissh -g -s TEST -o id_ed25519
```

`-g` and `-d` are only available when VaniSSH was built with CUDA support (see [Building](#building)).

### What can be matched

A public key line looks like this:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIYMqZbWhipIEuqToLPmHzM2y9YXd0YV3H8sZLO8TEST
            └──────── fixed ────────┘└─────────────── variable ────────────────┘
```

The first 25 characters encode the key type and length and are the same for every Ed25519 key, so `--prefix` matches what comes right after them. The first variable character can only be `A` to `P`, because it shares a base64 group with the constant key-length byte; VaniSSH rejects prefixes that can never occur. `--suffix` and `--contains` apply to the whole 68-character string. Patterns may only use base64 characters (`A-Z`, `a-z`, `0-9`, `+`, `/`).

### Examples

```bash
vanissh -s TEST                   # public key ends with "TEST"
vanissh -c cafe -i                # contains "cafe" in any combination of cases
vanissh -p abc -i -o id_ed25519   # starts with "abc" in any case, private key saved to id_ed25519
vanissh -g -s TEST -o id_ed25519  # the same search on the GPU
```

The private key is printed to stdout unless `--output` is given, in which case the file is created with mode 0600; an existing file is never overwritten. The public key is always printed, and can also be recovered from the private key with `ssh-keygen -y -f id_ed25519`.

## Performance

Every additional character multiplies the expected number of attempts by 64 (or by 32 for a letter matched case-insensitively). Measured rates, searching for a pattern that never matches:

| Backend | Keys per second |
| --- | --- |
| CPU, AMD Ryzen 9 5950X (16 cores / 32 threads, OpenSSL) | ~0.5 million |
| CUDA, NVIDIA RTX A6000 (`-g`) | ~250 million |

Expected search times for a case-sensitive pattern of a given length:

| Characters | Expected attempts | RTX A6000 | Ryzen 9 5950X |
| --- | --- | --- | --- |
| 4 | 16.8 M | < 1 s | 34 s |
| 5 | 1.1 G | 4 s | 36 min |
| 6 | 68.7 G | 5 min | 38 h |
| 7 | 4.4 T | 4.9 h | 102 days |

Both backends are unaffected by which of `--prefix`, `--suffix` or `--contains` is used.

## How it works

An Ed25519 public key is derived from its 32-byte seed as `SHA-512(seed) → clamp → scalar × base point → encode`, and there is no shortcut: OpenSSH private keys store the seed, not the scalar, so every candidate needs its own hash and scalar multiplication. VaniSSH simply does this as fast as possible.

The CPU backend generates keys with OpenSSL on every core and matches their base64 form. The CUDA backend runs the whole derivation on the GPU:

- field arithmetic mod 2²⁵⁵ − 19 in radix 2^25.5 (ten 32-bit limbs, the ref10/donna layout), built around the GPU's 32×32→64-bit multiply-add;
- fixed-base scalar multiplication with an 18-bit signed comb window, i.e. 15 point additions per key against a 240 MiB table computed on the device at startup;
- Montgomery's batch-inversion trick, sharing one field inversion between 32 keys per thread;
- matching directly on base64 sextets, so no strings are built on the GPU.

## Security

- **Entropy.** CPU keys come straight from OpenSSL's key generation. GPU keys are derived from a fresh 256-bit base seed drawn from OpenSSL's private CSPRNG for every kernel launch, with a per-candidate counter mixed in; every candidate seed is therefore a uniformly random 256-bit value.
- **Verification.** The GPU only searches. At startup, 4096 GPU-derived public keys are compared with OpenSSL, and every key the GPU reports is re-derived and re-matched with OpenSSL on the host before it is written out. A bug in the GPU arithmetic can only make the search fail loudly, never produce a wrong key.
- **Key files** are created with mode 0600 and existing files are never overwritten.

## Building

### Prerequisites

- A C++23 compiler (Clang or GCC)
- Meson 1.1 or later and Ninja
- OpenSSL and libssh development files
- [just](https://github.com/casey/just) (optional, for the recipes below)
- CUDA Toolkit 12 or later with `nvcc` on `PATH` (optional, for the GPU backend)

Arch Linux:

```bash
sudo pacman -Syu base-devel meson libssh clang ninja just
sudo pacman -S cuda  # optional, GPU backend
```

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install meson ninja-build pkg-config clang libssl-dev libssh-dev just
```

Red Hat/Fedora:

```bash
sudo dnf install meson ninja-build pkgconf clang openssl-devel libssh-devel just
```

### Compile

With just installed:

```bash
just            # release build, GPU backend included when nvcc is found
just build-cpu  # release build without the GPU backend
just test       # run the tests
```

Or with Meson directly:

```bash
CXX=clang++ meson setup build --buildtype=release -Denable_native=true
meson compile -C build
meson test -C build
```

The binary is `build/vanissh`. The tests generate a key with each available backend and check it with `ssh-keygen`; CUDA builds additionally run unit tests that compare the GPU field arithmetic, SHA-512 and scalar multiplication against OpenSSL on adversarial inputs.

### Build options

- `-Denable_native=true` (default): compile for the CPU of the build machine (`-march=native`).
- `-Denable_cuda=auto` (default): build the GPU backend when `nvcc` is found. `disabled` skips it, `enabled` fails if CUDA is unavailable.
- `-Dgpu_arch=native` (default): value passed to `nvcc -arch`. The default compiles for the GPU in the build machine; use e.g. `sm_86` or `all-major` for a portable binary.
- `-Dgpu_window=18` (default): window size in bits of the precomputed table (4–20). Each key costs ⌈256 / window⌉ point additions, while the table takes ⌈256 / window⌉ × 2^(window−1) × 128 bytes of GPU memory: 240 MiB at 18, 64 MiB at 16 (about 4% slower). Larger windows were slower on an RTX A6000.

## AI use declaration

AI tools have been used to assist the design and implementation of this project since version 2.0.0, which added the CUDA backend; earlier releases were written entirely by hand. Every AI-assisted change was reviewed and approved by a human maintainer.

## License

This project is licensed under [GNU AGPL version 3](https://www.gnu.org/licenses/agpl-3.0.txt).\
Copyright (C) 2025-2026 K4YT3X.

![AGPLv3](https://www.gnu.org/graphics/agplv3-155x51.png)
