# VaniSSH

> [!WARNING]
> VaniSSH generates keys with OpenSSL, but it has not been independently audited. Other vanity key generators have shipped serious vulnerabilities before, such as [Profanity](https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool/). Understand the risks before using a vanity key for anything important.

VaniSSH generates Ed25519 SSH keys whose public key or SHA-256 fingerprint starts with, ends with, or contains strings of your choice. It generates random keys until one matches, so the result is an ordinary key that happens to look the way you want.

<img width="1058" height="808" alt="VaniSSH screenshot" src="https://github.com/user-attachments/assets/0ae27b70-0f3f-411b-853b-8bb801bcc40c" />

## Features

- **Prefix, suffix and substring matching** on the public key, on its SHA-256 fingerprint, or on both at once, case-sensitive or not.
- **CPU backend** built on OpenSSL, using every core.
- **CUDA backend** that runs the whole key derivation on the GPU: about 250 million keys per second on an RTX A6000, roughly 500 times a Ryzen 9 5950X.
- **Multi-GPU search** uses all visible GPUs or a selected subset, stopping at the first verified match.
- **Verified results**: every key found on the GPU is re-derived with OpenSSL before it is accepted.
- **OpenSSH key format** output with owner-only permissions, ready for `~/.ssh`.

## Installation

Download the Linux x86-64 binary from [GitHub Releases](https://github.com/k4yt3x/vanissh/releases/latest) and put `vanissh` on your `PATH`. It needs glibc 2.35 or newer (Ubuntu 22.04, Debian 12 and later); the GPU backend needs an NVIDIA driver with CUDA 13 support (R580 or newer). Other platforms can build from source, see [Building](#building).

## Usage

```console
Usage: vanissh [OPTIONS]

Generate Ed25519 SSH keys whose public key or SHA-256 fingerprint starts with,
ends with, or contains the strings you choose.

Options:
  -p, --prefix PREFIX                Desired prefix of the base64 public key
  -s, --suffix SUFFIX                Desired suffix of the base64 public key
  -c, --contains STRING              String that must appear anywhere in the
                                       base64 public key
  -P, --fingerprint-prefix PREFIX    Desired prefix of the SHA-256 fingerprint
  -S, --fingerprint-suffix SUFFIX    Desired suffix of the SHA-256 fingerprint
  -C, --fingerprint-contains STRING  String that must appear anywhere in the
                                       SHA-256 fingerprint
  -j, --threads NUM                  Number of threads to use (default: auto)
  -g, --gpus DEVICES                 CUDA GPUs to use: 'all' or comma-separated
                                       indices (e.g. 0,2); default: CPU
  -o, --output FILE                  Output private key to file (default: stdout)
  -i, --ignore-case                  Case-insensitive matching
  -h, --help                         Show this help message

Notes:
  - At least one pattern must be specified; all given patterns must match.
  - Ed25519 public keys always start with 'AAAAC3NzaC1lZDI1NTE5AAAAI', which is
      skipped when matching prefixes. The character after it is one of A-P.
  - Fingerprint patterns apply to the 43 characters after 'SHA256:', the last
      of which is one of A E I M Q U Y c g k o s w 0 4 8.

Examples:
  vanissh -s TEST
  vanissh -c 1337 -i
  vanissh -p abc -i -o id_ed25519
  vanissh -S cafe -i
  vanissh -g all -s TEST -o id_ed25519
  vanissh -g 0,2 -s TEST
```

`-g`/`--gpus` is only available when VaniSSH was built with CUDA support (see [Building](#building)).

The CPU is used unless `-g`/`--gpus` is specified. Use `-g all` for every GPU visible
to CUDA, `-g 0` for one GPU, or `-g 0,2` for a subset. A selector is required; if
the option is repeated, the last selector is used. Indices refer to the devices
visible to the process, including any remapping by `CUDA_VISIBLE_DEVICES`;
duplicate indices in a list are rejected.
Each GPU searches independently with fresh random seeds. The first match verified
by OpenSSL stops the search, and other GPUs finish their current launch before
exiting. The attempt count and progress rate include all selected GPUs.
A failure on any selected GPU stops the entire search and reports the device.

### Examples

```bash
vanissh -s TEST                   # public key ends with "TEST"
vanissh -c cafe -i                # public key contains "cafe" in any case
vanissh -p abc -i -o id_ed25519   # public key starts with "abc", private key saved to id_ed25519
vanissh -S cafe -i                # fingerprint ends with "cafe" in any case
vanissh -P k4y -i -c 1337         # fingerprint starts with "k4y" and the public key contains "1337"
vanissh -g all -s TEST           # search on all visible GPUs
vanissh -g 0 -s TEST             # search on GPU 0
vanissh -g 0,2 -s TEST           # search on GPUs 0 and 2
```

The private key goes to stdout unless `--output` is given; the file is created with mode 0600 and never overwritten. The public key and its fingerprint are always printed.

### Matching rules

- Patterns use base64 characters only: `A-Z`, `a-z`, `0-9`, `+` and `/`.
- Every Ed25519 public key starts with `AAAAC3NzaC1lZDI1NTE5AAAAI`. `--prefix` matches what follows, and the first character after it is always one of `A-P`.
- Fingerprint patterns apply to the 43 characters after `SHA256:`. The last character is always one of `A E I M Q U Y c g k o s w 0 4 8`. A pasted `SHA256:` prefix is ignored.
- All given patterns must match the same key. Patterns that can never match are rejected up front.

## Performance

Every character multiplies the expected number of attempts by 64 (32 for a letter matched case-insensitively), on the public key and the fingerprint alike. Measured rates:

| Backend | Keys per second |
| --- | --- |
| CPU, AMD Ryzen 9 5950X (16 cores / 32 threads, OpenSSL) | ~0.5 million |
| CUDA, NVIDIA RTX A6000 (`-g all`) | ~250 million |

Expected search times for a case-sensitive pattern of a given length:

| Characters | Expected attempts | RTX A6000 | Ryzen 9 5950X |
| --- | --- | --- | --- |
| 4 | 16.8 M | < 1 s | 34 s |
| 5 | 1.1 G | 4 s | 36 min |
| 6 | 68.7 G | 5 min | 38 h |
| 7 | 4.4 T | 4.9 h | 102 days |
| 8 | 281.5 T | 13 days | 17.9 years |
| 9 | 18.0 P | 2.3 years | 1142.5 years |

Fingerprint patterns cost about 5% on the GPU and nothing measurable on the CPU. Combined with a public key pattern, the search runs at the public key rate.

## Security

- **Entropy.** CPU keys come from OpenSSL's key generation. GPU keys are derived from a fresh 256-bit seed drawn from OpenSSL's CSPRNG for every launch, so every candidate is a uniformly random 256-bit value.
- **Verification.** At startup 4096 keys from each selected GPU are compared with OpenSSL, and every key a GPU reports is re-derived and re-matched with OpenSSL before it is written. A GPU bug can only make the search fail, never produce a wrong key.
- **Key files** are created with mode 0600 and never overwritten.

## Building

Requires a C++23 compiler, Meson 1.1 or later, Ninja and the OpenSSL development files. CUDA Toolkit 12 or later is optional for the GPU backend, [just](https://github.com/casey/just) for the recipes below.

```bash
sudo pacman -S base-devel meson openssl clang ninja just cuda        # Arch Linux (cuda optional)
sudo apt install meson ninja-build pkg-config clang libssl-dev just  # Debian/Ubuntu
sudo dnf install meson ninja-build pkgconf clang openssl-devel just  # Fedora
```

```bash
just            # release build, GPU backend included when nvcc is found
just build-cpu  # release build without the GPU backend
just test       # run the tests
```

Or with Meson directly:

```bash
CXX=clang++ meson setup build --buildtype=release
meson compile -C build
```

The binary is `build/vanissh`.

### Build options

- `-Denable_native=true` (default): compile for the CPU of the build machine.
- `-Denable_cuda=auto` (default): build the GPU backend when `nvcc` is found; `disabled` skips it, `enabled` requires it.
- `-Dgpu_arch=native` (default): value passed to `nvcc -arch`; use `all-major` for a portable binary.
- `-Dgpu_window=18` (default): size of the precomputed GPU table, 4–20 bits. 18 uses 224 MiB of GPU memory; 16 uses 64 MiB.

## AI use declaration

AI tools have been used to assist the design and implementation of this project since version 2.0.0, which added the CUDA backend; earlier releases were written entirely by hand. Every AI-assisted change was reviewed and approved by a human maintainer.

## License

This project is licensed under [GNU AGPL version 3](https://www.gnu.org/licenses/agpl-3.0.txt).\
Copyright (C) 2025-2026 K4YT3X.

![AGPLv3](https://www.gnu.org/graphics/agplv3-155x51.png)
