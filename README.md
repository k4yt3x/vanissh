# VaniSSH

> [!WARNING]
> While VaniSSH is designed to be safe and uses OpenSSL for key generation, this tool has not been thoroughly audited. Other vanity key generators have had vulnerabilities in the past, such as the [Profanity vulnerability found by 1inch Network](https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool/). Know the risks before using this tool, especially for production use.

VaniSSH is a simple tool for generating vanity SSH public keys that start, contain, or end with specified strings. It searches on the CPU by default and can use an NVIDIA GPU through CUDA, which is a few hundred times faster.

<img width="1058" height="808" alt="Image" src="https://github.com/user-attachments/assets/0ae27b70-0f3f-411b-853b-8bb801bcc40c" />

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
  - The prefixes have a limited character set; not all characters are possible.

Examples:
  vanissh -s TEST
  vanissh -c 1337 -i
  vanissh -p abc -i -o id_ed25519
  vanissh -g -s TEST -o id_ed25519
```

The `-g`/`-d` options are only available when VaniSSH was built with CUDA support (see below).

## Performance

Keys per second, searching for an 8-character suffix (i.e. never finding one):

| Backend                                | Rate            |
| -------------------------------------- | --------------- |
| CPU, 32 threads (OpenSSL keygen)       | ~0.5 M keys/s   |
| CUDA, NVIDIA RTX A6000 (`-g`)          | ~250 M keys/s   |

The expected number of attempts is 64ⁿ for a case-sensitive pattern of n characters (halved for every letter in the pattern with `-i`), so on the A6000 a 5-character suffix takes about 4 seconds on average and a 6-character one about 5 minutes.

### How the GPU search works

Each Ed25519 public key is derived from a 32-byte seed as `SHA-512(seed) → clamp → scalar × base point → encode`, and there is no shortcut: unlike raw-scalar schemes, OpenSSH private keys store the seed, so every candidate needs its own hash and scalar multiplication. The CUDA kernel therefore does the whole derivation on the GPU:

- Field arithmetic mod 2^255−19 in radix 2^25.5 (ten 32-bit limbs, the ref10/donna layout), tuned around the GPU's 32×32→64 multiply-add.
- Fixed-base scalar multiplication with an 18-bit signed comb window: 15 mixed point additions per key against a 240 MiB table precomputed on the device at startup (`-Dgpu_window` trades table size for additions).
- Montgomery's batch-inversion trick, 32 keys per thread per inversion.
- Pattern matching directly on base64 sextets, so no strings are built on the GPU.

Seeds are derived by mixing a per-thread counter into a fresh 256-bit base seed from OpenSSL's CSPRNG for every kernel launch, so found keys have full entropy. The GPU only *searches*: at startup 4096 GPU-derived public keys are checked against OpenSSL, and any key the GPU reports is re-derived with OpenSSL on the host and re-matched before it is written out, so a GPU arithmetic bug can only make the search fail loudly, never produce a wrong key.

## Building

### Prerequisites

The following dependencies are required to build this project:

- C++23 compatible compiler
- Meson 1.1 or later
- libssh development libraries
- just (optional)
- Ninja (optional)
- CUDA Toolkit 12 or later with `nvcc` on `PATH` (optional, for the GPU backend)

Arch Linux:

```bash
sudo pacman -Syu base-devel meson libssh clang ninja just
sudo pacman -S cuda  # optional, GPU backend
```

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install meson libssh-dev clang ninja-build just
```

Red Hat/Fedora:

```bash
sudo dnf install meson libssh-devel clang ninja-build just
```

### Compile

If Clang, Ninja, and just are installed, you can simply run:

```bash
just
```

Alternatively, you can use Meson directly:

```bash
CXX=clang++ meson setup build --reconfigure \
    --buildtype=release \
    -Denable_native=true
meson compile -C build
```

The compiled binary will be located at `build/vanissh`. `just test` (or `meson test -C build`) runs a smoke test that generates a key with each available backend and checks it with `ssh-keygen`.

### CUDA backend

The GPU backend is built automatically when `nvcc` is found (`-Denable_cuda=auto`, the default); use `just build-cpu` or `-Denable_cuda=disabled` to build without it, or `-Denable_cuda=enabled` to fail if CUDA is unavailable. Related options:

- `-Dgpu_arch=native` (default): value passed to `nvcc -arch`. The default compiles for the GPU in the build machine; use e.g. `sm_86` or `all-major` for a portable binary.
- `-Dgpu_window=18` (default): window size in bits of the precomputed table (4–20). Each key costs ⌈256 / window⌉ point additions, while the table takes ⌈256 / window⌉ × 2^(window−1) × 128 bytes of GPU memory (240 MiB at 18). 16 needs 64 MiB and is about 4% slower; larger windows were slower on an RTX A6000.

## License

This project is licensed under [GNU AGPL version 3](https://www.gnu.org/licenses/agpl-3.0.txt).\
Copyright (C) 2025 K4YT3X.

![AGPLv3](https://www.gnu.org/graphics/agplv3-155x51.png)
