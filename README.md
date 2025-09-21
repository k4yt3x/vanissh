# VaniSSH

> [!WARNING]
> While VaniSSH is designed to be safe and uses OpenSSL for key generation, this tool has not been thoroughly audited. Other vanity key generators have had vulnerabilities in the past, such as the [Profanity vulnerability found by 1inch Network](https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool/). Know the risks before using this tool, especially for production use.

VaniSSH is a simple tool for generating vanity SSH public keys that start, contain, or end with specified strings.

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
```

## Building

### Prerequisites

The following dependencies are required to build this project:

- C++23 compatible compiler
- Meson 1.1 or later
- libssh development libraries
- just (optional)
- Ninja (optional)

Arch Linux:

```bash
sudo pacman -Syu base-devel meson libssh clang ninja just
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
    -Denable_native=true \
    -Denable_fast_math=true
meson compile -C build
```

The compiled binary will be located at `build/vanissh`.

## License

This project is licensed under [GNU AGPL version 3](https://www.gnu.org/licenses/agpl-3.0.txt).\
Copyright (C) 2025 K4YT3X.

![AGPLv3](https://www.gnu.org/graphics/agplv3-155x51.png)
