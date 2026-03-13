# Install

This document describes how to build, install, and validate `tafrah` from the workspace root.

## Prerequisites

- Rust stable toolchain
- `make`
- `clang` or an equivalent C/C++ toolchain
- `pkg-config` for C, C++, and Go consumers using the install layout

Optional tools for examples and host bindings:

- Python 3
- Node.js with development headers
- Go
- Java JDK
- Kotlin compiler

## Build the Rust Workspace

Run the full workspace test suite:

```sh
make test
```

Run the default reference-oracle suite:

```sh
make test-reference
```

Run the deeper FIPS 205 SPHINCS+ reference audit:

```sh
make test-deep-slh
```

Build debug artifacts:

```sh
make build
```

## Build and Install the C ABI

Install `tafrah-abi` into a local prefix:

```sh
make install PREFIX="$PWD/dist/install"
```

Or call the installer script directly:

```sh
sh ./scripts/install-abi.sh "$PWD/dist/install"
```

Installed files:

- `dist/install/lib/`
- `dist/install/include/tafrah/`
- `dist/install/lib/pkgconfig/tafrah.pc`

The install prefix contains both a shared ABI library and a static ABI library:

- Linux: `libtafrah_abi.so` and `libtafrah_abi.a`
- macOS: `libtafrah_abi.dylib` and `libtafrah_abi.a`
- Windows: `tafrah_abi.dll` and `tafrah_abi.lib`

## Build UniFFI

Build the UniFFI shared library:

```sh
make build-uniffi
```

Generate bindings:

```sh
make generate-uniffi UNIFFI_LANGUAGE=python
```

Common languages:

- `python`
- `kotlin`
- `swift`

## Run the Examples

Run the multi-language example bundle:

```sh
make examples
```

Run the richer Python proof:

```sh
make demo-python
```

## Platform Notes

- GitHub Release assets are architecture-specific, not universal.
- The current hosted release/CI matrix targets:
  - Linux `x86_64`
  - Linux `aarch64`
  - macOS `arm64`
  - macOS `x86_64`
  - Windows `x86_64`
- If no matching GitHub Release asset exists for the target machine, build from source:

```sh
make test
make install PREFIX="$PWD/dist/install"
```

- Rust consumers should use the native `tafrah` crate directly instead of going through the C ABI layer.
