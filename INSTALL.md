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

Run the deeper SLH-DSA current-reference audit:

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

- The primary hosted CI targets are currently macOS and Ubuntu.
- Windows support remains part of the release plan, but the main workflow is intentionally focused first on the macOS and Linux release path.
- Rust consumers should use the native `tafrah` crate directly instead of going through the C ABI layer.
