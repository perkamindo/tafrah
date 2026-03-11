# Build and Install

This guide describes the main build entrypoints from the repository root.

## Root Commands

The repository is intentionally organized so that common actions start from the root:

- `make test`
- `make test-reference`
- `make build`
- `make build-abi`
- `make build-uniffi`
- `make install PREFIX=...`
- `make examples`
- `make demo-python`

## Typical Native Rust Workflow

```sh
make test
```

This runs the full workspace test suite.

## Typical ABI Workflow

```sh
make install PREFIX="$PWD/dist/install"
```

That installs:

- `include/tafrah/tafrah.h`
- `include/tafrah/tafrah.hpp`
- `include/tafrah_abi.h`
- `include/tafrah_ffi.h` compatibility shim
- `lib/libtafrah_abi.{so,dylib}` or `tafrah_abi.dll`
- `lib/pkgconfig/tafrah.pc`

Consumers that support `pkg-config` can use the installed prefix directly.

## Typical Example Workflow

```sh
make install PREFIX="$PWD/dist/install"
make examples
```

That path is the closest thing to an end-to-end repository smoke test for non-Rust consumers.
