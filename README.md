# Tafrah

[![CI](https://github.com/perkamindo/tafrah/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/perkamindo/tafrah/actions/workflows/ci.yml)
[![Coverage](https://github.com/perkamindo/tafrah/actions/workflows/coverage.yml/badge.svg?branch=master)](https://github.com/perkamindo/tafrah/actions/workflows/coverage.yml)

Tafrah is a Rust-native post-quantum cryptography workspace covering [FIPS `203`, `204`, and `205`](https://csrc.nist.gov/Projects/post-quantum-cryptography) together with [FIPS `206` and `207`](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms), which NIST lists as selected algorithms with `FIPS coming soon` status.

The repository is organized around three layers:

- Native Rust crates for Rust consumers and `no_std`-friendly core implementations.
- An installable C ABI in `tafrah-abi` for language wrappers and systems integration.
- UniFFI bindings and example wrappers for higher-level host integrations.

## Library Layout

- `tafrah/`: umbrella crate for Rust consumers.
- `tafrah-ml-kem/`: FIPS 203 ML-KEM.
- `tafrah-ml-dsa/`: FIPS 204 ML-DSA.
- `tafrah-slh-dsa/`: FIPS 205 SLH-DSA.
- `tafrah-falcon/`: FIPS 206 Falcon.
- `tafrah-hqc/`: FIPS 207 HQC.
- `tafrah-abi/`: installable C ABI and headers.
- `tafrah-uniffi/`: UniFFI-facing wrapper crate.
- `tafrah-traits/`: shared traits and common error surface.
- `examples/auth-demo/`: beginner-oriented cross-language implementation examples.
- `docs/`: architecture, integration, and API documentation.

## Quick Start

```sh
make test
make install PREFIX="$PWD/dist/install"
make examples
```

Common root targets:

- `make test`
- `make test-reference`
- `make test-deep-slh`
- `make coverage`
- `make build`
- `make build-abi`
- `make build-uniffi`
- `make install`
- `make examples`
- `make demo-python`
- `make generate-uniffi UNIFFI_LANGUAGE=python`

## Documentation

- [INSTALL.md](INSTALL.md)
- [docs/README.md](docs/README.md)
- [CHANGELOG.md](CHANGELOG.md)

## Examples

Beginner-friendly examples and proof scripts live in [examples/README.md](examples/README.md).

The primary example bundle is [examples/auth-demo/README.md](examples/auth-demo/README.md). It includes:

- a direct Rust crate example
- a Python `ctypes` wrapper
- C++, Go, Java, Kotlin, and JavaScript bindings over the C ABI
- a richer Python proof script for chat, file encryption, signatures, and small benchmarks

## Install Layout

`tafrah-abi` installs into a prefix with the following layout:

- `lib/libtafrah_abi.{so,dylib}` or `tafrah_abi.dll`
- `include/tafrah/tafrah.h`
- `include/tafrah/tafrah.hpp`
- `include/tafrah_abi.h`
- `include/tafrah_ffi.h` as a compatibility shim
- `lib/pkgconfig/tafrah.pc`

For a local install:

```sh
make install PREFIX="$PWD/dist/install"
```
