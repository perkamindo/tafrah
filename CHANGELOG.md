# Changelog

All notable changes to Tafrah are documented in this file.

## [0.1.2] - 2026-03-12

### Fixed

- Removed the obsolete `doc_auto_cfg` nightly gate from the umbrella crate so docs.rs can build `tafrah` on current nightly toolchains.
- Kept docs.rs configured for `all-features`, preserving Falcon and HQC visibility in the umbrella documentation without relying on removed nightly features.

## [0.1.1] - 2026-03-12

### Changed

- Configured `tafrah` docs.rs builds to use all crate features so the umbrella documentation includes Falcon and HQC re-exports.
- Enabled `docsrs` rustdoc configuration for clearer feature-gated API presentation in the umbrella crate documentation.

## [0.1.0] - 2026-03-12

### Highlights

- First tagged workspace release of Tafrah as a Rust-native post-quantum cryptography library covering FIPS 203, 204, 205, 206, and 207.
- Native Rust implementations are available for ML-KEM, ML-DSA, SLH-DSA, Falcon, and HQC, with `no_std`-friendly core crates.
- The repository now ships an installable `tafrah-abi` layer, a UniFFI integration path, and beginner-oriented implementation examples for Python, C++, Go, Java, Kotlin, JavaScript, and Rust.

### Added

- Final ML-KEM oracle parity against `liboqs` `mlkem-native` for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
- Default-on ML-DSA oracle verification against `dilithium-master/ref` for ML-DSA-44, ML-DSA-65, and ML-DSA-87.
- Current-reference SLH-DSA deterministic parity against `sphincsplus-master/ref` for all 12 standard parameter sets at `count=0`, plus a deeper selected-count audit.
- Full all-count HQC reference reconstruction and decapsulation coverage for HQC-128, HQC-192, and HQC-256.
- Multi-language implementation examples in `examples/auth-demo`.
- Root-level build, install, examples, and coverage entry points through `make`.
- GitHub Actions workflows for CI, coverage, and tagged release packaging.

### Changed

- Generic parameter validation now exists across the core scheme crates for ML-KEM, ML-DSA, SLH-DSA, Falcon, and HQC.
- The public interoperability boundary is documented and shipped as `tafrah-abi`, while `tafrah_ffi.h` remains as a compatibility shim for existing consumers.
- SLH-DSA key generation and signing now return `Result`, matching the hardened direction already applied in the generic ML-KEM and ML-DSA APIs.
- Falcon remains pure Rust only; no C backend is part of the runtime crate.

### Fixed

- Public signing, verification, encapsulation, and decapsulation paths reject malformed serialized inputs more consistently instead of relying on unchecked slicing.
- Falcon signatures in the C ABI now report `sig_written` instead of forcing a fixed detached signature length.
- Several stale warning sources in debug and test code were removed during the release hardening pass.

### Verification

- `cargo test` passes for the full workspace.
- Reference-oracle coverage passes for ML-KEM, ML-DSA, SLH-DSA, Falcon, and HQC at the documented validation depth.
- Cross-language examples build and run locally through `make examples`.
- Tagged GitHub releases publish Linux and macOS install archives.

## [0.0.0] - 2021-12-08

### Added

- Introduced `tafrah-math` as the original foundation layer for NTT, polynomial arithmetic, finite-field operations, sampling, matrix utilities, and compression helpers.
- Established the first reusable math and encoding primitives that later became the base for the wider Tafrah workspace.

### Changed

- Organized the early math implementation into the dedicated `tafrah-math/` directory for clearer separation and future expansion.
