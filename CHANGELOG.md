# Changelog

All notable changes to Tafrah are documented in this file.

## [0.1.7] - 2026-03-13

### Added

- Added opt-in SIMD backends in `tafrah-math` for ML-KEM and ML-DSA polynomial kernels:
  - `avx2` for x86/x86_64 hosts with runtime AVX2 detection
  - `neon` for AArch64 hosts
- Added a benchmark crate and root targets for scalar and SIMD measurements:
  - `make bench`
  - `make bench-json`
  - `make bench-avx2`
  - `make bench-avx2-json`
  - `make bench-neon`
  - `make bench-neon-json`
- Added CI coverage for SIMD benchmarking on GitHub-hosted x64 runners through a dedicated `simd-bench` job.

### Changed

- Refined the example implementations so shared-secret comparisons use constant-time equality where practical and key-derivation examples use stricter framing and HMAC-SHA3-256 based derivation.
- Documented the current SIMD validation boundary, including the fact that SVE is not yet implemented and Apple Silicon validation targets Neon instead.
- Synchronized all public workspace crate versions, ABI metadata, and user-visible version strings to `0.1.7`.

### Fixed

- Hardened example language integrations to avoid stale native-library loading and weaker byte-comparison patterns.
- Kept SIMD dispatch parity-safe by validating every new backend against the scalar NTT and pointwise reference kernels before exposing it through public dispatch.

## [0.1.6] - 2026-03-12

### Added

- Expanded the FIPS 204 ML-DSA oracle parity harness to cover deterministic deep-count audits against the native ML-DSA reference surface, including an `all counts` release-mode audit target.
- Added deterministic sampling regression coverage in `tafrah-math` for ML-KEM and ML-DSA seed-driven sampling helpers.

### Changed

- Aligned all public crate versions, ABI metadata, and release packaging metadata to the coordinated `0.1.6` workspace release.
- Documented `tafrah-math` explicitly as a deterministic foundational layer that keeps entropy sourcing in the scheme and host layers instead of depending on `rand` directly.
- Added a repository-level warning that FIPS 206 and FIPS 207 remain based on currently available specifications until NIST publishes final standards.

### Fixed

- Prevented the default ML-DSA reference test target from drifting behind the shipped API by wiring `mldsa_native_reference` into `make test-reference`.
- Removed the hard-coded temporary checkout assumption from the deep ML-DSA audit target so release verification can discover the reference repository through the existing fallback logic.

## [0.1.5] - 2026-03-12

### Added

- Completed the public FIPS 205 SLH-DSA surface with deterministic internal key generation, pure/context signing and verification, and HashSLH-DSA pre-hash wrappers.
- Added deeper SPHINCS+ / FIPS 205 reference-oracle coverage for all 12 parameter sets, pre-hash algorithms, and selected deep-count KAT checks.

### Changed

- Renamed the FIPS 205 reference harness and user-facing documentation to refer to SPHINCS+ / FIPS 205 reference validation rather than an external repository label.
- Updated `make test-deep-slh` and the API overview so the documented SLH-DSA surface matches the code that is actually shipped.

### Fixed

- Corrected FORS base-`2^a` index extraction to match the FIPS 205 bit ordering.
- Corrected ADRS type-transition handling so `set_type`, `set_type_and_clear`, and the key-pair-preserving variant follow the expected SPHINCS+ semantics.

## [0.1.4] - 2026-03-12

### Fixed

- Re-exported the shared KEM traits, signature traits, and common `Error` type from the `tafrah` umbrella crate so crate-root documentation links resolve internally on docs.rs.
- Removed the broken crate-root links that previously pointed into a non-existent `tafrah_traits` path under the `tafrah` docs namespace.

## [0.1.3] - 2026-03-12

### Changed

- Expanded the `tafrah` crate root documentation into a sectioned, docs.rs-friendly guide covering standards, API selection, feature flags, quick-start examples, `no_std`, error handling, and ecosystem layers.
- Added clickable links from the umbrella crate documentation into the shared trait and error documentation so the crate root acts as a practical navigation hub.

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
- Current FIPS 205 SPHINCS+ reference parity for all 12 standard parameter sets at `count=0`, plus a deeper selected-count audit.
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
