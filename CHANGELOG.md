# Changelog

## 0.1.0-rc.1 - 2026-03-11

### Added

- Final ML-KEM oracle parity against `liboqs` `mlkem-native` for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
- Default-on ML-DSA oracle verification against `dilithium-master/ref` for ML-DSA-44, ML-DSA-65, and ML-DSA-87.
- Current-reference SLH-DSA deterministic parity against `sphincsplus-master/ref` for all 12 standard parameter sets at `count=0`, plus a deeper selected-count audit.
- Full all-count HQC reference reconstruction and decapsulation coverage for HQC-128, HQC-192, and HQC-256.
- Additional negative-path regression tests for SLH-DSA, Falcon, and HQC parameter validation.
- Validation summary in `VALIDATION.md`.
- Multi-language examples in `examples/auth-demo` for Python, C++, Java, Kotlin, Go, JS, and Rust.
- Local install layout for `tafrah-abi`, including `include/tafrah/`, `tafrah.hpp`, and `pkg-config`.

### Changed

- Generic parameter validation now exists across all core FIPS scheme crates:
  - ML-KEM
  - ML-DSA
  - SLH-DSA
  - Falcon
  - HQC
- SLH-DSA keygen and sign now return `Result`, matching the hardening direction already applied in ML-KEM and ML-DSA generic APIs.
- Falcon remains pure Rust only; no C backend is present in the runtime crate.
- CI now includes explicit reference-oracle coverage for the workspace.

### Fixed

- Public signing and verification paths reject malformed serialized inputs more consistently instead of relying on unchecked slicing.
- Several stale warning sources in debug and test code were removed.
- Stale Falcon `vendor` reference directory had already been removed in the prior hardening pass and is no longer part of the crate.
- `tafrah_abi.h` now defines the primary C ABI header, while `tafrah_ffi.h` remains as a compatibility shim for existing consumers.
- Falcon signatures in the C ABI now use `sig_written` instead of forcing a fixed detached signature length.

### Validation Highlights

- `cargo test` passes for the full workspace.
- Falcon deterministic KAT parity passes for all local reference counts.
- HQC all-count KAT reconstruction and decapsulation pass for all local reference counts.
- ML-KEM, ML-DSA, and SLH-DSA pass current reference-oracle parity at the documented validation depth.
