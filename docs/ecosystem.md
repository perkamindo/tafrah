# Tafrah Ecosystem

Tafrah is split into layers so that production runtime code stays Rust-native, while host integrations remain thin and replaceable.

## Core Crates

- `tafrah-ml-kem`: FIPS 203
- `tafrah-ml-dsa`: FIPS 204
- `tafrah-slh-dsa`: FIPS 205, including internal, pure/context, and HashSLH-DSA APIs
- `tafrah-falcon`: FIPS 206
- `tafrah-hqc`: FIPS 207

These crates hold the algorithm implementations and remain the most important correctness boundary.

For `tafrah-hqc`, the currently implemented sizes and serialization layouts are
aligned with the local HQC reference bundle used by this repository. HQC is
still pre-standard, so newer draft/specification snapshots may publish
different lengths.

## Shared Support Crates

- `tafrah-traits`: traits and shared error surface
- `tafrah-math`: lower-level math helpers reused by multiple schemes

`tafrah-traits::kem::Kem` is the high-level generic abstraction for fixed KEM
parameter sets. The lower-level `Encapsulate` and `Decapsulate` traits remain
useful when generic code is written around key carrier types instead of
algorithm-family marker types.

## Consumer-Facing Crates

- `tafrah`: umbrella crate for Rust consumers
- `tafrah-abi`: C ABI for universal foreign-function access across the exposed
  ML-KEM, ML-DSA, SLH-DSA, Falcon, and HQC parameter sets
- `tafrah-uniffi`: higher-level binding surface for UniFFI workflows

## Examples and Proofs

- `examples/auth-demo`: multi-language usage examples and proof scripts

## Design Intent

- Rust consumers should prefer the native crates directly.
- Non-Rust consumers should prefer the installed C ABI or a thin wrapper over it.
- UniFFI is useful for higher-level host binding workflows, but it is not the replacement for the universal ABI.
