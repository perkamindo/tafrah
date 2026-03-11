# Tafrah Ecosystem

Tafrah is split into layers so that production runtime code stays Rust-native, while host integrations remain thin and replaceable.

## Core Crates

- `tafrah-ml-kem`: FIPS 203
- `tafrah-ml-dsa`: FIPS 204
- `tafrah-slh-dsa`: FIPS 205
- `tafrah-falcon`: FIPS 206
- `tafrah-hqc`: FIPS 207

These crates hold the algorithm implementations and remain the most important correctness boundary.

## Shared Support Crates

- `tafrah-traits`: traits and shared error surface
- `tafrah-math`: lower-level math helpers reused by multiple schemes

## Consumer-Facing Crates

- `tafrah`: umbrella crate for Rust consumers
- `tafrah-abi`: C ABI for universal foreign-function access
- `tafrah-uniffi`: higher-level binding surface for UniFFI workflows

## Examples and Proofs

- `examples/auth-demo`: multi-language usage examples and proof scripts

## Design Intent

- Rust consumers should prefer the native crates directly.
- Non-Rust consumers should prefer the installed C ABI or a thin wrapper over it.
- UniFFI is useful for higher-level host binding workflows, but it is not the replacement for the universal ABI.
