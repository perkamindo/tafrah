# API Overview

This document maps the public-facing workspace surface to the main modules, traits, and helper types.

## Umbrella Crate

The `tafrah` crate re-exports the major scheme crates behind feature flags:

- `tafrah::ml_kem`
- `tafrah::ml_dsa`
- `tafrah::slh_dsa`
- `tafrah::falcon`
- `tafrah::hqc`
- `tafrah::traits`

## Shared Traits

`tafrah-traits` exposes:

- `tafrah_traits::Error`
- `tafrah_traits::kem::Encapsulate`
- `tafrah_traits::kem::Decapsulate`
- `tafrah_traits::dsa::SigningKey`
- `tafrah_traits::dsa::VerifyingKey`
- `tafrah_traits::serdes::Encode`
- `tafrah_traits::serdes::Decode`

## Scheme Entry Points

Fixed-parameter convenience modules expose the most common operations:

- ML-KEM: `ml_kem_512`, `ml_kem_768`, `ml_kem_1024`
- ML-DSA: `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87`
- Falcon: `falcon_512`, `falcon_1024`
- HQC: `hqc_128`, `hqc_192`, `hqc_256`

SLH-DSA exposes parameter bundles plus the full FIPS 205 generic surface:

- `keygen::slh_dsa_keygen`
- `keygen::slh_keygen_internal`
- `sign::slh_dsa_sign`
- `sign::slh_sign_internal`
- `sign::slh_sign`
- `verify::slh_dsa_verify`
- `verify::slh_verify_internal`
- `verify::slh_verify`
- `prehash::hash_slh_sign`
- `prehash::hash_slh_verify`
- constants such as `params::SLH_DSA_SHAKE_128F`

ML-DSA exposes both the detached-signature surface and the broader FIPS 204
helpers:

- `keygen::ml_dsa_keygen`
- `keygen::ml_dsa_keygen_internal`
- `sign::ml_dsa_sign`
- `sign::ml_dsa_sign_with_context`
- `sign::ml_dsa_sign_deterministic`
- `sign::ml_dsa_sign_internal`
- `sign::ml_dsa_sign_extmu`
- `sign::ml_dsa_sign_prehash`
- `sign::ml_dsa_sign_prehash_shake256`
- `sign::ml_dsa_sign_message`
- `verify::ml_dsa_verify`
- `verify::ml_dsa_verify_with_context`
- `verify::ml_dsa_verify_internal`
- `verify::ml_dsa_verify_extmu`
- `verify::ml_dsa_verify_prehash`
- `verify::ml_dsa_verify_prehash_shake256`
- `verify::ml_dsa_open_signed_message`
- constants such as `params::ML_DSA_44`

## Typical Types

Each scheme crate exposes serialized key and message carrier types in its `types` module, such as:

- encapsulation keys
- decapsulation keys
- verifying keys
- signing keys
- ciphertexts
- signatures
- shared secrets

## Error Handling

The common error surface includes:

- invalid serialized length
- invalid parameter bundle
- decode failure
- RNG failure
- verification failure

The public API is designed to return these errors instead of panicking on malformed serialized inputs.
