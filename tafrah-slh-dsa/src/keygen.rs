/// Generic SLH-DSA key generation entry point.
///
/// Implements FIPS 205 Algorithm 18.

extern crate alloc;
use alloc::vec::Vec;

use crate::address::Adrs;
use crate::params::Params;
use crate::types::{SigningKey, VerifyingKey};
use crate::xmss;
use tafrah_traits::Error;

/// Deterministically derives an SLH-DSA key pair from explicit seed material.
///
/// This matches FIPS 205 Algorithm 18 and the deterministic SPHINCS+ / SLH-DSA
/// internal key-generation surface.
pub fn slh_keygen_internal(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    params: &Params,
) -> Result<(VerifyingKey, SigningKey), Error> {
    params.validate()?;
    let n = params.n;

    if sk_seed.len() != n || sk_prf.len() != n || pk_seed.len() != n {
        return Err(Error::InvalidParameter);
    }

    // Compute root of the top XMSS tree (layer d-1).
    let mut adrs = Adrs::new();
    adrs.set_layer_address((params.d - 1) as u32);
    let pk_root = xmss::xmss_treehash(sk_seed, pk_seed, 0, params.hp as u32, &mut adrs, params);

    let mut sk_bytes = Vec::with_capacity(4 * n);
    sk_bytes.extend_from_slice(sk_seed);
    sk_bytes.extend_from_slice(sk_prf);
    sk_bytes.extend_from_slice(pk_seed);
    sk_bytes.extend_from_slice(&pk_root);

    let mut pk_bytes = Vec::with_capacity(2 * n);
    pk_bytes.extend_from_slice(pk_seed);
    pk_bytes.extend_from_slice(&pk_root);

    Ok((
        VerifyingKey { bytes: pk_bytes },
        SigningKey { bytes: sk_bytes },
    ))
}

/// Generates an SLH-DSA verifying key and signing key pair.
pub fn slh_dsa_keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    params: &Params,
) -> Result<(VerifyingKey, SigningKey), Error> {
    params.validate()?;
    let n = params.n;

    // Match the reference KAT flow: draw SK.seed || SK.prf || PK.seed in one RNG call.
    let mut seed_material = alloc::vec![0u8; 3 * n];
    rng.fill_bytes(&mut seed_material);
    let sk_seed = &seed_material[..n];
    let sk_prf = &seed_material[n..2 * n];
    let pk_seed = &seed_material[2 * n..3 * n];
    slh_keygen_internal(sk_seed, sk_prf, pk_seed, params)
}
