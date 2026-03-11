//! Generic HQC key generation entry points.

use crate::arithmetic::{cyclic_product_mod_xn_minus_1, vector_add};
use crate::params::Params;
use crate::parse::{
    encode_public_key, encode_secret_key, PublicKeyParts, SecretKeyParts, HQC_SEED_BYTES,
};
use crate::sampling::{random_vector_from_seed, secret_vectors_from_seed};
use crate::types::{DecapsulationKey, EncapsulationKey};
use tafrah_traits::Error;

/// Deterministically derives an HQC keypair from explicit secret and public seeds.
pub fn hqc_keygen_from_seeds(
    sk_seed: &[u8; HQC_SEED_BYTES],
    pk_seed: &[u8; HQC_SEED_BYTES],
    params: &Params,
) -> Result<(EncapsulationKey, DecapsulationKey), Error> {
    params.validate()?;
    let (x, y) = secret_vectors_from_seed(sk_seed, params);
    let h = random_vector_from_seed(pk_seed, params);
    let s = vector_add(&x, &cyclic_product_mod_xn_minus_1(&y, &h, params));

    let public_key = encode_public_key(
        &PublicKeyParts {
            seed: *pk_seed,
            h,
            s,
        },
        params,
    )?;
    let secret_key = encode_secret_key(
        &SecretKeyParts {
            seed: *sk_seed,
            public_key: public_key.clone(),
            x,
            y,
        },
        params,
    )?;

    Ok((public_key, secret_key))
}

/// Generates an HQC keypair from fresh randomness.
pub fn hqc_keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    params: &Params,
) -> Result<(EncapsulationKey, DecapsulationKey), Error> {
    params.validate()?;
    let mut sk_seed = [0u8; HQC_SEED_BYTES];
    let mut pk_seed = [0u8; HQC_SEED_BYTES];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut pk_seed);
    hqc_keygen_from_seeds(&sk_seed, &pk_seed, params)
}
