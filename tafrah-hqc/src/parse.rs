//! Public parsing and serialization helpers for HQC wire formats.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::params::Params;
use crate::sampling::{random_vector_from_seed, secret_vectors_from_seed, words_to_bytes_le};
use crate::types::{Ciphertext, DecapsulationKey, EncapsulationKey};
use tafrah_traits::Error;

/// Length in bytes of the HQC seed fields used in public and secret keys.
pub const HQC_SEED_BYTES: usize = 40;
/// Length in bytes of the `d` digest field embedded in HQC ciphertexts.
pub const HQC_D_BYTES: usize = 64;
/// Length in bytes of the HQC ciphertext salt.
pub const HQC_SALT_BYTES: usize = 16;

#[derive(Clone)]
pub struct PublicKeyParts {
    /// Seed that expands to the public vector `h`.
    pub seed: [u8; HQC_SEED_BYTES],
    /// Expanded public vector `h`.
    pub h: Vec<u64>,
    /// Public syndrome vector `s`.
    pub s: Vec<u64>,
}

#[derive(Clone)]
pub struct SecretKeyParts {
    /// Seed that expands to the secret vectors.
    pub seed: [u8; HQC_SEED_BYTES],
    /// Embedded public key bytes stored in the secret key encoding.
    pub public_key: EncapsulationKey,
    /// Secret sparse vector `x`.
    pub x: Vec<u64>,
    /// Secret sparse vector `y`.
    pub y: Vec<u64>,
}

#[derive(Clone)]
pub struct CiphertextParts {
    /// First ciphertext component.
    pub u: Vec<u64>,
    /// Second ciphertext component.
    pub v: Vec<u64>,
    /// Hash-based integrity digest.
    pub d: [u8; HQC_D_BYTES],
    /// Per-ciphertext salt value.
    pub salt: [u8; HQC_SALT_BYTES],
}

fn words_from_bytes_le(bytes: &[u8], word_count: usize) -> Vec<u64> {
    let mut words = vec![0u64; word_count];
    for (index, chunk) in bytes.chunks(8).enumerate() {
        let mut padded = [0u8; 8];
        padded[..chunk.len()].copy_from_slice(chunk);
        words[index] = u64::from_le_bytes(padded);
    }
    words
}

/// Parses an encoded HQC public key into structured components.
pub fn parse_public_key(ek: &EncapsulationKey, params: &Params) -> Result<PublicKeyParts, Error> {
    params.validate()?;
    if ek.bytes.len() != params.pk_bytes {
        return Err(Error::InvalidKeyLength);
    }

    let mut seed = [0u8; HQC_SEED_BYTES];
    seed.copy_from_slice(&ek.bytes[..params.seed_bytes]);
    let s = words_from_bytes_le(&ek.bytes[params.seed_bytes..], params.vec_n_size_u64());
    let h = random_vector_from_seed(&seed, params);

    Ok(PublicKeyParts { seed, h, s })
}

/// Encodes structured HQC public key parts into the wire format.
pub fn encode_public_key(
    parts: &PublicKeyParts,
    params: &Params,
) -> Result<EncapsulationKey, Error> {
    params.validate()?;
    let s_bytes = words_to_bytes_le(&parts.s, params.vec_n_size_bytes());
    if s_bytes.len() != params.vec_n_size_bytes() {
        return Err(Error::InvalidKeyLength);
    }

    let mut bytes = Vec::with_capacity(params.pk_bytes);
    bytes.extend_from_slice(&parts.seed);
    bytes.extend_from_slice(&s_bytes);
    Ok(EncapsulationKey { bytes })
}

/// Parses an encoded HQC secret key into structured components.
pub fn parse_secret_key(dk: &DecapsulationKey, params: &Params) -> Result<SecretKeyParts, Error> {
    params.validate()?;
    if dk.bytes.len() != params.sk_bytes {
        return Err(Error::InvalidKeyLength);
    }

    let mut seed = [0u8; HQC_SEED_BYTES];
    seed.copy_from_slice(&dk.bytes[..params.seed_bytes]);
    let public_key = EncapsulationKey {
        bytes: dk.bytes[params.seed_bytes..].to_vec(),
    };
    let (x, y) = secret_vectors_from_seed(&seed, params);

    Ok(SecretKeyParts {
        seed,
        public_key,
        x,
        y,
    })
}

/// Encodes structured HQC secret key parts into the wire format.
pub fn encode_secret_key(
    parts: &SecretKeyParts,
    params: &Params,
) -> Result<DecapsulationKey, Error> {
    params.validate()?;
    if parts.public_key.bytes.len() != params.pk_bytes {
        return Err(Error::InvalidKeyLength);
    }

    let mut bytes = Vec::with_capacity(params.sk_bytes);
    bytes.extend_from_slice(&parts.seed);
    bytes.extend_from_slice(&parts.public_key.bytes);
    Ok(DecapsulationKey { bytes })
}

/// Parses an encoded HQC ciphertext into structured components.
pub fn parse_ciphertext(ct: &Ciphertext, params: &Params) -> Result<CiphertextParts, Error> {
    params.validate()?;
    if ct.bytes.len() != params.ct_bytes {
        return Err(Error::InvalidCiphertextLength);
    }

    let u_bytes = params.vec_n_size_bytes();
    let v_bytes = params.vec_n1n2_size_bytes();
    let d_start = u_bytes + v_bytes;
    let salt_start = d_start + HQC_D_BYTES;

    let u = words_from_bytes_le(&ct.bytes[..u_bytes], params.vec_n_size_u64());
    let v = words_from_bytes_le(&ct.bytes[u_bytes..d_start], params.vec_n1n2_size_u64());

    let mut d = [0u8; HQC_D_BYTES];
    d.copy_from_slice(&ct.bytes[d_start..salt_start]);

    let mut salt = [0u8; HQC_SALT_BYTES];
    salt.copy_from_slice(&ct.bytes[salt_start..]);

    Ok(CiphertextParts { u, v, d, salt })
}

/// Encodes structured HQC ciphertext parts into the wire format.
pub fn encode_ciphertext(parts: &CiphertextParts, params: &Params) -> Result<Ciphertext, Error> {
    params.validate()?;
    let u_bytes = words_to_bytes_le(&parts.u, params.vec_n_size_bytes());
    let v_bytes = words_to_bytes_le(&parts.v, params.vec_n1n2_size_bytes());

    if u_bytes.len() != params.vec_n_size_bytes() || v_bytes.len() != params.vec_n1n2_size_bytes() {
        return Err(Error::InvalidCiphertextLength);
    }

    let mut bytes = Vec::with_capacity(params.ct_bytes);
    bytes.extend_from_slice(&u_bytes);
    bytes.extend_from_slice(&v_bytes);
    bytes.extend_from_slice(&parts.d);
    bytes.extend_from_slice(&parts.salt);
    Ok(Ciphertext { bytes })
}
