use crate::params::ML_DSA_65;
use crate::types::*;
use tafrah_traits::Error;

/// Generates an `ML-DSA-65` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> (VerifyingKey, SigningKey) {
    crate::keygen::ml_dsa_keygen(rng, &ML_DSA_65)
        .expect("fixed ML-DSA-65 parameter set must be valid")
}

/// Generates an `ML-DSA-65` keypair from a caller-supplied seed.
pub fn keygen_internal(seed: &[u8; 32]) -> (VerifyingKey, SigningKey) {
    crate::keygen::ml_dsa_keygen_internal(seed, &ML_DSA_65)
        .expect("fixed ML-DSA-65 parameter set must be valid")
}

/// Signs a message with `ML-DSA-65`.
pub fn sign(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Signature {
    crate::sign::ml_dsa_sign(sk, msg, rng, &ML_DSA_65)
        .expect("fixed ML-DSA-65 parameter set must be valid")
}

/// Signs a message with `ML-DSA-65` and a context string.
pub fn sign_with_context(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<Signature, Error> {
    crate::sign::ml_dsa_sign_with_context(sk, msg, ctx, rng, &ML_DSA_65)
}

/// Signs a message with the deterministic `ML-DSA-65` variant.
pub fn sign_deterministic(sk: &SigningKey, msg: &[u8]) -> Result<Signature, Error> {
    crate::sign::ml_dsa_sign_deterministic(sk, msg, &ML_DSA_65)
}

/// Signs a message with the deterministic `ML-DSA-65` variant and context.
pub fn sign_deterministic_with_context(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
) -> Result<Signature, Error> {
    crate::sign::ml_dsa_sign_deterministic_with_context(sk, msg, ctx, &ML_DSA_65)
}

/// Signs an externally supplied `mu` value with `ML-DSA-65`.
pub fn sign_extmu(
    sk: &SigningKey,
    mu: &[u8; 64],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<Signature, Error> {
    crate::sign::ml_dsa_sign_extmu(sk, mu, rng, &ML_DSA_65)
}

/// Deterministically signs an externally supplied `mu` value with `ML-DSA-65`.
pub fn sign_extmu_deterministic(sk: &SigningKey, mu: &[u8; 64]) -> Result<Signature, Error> {
    crate::sign::ml_dsa_sign_extmu_deterministic(sk, mu, &ML_DSA_65)
}

/// Signs a message using the SHAKE256 HashML-DSA convenience API.
pub fn sign_prehash_shake256(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<Signature, Error> {
    crate::sign::ml_dsa_sign_prehash_shake256(sk, msg, ctx, rng, &ML_DSA_65)
}

/// Deterministically signs a message using the SHAKE256 HashML-DSA API.
pub fn sign_prehash_shake256_deterministic(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
) -> Result<Signature, Error> {
    crate::sign::ml_dsa_sign_prehash_shake256_deterministic(sk, msg, ctx, &ML_DSA_65)
}

/// Signs and returns `signature || message` for `ML-DSA-65`.
pub fn sign_message(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<SignedMessage, Error> {
    crate::sign::ml_dsa_sign_message(sk, msg, rng, &ML_DSA_65)
}

/// Signs and returns `signature || message` for `ML-DSA-65` with context.
pub fn sign_message_with_context(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<SignedMessage, Error> {
    crate::sign::ml_dsa_sign_message_with_context(sk, msg, ctx, rng, &ML_DSA_65)
}

/// Verifies an `ML-DSA-65` signature.
pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    crate::verify::ml_dsa_verify(vk, msg, sig, &ML_DSA_65)
}

/// Verifies an `ML-DSA-65` signature with a context string.
pub fn verify_with_context(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    ctx: &[u8],
) -> Result<(), Error> {
    crate::verify::ml_dsa_verify_with_context(vk, msg, sig, ctx, &ML_DSA_65)
}

/// Verifies an `ML-DSA-65` signature over an externally supplied `mu`.
pub fn verify_extmu(vk: &VerifyingKey, mu: &[u8; 64], sig: &Signature) -> Result<(), Error> {
    crate::verify::ml_dsa_verify_extmu(vk, mu, sig, &ML_DSA_65)
}

/// Verifies a SHAKE256 HashML-DSA signature for `ML-DSA-65`.
pub fn verify_prehash_shake256(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    ctx: &[u8],
) -> Result<(), Error> {
    crate::verify::ml_dsa_verify_prehash_shake256(vk, msg, sig, ctx, &ML_DSA_65)
}

/// Verifies and opens a signed `ML-DSA-65` message.
pub fn open_signed_message(
    vk: &VerifyingKey,
    signed_message: &SignedMessage,
) -> Result<alloc::vec::Vec<u8>, Error> {
    crate::verify::ml_dsa_open_signed_message(vk, signed_message, &ML_DSA_65)
}

/// Verifies and opens a signed `ML-DSA-65` message with context.
pub fn open_signed_message_with_context(
    vk: &VerifyingKey,
    signed_message: &SignedMessage,
    ctx: &[u8],
) -> Result<alloc::vec::Vec<u8>, Error> {
    crate::verify::ml_dsa_open_signed_message_with_context(vk, signed_message, ctx, &ML_DSA_65)
}
