use crate::params::ML_DSA_44;
use crate::types::*;
use tafrah_traits::Error;

/// Generates an `ML-DSA-44` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> (VerifyingKey, SigningKey) {
    crate::keygen::ml_dsa_keygen(rng, &ML_DSA_44)
        .expect("fixed ML-DSA-44 parameter set must be valid")
}

/// Signs a message with `ML-DSA-44`.
pub fn sign(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Signature {
    crate::sign::ml_dsa_sign(sk, msg, rng, &ML_DSA_44)
        .expect("fixed ML-DSA-44 parameter set must be valid")
}

/// Signs a message with `ML-DSA-44` and a context string.
pub fn sign_with_context(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<Signature, Error> {
    crate::sign::ml_dsa_sign_with_context(sk, msg, ctx, rng, &ML_DSA_44)
}

/// Verifies an `ML-DSA-44` signature.
pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    crate::verify::ml_dsa_verify(vk, msg, sig, &ML_DSA_44)
}

/// Verifies an `ML-DSA-44` signature with a context string.
pub fn verify_with_context(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    ctx: &[u8],
) -> Result<(), Error> {
    crate::verify::ml_dsa_verify_with_context(vk, msg, sig, ctx, &ML_DSA_44)
}
