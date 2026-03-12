use crate::params::FALCON_512;
use crate::types::{Signature, SigningKey, VerifyingKey};
use tafrah_traits::Error;

/// Generates a `Falcon-512` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<(VerifyingKey, SigningKey), Error> {
    crate::keygen::falcon_keygen(rng, &FALCON_512)
}

/// Signs a message with `Falcon-512`.
pub fn sign(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<Signature, Error> {
    crate::sign::falcon_sign(sk, msg, rng, &FALCON_512)
}

/// Derives the `Falcon-512` verifying key from a signing key.
pub fn derive_verifying_key(sk: &SigningKey) -> Result<VerifyingKey, Error> {
    crate::derive::falcon_derive_verifying_key(sk, &FALCON_512)
}

/// Verifies a `Falcon-512` signature.
pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    crate::verify::falcon_verify(vk, msg, sig, &FALCON_512)
}
