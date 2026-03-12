use crate::params::FALCON_1024;
use crate::types::{Signature, SigningKey, VerifyingKey};
use tafrah_traits::Error;

/// Generates a `Falcon-1024` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<(VerifyingKey, SigningKey), Error> {
    crate::keygen::falcon_keygen(rng, &FALCON_1024)
}

/// Signs a message with `Falcon-1024`.
pub fn sign(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<Signature, Error> {
    crate::sign::falcon_sign(sk, msg, rng, &FALCON_1024)
}

/// Derives the `Falcon-1024` verifying key from a signing key.
pub fn derive_verifying_key(sk: &SigningKey) -> Result<VerifyingKey, Error> {
    crate::derive::falcon_derive_verifying_key(sk, &FALCON_1024)
}

/// Verifies a `Falcon-1024` signature.
pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    crate::verify::falcon_verify(vk, msg, sig, &FALCON_1024)
}
