use crate::params::HQC_192;
use crate::types::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret};
use tafrah_traits::Error;

/// Generates an `HQC-192` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<(EncapsulationKey, DecapsulationKey), Error> {
    crate::keygen::hqc_keygen(rng, &HQC_192)
}

/// Encapsulates a shared secret for an `HQC-192` public key.
pub fn encapsulate(
    ek: &EncapsulationKey,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<(Ciphertext, SharedSecret), Error> {
    crate::encaps::hqc_encaps(ek, rng, &HQC_192)
}

/// Decapsulates an `HQC-192` ciphertext.
pub fn decapsulate(dk: &DecapsulationKey, ct: &Ciphertext) -> Result<SharedSecret, Error> {
    crate::decaps::hqc_decaps(dk, ct, &HQC_192)
}
