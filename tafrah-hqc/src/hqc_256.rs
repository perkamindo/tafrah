use crate::params::HQC_256;
use crate::types::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret};
use tafrah_traits::Error;

/// Generates an `HQC-256` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<(EncapsulationKey, DecapsulationKey), Error> {
    crate::keygen::hqc_keygen(rng, &HQC_256)
}

/// Encapsulates a shared secret for an `HQC-256` public key.
pub fn encapsulate(
    ek: &EncapsulationKey,
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<(Ciphertext, SharedSecret), Error> {
    crate::encaps::hqc_encaps(ek, rng, &HQC_256)
}

/// Decapsulates an `HQC-256` ciphertext.
pub fn decapsulate(dk: &DecapsulationKey, ct: &Ciphertext) -> Result<SharedSecret, Error> {
    crate::decaps::hqc_decaps(dk, ct, &HQC_256)
}
