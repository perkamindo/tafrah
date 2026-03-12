use crate::params::ML_KEM_768;
use crate::types::*;
use tafrah_traits::Error;

/// Generates an `ML-KEM-768` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> (EncapsulationKey, DecapsulationKey) {
    crate::keygen::ml_kem_keygen(rng, &ML_KEM_768)
        .expect("fixed ML-KEM-768 parameter set must be valid")
}

/// Encapsulates a shared secret for an `ML-KEM-768` public key.
pub fn encapsulate(
    ek: &EncapsulationKey,
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<(Ciphertext, SharedSecret), Error> {
    crate::encaps::ml_kem_encaps(ek, rng, &ML_KEM_768)
}

/// Decapsulates an `ML-KEM-768` ciphertext.
pub fn decapsulate(dk: &DecapsulationKey, ct: &Ciphertext) -> Result<SharedSecret, Error> {
    crate::decaps::ml_kem_decaps(dk, ct, &ML_KEM_768)
}
