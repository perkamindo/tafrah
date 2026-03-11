use crate::params::ML_KEM_512;
use crate::types::*;
use tafrah_traits::Error;

/// Generates an `ML-KEM-512` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> (EncapsulationKey, DecapsulationKey) {
    crate::keygen::ml_kem_keygen(rng, &ML_KEM_512)
        .expect("fixed ML-KEM-512 parameter set must be valid")
}

/// Encapsulates a shared secret for an `ML-KEM-512` public key.
pub fn encapsulate(
    ek: &EncapsulationKey,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<(Ciphertext, SharedSecret), Error> {
    crate::encaps::ml_kem_encaps(ek, rng, &ML_KEM_512)
}

/// Decapsulates an `ML-KEM-512` ciphertext.
pub fn decapsulate(dk: &DecapsulationKey, ct: &Ciphertext) -> Result<SharedSecret, Error> {
    crate::decaps::ml_kem_decaps(dk, ct, &ML_KEM_512)
}
