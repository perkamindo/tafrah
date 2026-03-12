use crate::params::ML_KEM_512;
use crate::types::*;
use tafrah_traits::kem::Kem;
use tafrah_traits::Error;

/// Marker type for generic `ML-KEM-512` code via [`Kem`].
pub struct MlKem512Kem;

/// Generates an `ML-KEM-512` keypair.
pub fn keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> (EncapsulationKey, DecapsulationKey) {
    crate::keygen::ml_kem_keygen(rng, &ML_KEM_512)
        .expect("fixed ML-KEM-512 parameter set must be valid")
}

/// Encapsulates a shared secret for an `ML-KEM-512` public key.
pub fn encapsulate(
    ek: &EncapsulationKey,
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
) -> Result<(Ciphertext, SharedSecret), Error> {
    crate::encaps::ml_kem_encaps(ek, rng, &ML_KEM_512)
}

/// Decapsulates an `ML-KEM-512` ciphertext.
pub fn decapsulate(dk: &DecapsulationKey, ct: &Ciphertext) -> Result<SharedSecret, Error> {
    crate::decaps::ml_kem_decaps(dk, ct, &ML_KEM_512)
}

impl Kem for MlKem512Kem {
    type EncapsulationKey = EncapsulationKey;
    type DecapsulationKey = DecapsulationKey;
    type Ciphertext = Ciphertext;
    type SharedSecret = SharedSecret;
    type Error = Error;

    fn keygen<R: rand_core::CryptoRng + rand_core::Rng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error> {
        Ok(keygen(rng))
    }

    fn encapsulate<R: rand_core::CryptoRng + rand_core::Rng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        encapsulate(ek, rng)
    }

    fn decapsulate(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error> {
        decapsulate(dk, ct)
    }
}
