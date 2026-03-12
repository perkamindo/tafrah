use crate::params::HQC_256;
use crate::types::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret};
use tafrah_traits::kem::Kem;
use tafrah_traits::Error;

/// Marker type for generic `HQC-256` code via [`Kem`].
pub struct Hqc256Kem;

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

impl Kem for Hqc256Kem {
    type EncapsulationKey = EncapsulationKey;
    type DecapsulationKey = DecapsulationKey;
    type Ciphertext = Ciphertext;
    type SharedSecret = SharedSecret;
    type Error = Error;

    fn keygen<R: rand_core::CryptoRng + rand_core::Rng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error> {
        keygen(rng)
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
