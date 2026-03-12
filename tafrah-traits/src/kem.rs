//! Traits shared by key encapsulation mechanisms.

use rand_core::{CryptoRng, Rng};

/// High-level KEM family trait for fixed-parameter algorithm wrappers.
///
/// This complements [`Encapsulate`] and [`Decapsulate`]. The lower-level traits
/// model capabilities on individual key carriers, while `Kem` models a full
/// algorithm family that can generate keys and perform encapsulation and
/// decapsulation through a single generic type.
pub trait Kem {
    type EncapsulationKey;
    type DecapsulationKey;
    type Ciphertext;
    type SharedSecret;
    type Error;

    /// Generates a fresh KEM keypair for the fixed parameter set.
    fn keygen<R: CryptoRng + Rng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error>;

    /// Encapsulates a shared secret for `ek`.
    fn encapsulate<R: CryptoRng + Rng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error>;

    /// Decapsulates `ct` with `dk`.
    fn decapsulate(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Self::Error>;
}

/// Encapsulation capability for a KEM public key type.
pub trait Encapsulate {
    type SharedSecret;
    type Ciphertext;
    type Error;

    /// Produces a ciphertext and shared secret.
    fn encapsulate(
        &self,
        rng: &mut (impl CryptoRng + Rng),
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error>;
}

/// Decapsulation capability for a KEM private key type.
pub trait Decapsulate {
    type SharedSecret;
    type Ciphertext;
    type Error;

    /// Recovers the shared secret from `ct`.
    fn decapsulate(&self, ct: &Self::Ciphertext) -> Result<Self::SharedSecret, Self::Error>;
}
