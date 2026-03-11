//! Traits shared by key encapsulation mechanisms.

use rand_core::{CryptoRng, RngCore};

/// Encapsulation capability for a KEM public key type.
pub trait Encapsulate {
    type SharedSecret;
    type Ciphertext;
    type Error;

    /// Produces a ciphertext and shared secret.
    fn encapsulate(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
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
