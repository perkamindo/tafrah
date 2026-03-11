//! Traits shared by signature schemes.

use rand_core::{CryptoRng, RngCore};

/// Signing capability for a signature private key type.
pub trait SigningKey {
    type Signature;
    type Error;

    /// Signs `msg` and returns the detached signature.
    fn sign(
        &self,
        msg: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self::Signature, Self::Error>;
}

/// Verification capability for a signature public key type.
pub trait VerifyingKey {
    type Signature;
    type Error;

    /// Verifies `sig` over `msg`.
    fn verify(&self, msg: &[u8], sig: &Self::Signature) -> Result<(), Self::Error>;
}
