//! Serialized carrier types for HQC.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;

#[derive(Clone)]
/// Serialized HQC encapsulation public key.
pub struct EncapsulationKey {
    /// Raw serialized bytes in the HQC reference-compatible encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// Serialized HQC decapsulation private key.
pub struct DecapsulationKey {
    /// Raw serialized bytes in the HQC reference-compatible encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
/// Serialized HQC ciphertext.
pub struct Ciphertext {
    /// Raw serialized bytes in the HQC reference-compatible encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// HQC shared secret.
pub struct SharedSecret {
    /// Raw shared-secret bytes.
    pub bytes: Vec<u8>,
}

impl EncapsulationKey {
    /// Returns the serialized key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl DecapsulationKey {
    /// Returns the serialized key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Ciphertext {
    /// Returns the serialized ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl SharedSecret {
    /// Returns the shared-secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
