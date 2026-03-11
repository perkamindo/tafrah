//! Serialized carrier types for ML-KEM.

extern crate alloc;
use alloc::vec::Vec;
use zeroize::Zeroize;

#[derive(Clone)]
/// Serialized ML-KEM encapsulation public key.
pub struct EncapsulationKey {
    /// Raw serialized bytes in the FIPS 203 encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// Serialized ML-KEM decapsulation private key.
pub struct DecapsulationKey {
    /// Raw serialized bytes in the FIPS 203 encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
/// Serialized ML-KEM ciphertext.
pub struct Ciphertext {
    /// Raw serialized bytes in the FIPS 203 encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// ML-KEM shared secret.
pub struct SharedSecret {
    /// Raw shared-secret bytes.
    pub bytes: [u8; 32],
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
