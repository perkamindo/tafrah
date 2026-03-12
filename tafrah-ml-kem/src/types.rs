//! Serialized carrier types for ML-KEM.

extern crate alloc;
use alloc::vec::Vec;
use zeroize::Zeroize;

#[derive(Clone)]
/// Serialized ML-KEM encapsulation public key.
pub struct EncapsulationKey {
    /// Raw serialized bytes in the FIPS 203 encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// Serialized ML-KEM decapsulation private key.
pub struct DecapsulationKey {
    /// Raw serialized bytes in the FIPS 203 encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone)]
/// Serialized ML-KEM ciphertext.
pub struct Ciphertext {
    /// Raw serialized bytes in the FIPS 203 encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// ML-KEM shared secret.
pub struct SharedSecret {
    /// Raw shared-secret bytes.
    pub(crate) bytes: [u8; 32],
}

impl EncapsulationKey {
    /// Wraps serialized bytes as an ML-KEM encapsulation key carrier.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the serialized key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the serialized key bytes as a mutable slice.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consumes the carrier and returns the owned serialized bytes.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl DecapsulationKey {
    /// Wraps serialized bytes as an ML-KEM decapsulation key carrier.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the serialized key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the serialized key bytes as a mutable slice.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consumes the carrier and returns the owned serialized bytes.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl Ciphertext {
    /// Wraps serialized bytes as an ML-KEM ciphertext carrier.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the serialized ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the serialized ciphertext bytes as a mutable slice.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consumes the carrier and returns the owned serialized bytes.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl SharedSecret {
    /// Wraps raw shared-secret bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns the shared-secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the shared-secret bytes as a mutable slice.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consumes the carrier and returns the owned shared-secret bytes.
    pub fn into_bytes(mut self) -> [u8; 32] {
        core::mem::take(&mut self.bytes)
    }
}
