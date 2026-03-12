//! Serialized carrier types for HQC.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;

#[derive(Clone)]
/// Serialized HQC encapsulation public key.
pub struct EncapsulationKey {
    /// Raw serialized bytes in the HQC reference-compatible encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// Serialized HQC decapsulation private key.
pub struct DecapsulationKey {
    /// Raw serialized bytes in the HQC reference-compatible encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone)]
/// Serialized HQC ciphertext.
pub struct Ciphertext {
    /// Raw serialized bytes in the HQC reference-compatible encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// HQC shared secret.
pub struct SharedSecret {
    /// Raw shared-secret bytes.
    pub(crate) bytes: Vec<u8>,
}

impl EncapsulationKey {
    /// Wraps serialized bytes as an HQC encapsulation-key carrier.
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
    /// Wraps serialized bytes as an HQC decapsulation-key carrier.
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
    /// Wraps serialized bytes as an HQC ciphertext carrier.
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
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
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
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}
