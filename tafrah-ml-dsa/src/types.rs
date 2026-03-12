//! Serialized carrier types for ML-DSA.

extern crate alloc;
use alloc::vec::Vec;
use zeroize::Zeroize;

#[derive(Clone)]
/// Serialized ML-DSA verifying key.
pub struct VerifyingKey {
    /// Raw serialized bytes in the FIPS 204 encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// Serialized ML-DSA signing key.
pub struct SigningKey {
    /// Raw serialized bytes in the FIPS 204 encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone)]
/// Serialized ML-DSA detached signature.
pub struct Signature {
    /// Raw serialized bytes in the FIPS 204 encoding.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone)]
/// Serialized ML-DSA signed message (`signature || message`).
pub struct SignedMessage {
    /// Raw serialized bytes in the FIPS 204 encoding.
    pub(crate) bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Wraps serialized bytes as an ML-DSA verifying-key carrier.
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

impl SigningKey {
    /// Wraps serialized bytes as an ML-DSA signing-key carrier.
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

impl Signature {
    /// Wraps serialized bytes as an ML-DSA detached-signature carrier.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the serialized signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the serialized signature bytes as a mutable slice.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consumes the carrier and returns the owned serialized bytes.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl SignedMessage {
    /// Wraps serialized bytes as an ML-DSA signed-message carrier.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the serialized signed-message bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the serialized signed-message bytes as a mutable slice.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consumes the carrier and returns the owned serialized bytes.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}
