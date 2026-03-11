//! Serialized carrier types for ML-DSA.

extern crate alloc;
use alloc::vec::Vec;
use zeroize::Zeroize;

#[derive(Clone)]
/// Serialized ML-DSA verifying key.
pub struct VerifyingKey {
    /// Raw serialized bytes in the FIPS 204 encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// Serialized ML-DSA signing key.
pub struct SigningKey {
    /// Raw serialized bytes in the FIPS 204 encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
/// Serialized ML-DSA detached signature.
pub struct Signature {
    /// Raw serialized bytes in the FIPS 204 encoding.
    pub bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Returns the serialized key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl SigningKey {
    /// Returns the serialized key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Signature {
    /// Returns the serialized signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
