//! Serialized carrier types for Falcon.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroize;

#[derive(Clone)]
/// Serialized Falcon verifying key.
pub struct VerifyingKey {
    /// Raw serialized bytes in the Falcon reference-compatible encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
/// Serialized Falcon signing key.
pub struct SigningKey {
    /// Raw serialized bytes in the Falcon reference-compatible encoding.
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
/// Serialized Falcon detached signature.
pub struct Signature {
    /// Raw serialized bytes in the NIST detached-signature encoding.
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
