//! Lightweight encoding and decoding traits.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
/// Serializes a value into an owned byte vector.
pub trait Encode {
    fn to_bytes(&self) -> Vec<u8>;
}

#[cfg(feature = "alloc")]
/// Decodes a value from a serialized byte slice.
pub trait Decode: Sized {
    type Error;
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}
