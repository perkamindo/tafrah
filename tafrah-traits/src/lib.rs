//! Shared traits and errors for Tafrah scheme crates.
//!
//! The traits in this crate are intentionally small. They are used to provide a
//! common vocabulary across KEM and signature schemes without forcing a single
//! object model on every algorithm crate.
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod dsa;
pub mod kem;
pub mod serdes;

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A serialized public or private key length is invalid.
    InvalidKeyLength,
    /// A serialized ciphertext length is invalid.
    InvalidCiphertextLength,
    /// A serialized signature length is invalid.
    InvalidSignatureLength,
    /// A parameter bundle is invalid or unsupported.
    InvalidParameter,
    /// Signature verification failed.
    VerificationFailed,
    /// A serialized object could not be decoded.
    DecodingError,
    /// Randomness generation failed.
    RngError,
    /// A requested operation is not implemented.
    NotImplemented,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "invalid key length"),
            Error::InvalidCiphertextLength => write!(f, "invalid ciphertext length"),
            Error::InvalidSignatureLength => write!(f, "invalid signature length"),
            Error::InvalidParameter => write!(f, "invalid parameter"),
            Error::VerificationFailed => write!(f, "verification failed"),
            Error::DecodingError => write!(f, "decoding error"),
            Error::RngError => write!(f, "RNG error"),
            Error::NotImplemented => write!(f, "not implemented"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::Error;

    fn assert_std_error<T: std::error::Error>() {}

    #[test]
    fn error_implements_std_error() {
        assert_std_error::<Error>();
    }
}
