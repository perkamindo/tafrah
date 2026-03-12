//! HashML-DSA helpers for FIPS 204.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use tafrah_traits::Error;

/// Maximum formatted domain separation message length.
pub const DOMAIN_SEPARATION_MAX_BYTES: usize = 2 + 255 + 11 + 64;

/// Supported pre-hash algorithms for HashML-DSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreHashAlgorithm {
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha2_512_224,
    Sha2_512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
}

impl PreHashAlgorithm {
    /// Returns the digest length in bytes required by this pre-hash mode.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha2_224 | Self::Sha2_512_224 | Self::Sha3_224 => 28,
            Self::Sha2_256 | Self::Sha2_512_256 | Self::Sha3_256 | Self::Shake128 => 32,
            Self::Sha2_384 | Self::Sha3_384 => 48,
            Self::Sha2_512 | Self::Sha3_512 | Self::Shake256 => 64,
        }
    }

    /// Returns the DER-encoded OID used in FIPS 204 domain separation.
    pub const fn oid(self) -> [u8; 11] {
        match self {
            Self::Sha2_224 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
            ],
            Self::Sha2_256 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            Self::Sha2_384 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ],
            Self::Sha2_512 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
            Self::Sha2_512_224 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
            ],
            Self::Sha2_512_256 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
            ],
            Self::Sha3_224 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
            ],
            Self::Sha3_256 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
            ],
            Self::Sha3_384 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
            ],
            Self::Sha3_512 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A,
            ],
            Self::Shake128 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
            ],
            Self::Shake256 => [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
            ],
        }
    }

    /// Validates the supplied digest length.
    pub fn validate_digest(self, digest: &[u8]) -> Result<(), Error> {
        if digest.len() == self.digest_len() {
            Ok(())
        } else {
            Err(Error::InvalidParameter)
        }
    }
}

/// Builds the HashML-DSA domain separation prefix.
pub fn build_prehash_prefix(
    digest: &[u8],
    ctx: &[u8],
    hashalg: PreHashAlgorithm,
) -> Result<([u8; DOMAIN_SEPARATION_MAX_BYTES], usize), Error> {
    if ctx.len() > u8::MAX as usize {
        return Err(Error::InvalidParameter);
    }
    hashalg.validate_digest(digest)?;

    let mut prefix = [0u8; DOMAIN_SEPARATION_MAX_BYTES];
    prefix[0] = 1;
    prefix[1] = ctx.len() as u8;
    prefix[2..2 + ctx.len()].copy_from_slice(ctx);
    let oid = hashalg.oid();
    let oid_offset = 2 + ctx.len();
    prefix[oid_offset..oid_offset + oid.len()].copy_from_slice(&oid);
    let digest_offset = oid_offset + oid.len();
    prefix[digest_offset..digest_offset + digest.len()].copy_from_slice(digest);

    Ok((prefix, digest_offset + digest.len()))
}

/// Computes the SHAKE256 pre-hash used by the convenience HashML-DSA API.
pub fn shake256_prehash(message: &[u8]) -> [u8; 64] {
    let mut hasher = Shake256::default();
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut digest = [0u8; 64];
    reader.read(&mut digest);
    digest
}

#[cfg(test)]
mod tests {
    use super::{build_prehash_prefix, shake256_prehash, PreHashAlgorithm};

    #[test]
    fn test_build_prehash_prefix_rejects_wrong_length() {
        assert!(build_prehash_prefix(&[0u8; 31], b"ctx", PreHashAlgorithm::Sha2_256).is_err());
    }

    #[test]
    fn test_build_prehash_prefix_encodes_oid_and_context() {
        let digest = [0xA5u8; 32];
        let (prefix, len) =
            build_prehash_prefix(&digest, b"ctx", PreHashAlgorithm::Sha2_256).unwrap();
        assert_eq!(prefix[0], 1);
        assert_eq!(prefix[1], 3);
        assert_eq!(&prefix[2..5], b"ctx");
        assert_eq!(
            &prefix[5..16],
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        );
        assert_eq!(&prefix[16..48], &digest);
        assert_eq!(len, 48);
    }

    #[test]
    fn test_shake256_prehash_matches_requested_length() {
        let digest = shake256_prehash(b"tafrah");
        assert_eq!(digest.len(), 64);
    }
}
