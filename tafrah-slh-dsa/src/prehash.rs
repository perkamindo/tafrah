//! HashSLH-DSA wrappers for FIPS 205 Algorithms 23 and 25.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::params::Params;
use crate::sign::slh_sign_internal;
use crate::types::{Signature, SigningKey, VerifyingKey};
use crate::verify::slh_verify_internal;
use tafrah_traits::Error;

use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

/// Pre-hash algorithms accepted by HashSLH-DSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrehashAlgorithm {
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

impl PrehashAlgorithm {
    /// Returns the FIPS 205 pre-hash identifier string.
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Sha2_224 => "SHA2-224",
            Self::Sha2_256 => "SHA2-256",
            Self::Sha2_384 => "SHA2-384",
            Self::Sha2_512 => "SHA2-512",
            Self::Sha2_512_224 => "SHA2-512/224",
            Self::Sha2_512_256 => "SHA2-512/256",
            Self::Sha3_224 => "SHA3-224",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Shake128 => "SHAKE-128",
            Self::Shake256 => "SHAKE-256",
        }
    }

    /// Returns the DER-encoded OID used by FIPS 205 for this pre-hash choice.
    pub const fn oid(self) -> [u8; 11] {
        match self {
            Self::Sha2_256 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            Self::Sha2_384 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            Self::Sha2_512 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            Self::Sha2_224 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
            Self::Sha2_512_224 => {
                [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05]
            }
            Self::Sha2_512_256 => {
                [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06]
            }
            Self::Sha3_224 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
            Self::Sha3_256 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
            Self::Sha3_384 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
            Self::Sha3_512 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A],
            Self::Shake128 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B],
            Self::Shake256 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C],
        }
    }

    /// Returns the digest size emitted by this pre-hash algorithm.
    pub const fn digest_bytes(self) -> usize {
        match self {
            Self::Sha2_224 | Self::Sha2_512_224 | Self::Sha3_224 => 28,
            Self::Sha2_256 | Self::Sha2_512_256 | Self::Sha3_256 | Self::Shake128 => 32,
            Self::Sha2_384 | Self::Sha3_384 => 48,
            Self::Sha2_512 | Self::Sha3_512 | Self::Shake256 => 64,
        }
    }

    /// Hashes a message using the selected pre-hash algorithm.
    pub fn digest_message(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha2_224 => Sha224::digest(msg).to_vec(),
            Self::Sha2_256 => Sha256::digest(msg).to_vec(),
            Self::Sha2_384 => Sha384::digest(msg).to_vec(),
            Self::Sha2_512 => Sha512::digest(msg).to_vec(),
            Self::Sha2_512_224 => Sha512_224::digest(msg).to_vec(),
            Self::Sha2_512_256 => Sha512_256::digest(msg).to_vec(),
            Self::Sha3_224 => Sha3_224::digest(msg).to_vec(),
            Self::Sha3_256 => Sha3_256::digest(msg).to_vec(),
            Self::Sha3_384 => Sha3_384::digest(msg).to_vec(),
            Self::Sha3_512 => Sha3_512::digest(msg).to_vec(),
            Self::Shake128 => {
                let mut hasher = Shake128::default();
                hasher.update(msg);
                let mut reader = hasher.finalize_xof();
                let mut out = vec![0u8; self.digest_bytes()];
                reader.read(&mut out);
                out
            }
            Self::Shake256 => {
                let mut hasher = Shake256::default();
                hasher.update(msg);
                let mut reader = hasher.finalize_xof();
                let mut out = vec![0u8; self.digest_bytes()];
                reader.read(&mut out);
                out
            }
        }
    }
}

fn encode_prehash_message(msg: &[u8], ctx: &[u8], ph: PrehashAlgorithm) -> Result<Vec<u8>, Error> {
    if ctx.len() > 255 {
        return Err(Error::InvalidParameter);
    }

    let digest = ph.digest_message(msg);
    let mut encoded = Vec::with_capacity(2 + ctx.len() + 11 + digest.len());
    encoded.push(1);
    encoded.push(ctx.len() as u8);
    encoded.extend_from_slice(ctx);
    encoded.extend_from_slice(&ph.oid());
    encoded.extend_from_slice(&digest);
    Ok(encoded)
}

/// Signs a message using the HashSLH-DSA FIPS 205 Algorithm 23 wrapper.
pub fn hash_slh_sign(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    ph: PrehashAlgorithm,
    addrnd: Option<&[u8]>,
    params: &Params,
) -> Result<Signature, Error> {
    let encoded = encode_prehash_message(msg, ctx, ph)?;
    slh_sign_internal(sk, &encoded, addrnd, params)
}

/// Verifies a HashSLH-DSA signature using FIPS 205 Algorithm 25.
pub fn hash_slh_verify(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    ctx: &[u8],
    ph: PrehashAlgorithm,
    params: &Params,
) -> Result<(), Error> {
    let encoded = encode_prehash_message(msg, ctx, ph)?;
    slh_verify_internal(vk, &encoded, sig, params)
}
