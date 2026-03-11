//! Falcon verifying-key derivation from a signing key.

extern crate alloc;

use alloc::vec::Vec;

use crate::codec::modq_encode;
use crate::key_material::decode_and_compute_public;
use crate::params::Params;
use crate::types::{SigningKey, VerifyingKey};
use tafrah_traits::Error;

/// Derives the Falcon verifying key that corresponds to a signing key.
pub fn falcon_derive_verifying_key(
    sk: &SigningKey,
    params: &Params,
) -> Result<VerifyingKey, Error> {
    params.validate()?;
    let h = decode_and_compute_public(&sk.bytes, params)?;
    let encoded = modq_encode(&h, params.log_n).ok_or(Error::DecodingError)?;

    let mut bytes = Vec::with_capacity(params.pk_bytes);
    bytes.push(params.pk_tag());
    bytes.extend_from_slice(&encoded);
    if bytes.len() != params.pk_bytes {
        return Err(Error::DecodingError);
    }

    Ok(VerifyingKey { bytes })
}
