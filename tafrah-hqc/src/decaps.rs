//! Generic HQC decapsulation entry point.

use crate::params::Params;
use crate::parse::{parse_ciphertext, parse_public_key, parse_secret_key};
use crate::pke::decapsulate_ciphertext;
use crate::types::{Ciphertext, DecapsulationKey, SharedSecret};
use tafrah_traits::Error;

/// Decapsulates an HQC ciphertext.
pub fn hqc_decaps(
    dk: &DecapsulationKey,
    ct: &Ciphertext,
    params: &Params,
) -> Result<SharedSecret, Error> {
    params.validate()?;
    if dk.bytes.len() != params.sk_bytes {
        return Err(Error::InvalidKeyLength);
    }
    if ct.bytes.len() != params.ct_bytes {
        return Err(Error::InvalidCiphertextLength);
    }

    let secret_key = parse_secret_key(dk, params)?;
    let public_key = parse_public_key(&secret_key.public_key, params)?;
    let ciphertext = parse_ciphertext(ct, params)?;

    Ok(decapsulate_ciphertext(
        &secret_key,
        &public_key,
        &ciphertext,
        params,
    ))
}
