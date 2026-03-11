//! Generic HQC encapsulation entry point.

use crate::params::Params;
use crate::parse::{encode_ciphertext, parse_public_key};
use crate::pke::{
    encapsulate_with_message_and_salt, random_message_from_rng, random_salt_from_rng,
};
use crate::types::{Ciphertext, EncapsulationKey, SharedSecret};
use tafrah_traits::Error;

/// Encapsulates a shared secret for an HQC public key.
pub fn hqc_encaps(
    ek: &EncapsulationKey,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    params: &Params,
) -> Result<(Ciphertext, SharedSecret), Error> {
    params.validate()?;
    if ek.bytes.len() != params.pk_bytes {
        return Err(Error::InvalidKeyLength);
    }

    let public_key = parse_public_key(ek, params)?;
    let message = random_message_from_rng(rng, params);
    let salt = random_salt_from_rng(rng, params);
    let (ciphertext_parts, ss) =
        encapsulate_with_message_and_salt(&public_key, &message, &salt, params);
    let ciphertext = encode_ciphertext(&ciphertext_parts, params)?;

    Ok((ciphertext, ss))
}
