//! Generic Falcon verification entry point.

extern crate alloc;

use crate::codec::{comp_decode, modq_decode};
use crate::common::hash_to_point_vartime;
use crate::mq::{build_ntt_tables, to_ntt_monty, verify_raw};
use crate::params::Params;
use crate::types::{Signature, VerifyingKey};
use tafrah_traits::Error;

/// Verifies a Falcon signature for a message.
pub fn falcon_verify(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    params: &Params,
) -> Result<(), Error> {
    params.validate()?;
    if vk.bytes.len() != params.pk_bytes {
        return Err(Error::InvalidKeyLength);
    }
    if sig.bytes.len() < 43 || sig.bytes.len() > params.sig_max_bytes {
        return Err(Error::InvalidSignatureLength);
    }

    let logn = params.log_n;
    if vk.bytes[0] != params.pk_tag() {
        return Err(Error::DecodingError);
    }

    let encoded_sig_len = ((sig.bytes[0] as usize) << 8) | sig.bytes[1] as usize;
    if encoded_sig_len == 0 || sig.bytes.len() != 42 + encoded_sig_len {
        return Err(Error::InvalidSignatureLength);
    }

    let nonce = &sig.bytes[2..42];
    let esig = &sig.bytes[42..];
    if esig[0] != params.sig_tag() {
        return Err(Error::DecodingError);
    }

    let n = 1usize << logn;
    let mut h = alloc::vec![0u16; n];
    if modq_decode(&mut h, logn, &vk.bytes[1..]).is_none() {
        return Err(Error::DecodingError);
    }

    let mut s2 = alloc::vec![0i16; n];
    let consumed = comp_decode(&mut s2, logn, &esig[1..]).ok_or(Error::DecodingError)?;
    if consumed != esig.len() - 1 {
        return Err(Error::DecodingError);
    }

    let hm = hash_to_point_vartime(nonce, msg, logn);
    let (gmb, _) = build_ntt_tables();
    to_ntt_monty(&mut h, logn, &gmb);

    if verify_raw(&hm, &s2, &h, logn) {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}
