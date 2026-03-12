//! Generic ML-DSA verification entry points.

extern crate alloc;
use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, XofReader};
use sha3::Shake256;

use tafrah_math::poly::dsa::Poly;
use tafrah_math::sampling::dsa;

use crate::context::build_context_prefix;
use crate::encode;
use crate::hint;
use crate::params::Params;
use crate::prehash::{build_prehash_prefix, shake256_prehash, PreHashAlgorithm};
use crate::types::{Signature, SignedMessage, VerifyingKey};
use tafrah_traits::Error;

fn expand_matrix(rho: &[u8], params: &Params) -> Vec<Vec<Poly>> {
    let mut a_hat: Vec<Vec<Poly>> = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let mut row = Vec::with_capacity(params.l);
        for j in 0..params.l {
            let mut seed = Vec::with_capacity(34);
            seed.extend_from_slice(rho);
            seed.push(j as u8);
            seed.push(i as u8);
            row.push(dsa::sample_uniform(&seed));
        }
        a_hat.push(row);
    }
    a_hat
}

fn verify_internal_core(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    pre: &[u8],
    external_mu: bool,
    params: &Params,
) -> Result<(), Error> {
    params.validate()?;
    let alpha = 2 * params.gamma2;

    if external_mu && msg.len() != 64 {
        return Err(Error::InvalidParameter);
    }

    if vk.bytes.len() != params.vk_size() {
        return Err(Error::InvalidKeyLength);
    }
    if sig.bytes.len() != params.sig_size() {
        return Err(Error::InvalidSignatureLength);
    }

    let z_bytes = params.z_bytes();
    if z_bytes == 0 {
        return Err(Error::InvalidParameter);
    }

    let rho = &vk.bytes[..32];
    let t1_bytes = 320;
    let mut t1: Vec<Poly> = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let start = 32 + i * t1_bytes;
        t1.push(encode::unpack_t1(&vk.bytes[start..start + t1_bytes]));
    }

    let c_tilde = &sig.bytes[..params.c_tilde_bytes];

    let mut offset = params.c_tilde_bytes;
    let mut z: Vec<Poly> = Vec::with_capacity(params.l);
    for _ in 0..params.l {
        z.push(encode::unpack_z(
            &sig.bytes[offset..offset + z_bytes],
            params.gamma1_bits,
        ));
        offset += z_bytes;
    }

    let hint_vec = encode::unpack_hint(&sig.bytes[offset..], params.k, params.omega)
        .ok_or(Error::InvalidSignatureLength)?;

    let z_bound = params.gamma1 - params.beta;
    if z.iter().any(|zi| !zi.check_norm(z_bound)) {
        return Err(Error::VerificationFailed);
    }

    let a_hat = expand_matrix(rho, params);

    let mut mu = [0u8; 64];
    if external_mu {
        mu.copy_from_slice(msg);
    } else {
        let mut tr_hasher = Shake256::default();
        sha3::digest::Update::update(&mut tr_hasher, &vk.bytes);
        let mut tr_reader = tr_hasher.finalize_xof();
        let mut tr = [0u8; 64];
        tr_reader.read(&mut tr);

        let mut mu_hasher = Shake256::default();
        sha3::digest::Update::update(&mut mu_hasher, &tr);
        sha3::digest::Update::update(&mut mu_hasher, pre);
        sha3::digest::Update::update(&mut mu_hasher, msg);
        let mut mu_reader = mu_hasher.finalize_xof();
        mu_reader.read(&mut mu);
    }

    let mut c = dsa::sample_in_ball(c_tilde, params.tau);
    c.ntt();

    let mut z_hat: Vec<Poly> = z;
    for p in &mut z_hat {
        p.ntt();
    }

    let mut t1_2d_hat: Vec<Poly> = Vec::with_capacity(params.k);
    for poly in &t1 {
        let mut t = Poly::zero();
        for j in 0..256 {
            t.coeffs[j] = poly.coeffs[j] << params.d;
        }
        t.ntt();
        t1_2d_hat.push(t);
    }

    let mut w_approx: Vec<Poly> = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let mut wi = Poly::zero();
        for j in 0..params.l {
            let prod = a_hat[i][j].pointwise_mul(&z_hat[j]);
            wi.add_assign(&prod);
        }
        let ct1 = c.pointwise_mul(&t1_2d_hat[i]);
        wi = wi.sub(&ct1);
        wi.reduce();
        wi.inv_ntt();
        wi.caddq();
        w_approx.push(wi);
    }

    let mut w1_prime: Vec<Poly> = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let mut w1i = Poly::zero();
        for j in 0..256 {
            w1i.coeffs[j] = hint::use_hint(hint_vec[i][j], w_approx[i].coeffs[j], alpha);
        }
        w1_prime.push(w1i);
    }

    let mut c_prime_hasher = Shake256::default();
    sha3::digest::Update::update(&mut c_prime_hasher, &mu);
    for p in &w1_prime {
        let packed = encode::pack_w1(p, params.gamma2);
        sha3::digest::Update::update(&mut c_prime_hasher, &packed);
    }
    let mut c_prime_reader = c_prime_hasher.finalize_xof();
    let mut c_prime_tilde = alloc::vec![0u8; params.c_tilde_bytes];
    c_prime_reader.read(&mut c_prime_tilde);

    if c_tilde != c_prime_tilde.as_slice() {
        return Err(Error::VerificationFailed);
    }

    Ok(())
}

/// Verifies an ML-DSA signature for a message.
pub fn ml_dsa_verify(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    params: &Params,
) -> Result<(), Error> {
    ml_dsa_verify_with_context(vk, msg, sig, &[], params)
}

/// Verifies an ML-DSA signature for a message and context string.
pub fn ml_dsa_verify_with_context(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    ctx: &[u8],
    params: &Params,
) -> Result<(), Error> {
    let (pre, prelen) = build_context_prefix(ctx)?;
    verify_internal_core(vk, msg, sig, &pre[..prelen], false, params)
}

/// Internal ML-DSA verification primitive from FIPS 204.
pub fn ml_dsa_verify_internal(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    pre: &[u8],
    external_mu: bool,
    params: &Params,
) -> Result<(), Error> {
    verify_internal_core(vk, msg, sig, pre, external_mu, params)
}

/// Verifies a signature over an externally supplied `mu` value.
pub fn ml_dsa_verify_extmu(
    vk: &VerifyingKey,
    mu: &[u8; 64],
    sig: &Signature,
    params: &Params,
) -> Result<(), Error> {
    verify_internal_core(vk, mu, sig, &[], true, params)
}

/// Verifies a pre-hashed message using the supplied digest and hash identifier.
pub fn ml_dsa_verify_prehash(
    vk: &VerifyingKey,
    digest: &[u8],
    sig: &Signature,
    ctx: &[u8],
    hashalg: PreHashAlgorithm,
    params: &Params,
) -> Result<(), Error> {
    let (pre, prelen) = build_prehash_prefix(digest, ctx, hashalg)?;
    verify_internal_core(vk, &pre[..prelen], sig, &[], false, params)
}

/// Verifies a message using the SHAKE256 HashML-DSA convenience API.
pub fn ml_dsa_verify_prehash_shake256(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    ctx: &[u8],
    params: &Params,
) -> Result<(), Error> {
    let digest = shake256_prehash(msg);
    ml_dsa_verify_prehash(vk, &digest, sig, ctx, PreHashAlgorithm::Shake256, params)
}

/// Verifies and opens a signed message.
pub fn ml_dsa_open_signed_message(
    vk: &VerifyingKey,
    signed_message: &SignedMessage,
    params: &Params,
) -> Result<Vec<u8>, Error> {
    ml_dsa_open_signed_message_with_context(vk, signed_message, &[], params)
}

/// Verifies and opens a signed message with context.
pub fn ml_dsa_open_signed_message_with_context(
    vk: &VerifyingKey,
    signed_message: &SignedMessage,
    ctx: &[u8],
    params: &Params,
) -> Result<Vec<u8>, Error> {
    params.validate()?;
    if signed_message.bytes.len() < params.sig_size() {
        return Err(Error::InvalidSignatureLength);
    }

    let sig = Signature {
        bytes: signed_message.bytes[..params.sig_size()].to_vec(),
    };
    let message = &signed_message.bytes[params.sig_size()..];
    ml_dsa_verify_with_context(vk, message, &sig, ctx, params)?;
    Ok(message.to_vec())
}
