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
use crate::types::{Signature, VerifyingKey};
use tafrah_traits::Error;

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
    params.validate()?;
    let k = params.k;
    let l = params.l;
    let alpha = 2 * params.gamma2;

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

    let (pre, prelen) = build_context_prefix(ctx)?;

    // Parse vk = ρ || t1
    let rho = &vk.bytes[..32];
    let t1_bytes = 320; // 256 * 10 / 8
    let mut t1: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let start = 32 + i * t1_bytes;
        t1.push(encode::unpack_t1(&vk.bytes[start..start + t1_bytes]));
    }

    // Parse signature: c_tilde || z || h
    let c_tilde = &sig.bytes[..params.c_tilde_bytes];

    let mut offset = params.c_tilde_bytes;
    let mut z: Vec<Poly> = Vec::with_capacity(l);
    for _ in 0..l {
        z.push(encode::unpack_z(
            &sig.bytes[offset..offset + z_bytes],
            params.gamma1_bits,
        ));
        offset += z_bytes;
    }

    let hint_vec = encode::unpack_hint(&sig.bytes[offset..], k, params.omega)
        .ok_or(Error::InvalidSignatureLength)?;

    // Check ||z||_inf < gamma1 - beta
    let z_bound = params.gamma1 - params.beta;
    for zi in &z {
        if !zi.check_norm(z_bound) {
            return Err(Error::VerificationFailed);
        }
    }

    // Expand A from ρ
    let mut a_hat: Vec<Vec<Poly>> = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(l);
        for j in 0..l {
            let mut seed = Vec::with_capacity(34);
            seed.extend_from_slice(rho);
            seed.push(j as u8);
            seed.push(i as u8);
            row.push(dsa::sample_uniform(&seed));
        }
        a_hat.push(row);
    }

    // tr = H(vk)
    let mut tr_hasher = Shake256::default();
    sha3::digest::Update::update(&mut tr_hasher, &vk.bytes);
    let mut tr_reader = tr_hasher.finalize_xof();
    let mut tr = [0u8; 64];
    tr_reader.read(&mut tr);

    // μ = H(tr || pre || M)
    let mut mu_hasher = Shake256::default();
    sha3::digest::Update::update(&mut mu_hasher, &tr);
    sha3::digest::Update::update(&mut mu_hasher, &pre[..prelen]);
    sha3::digest::Update::update(&mut mu_hasher, msg);
    let mut mu_reader = mu_hasher.finalize_xof();
    let mut mu = [0u8; 64];
    mu_reader.read(&mut mu);

    // c = SampleInBall(c_tilde)
    let mut c = dsa::sample_in_ball(c_tilde, params.tau);
    c.ntt();

    // NTT(z)
    let mut z_hat: Vec<Poly> = z;
    for p in z_hat.iter_mut() {
        p.ntt();
    }

    // NTT(t1 * 2^d)
    let mut t1_2d_hat: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut t = Poly::zero();
        for j in 0..256 {
            t.coeffs[j] = t1[i].coeffs[j] << params.d;
        }
        t.ntt();
        t1_2d_hat.push(t);
    }

    // w'_approx = NTT^{-1}(A_hat * z_hat - c_hat * t1_2d_hat)
    let mut w_approx: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut wi = Poly::zero();
        // A_hat * z_hat
        for j in 0..l {
            let prod = a_hat[i][j].pointwise_mul(&z_hat[j]);
            wi.add_assign(&prod);
        }
        // - c_hat * t1_2d_hat
        let ct1 = c.pointwise_mul(&t1_2d_hat[i]);
        wi = wi.sub(&ct1);
        wi.reduce(); // reduce before inv_ntt to prevent i32 overflow
        wi.inv_ntt();
        wi.caddq();
        w_approx.push(wi);
    }

    // w'_1 = UseHint(h, w'_approx)
    let mut w1_prime: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut w1i = Poly::zero();
        for j in 0..256 {
            w1i.coeffs[j] = hint::use_hint(hint_vec[i][j], w_approx[i].coeffs[j], alpha);
        }
        w1_prime.push(w1i);
    }

    // c'_tilde = H(μ || w1Encode(w'_1))
    let mut c_prime_hasher = Shake256::default();
    sha3::digest::Update::update(&mut c_prime_hasher, &mu);
    for p in &w1_prime {
        let packed = encode::pack_w1(p, params.gamma2);
        sha3::digest::Update::update(&mut c_prime_hasher, &packed);
    }
    let mut c_prime_reader = c_prime_hasher.finalize_xof();
    let mut c_prime_tilde = alloc::vec![0u8; params.c_tilde_bytes];
    c_prime_reader.read(&mut c_prime_tilde);

    // Verify c_tilde == c'_tilde
    if c_tilde != c_prime_tilde.as_slice() {
        return Err(Error::VerificationFailed);
    }

    Ok(())
}
