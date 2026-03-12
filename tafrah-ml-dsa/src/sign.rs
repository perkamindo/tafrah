//! Generic ML-DSA signing entry points.

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
use crate::types::{Signature, SignedMessage, SigningKey};
use tafrah_traits::Error;
use zeroize::Zeroize;

/// Randomness input length for ML-DSA internal signing.
pub const ML_DSA_RNDBYTES: usize = 32;

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

fn parse_signing_key<'a>(
    sk: &'a SigningKey,
    params: &Params,
) -> Result<
    (
        &'a [u8],
        &'a [u8],
        &'a [u8],
        Vec<Poly>,
        Vec<Poly>,
        Vec<Poly>,
    ),
    Error,
> {
    if sk.bytes.len() != params.sk_size() {
        return Err(Error::InvalidKeyLength);
    }

    let eta_bytes = params.eta_bytes();
    if eta_bytes == 0 {
        return Err(Error::InvalidParameter);
    }

    let rho = &sk.bytes[..32];
    let key_k = &sk.bytes[32..64];
    let tr = &sk.bytes[64..128];

    let mut offset = 128;
    let mut s1: Vec<Poly> = Vec::with_capacity(params.l);
    for _ in 0..params.l {
        s1.push(encode::unpack_eta(
            &sk.bytes[offset..offset + eta_bytes],
            params.eta,
        ));
        offset += eta_bytes;
    }

    let mut s2: Vec<Poly> = Vec::with_capacity(params.k);
    for _ in 0..params.k {
        s2.push(encode::unpack_eta(
            &sk.bytes[offset..offset + eta_bytes],
            params.eta,
        ));
        offset += eta_bytes;
    }

    let t0_bytes = 416;
    let mut t0: Vec<Poly> = Vec::with_capacity(params.k);
    for _ in 0..params.k {
        t0.push(encode::unpack_t0(&sk.bytes[offset..offset + t0_bytes]));
        offset += t0_bytes;
    }

    Ok((rho, key_k, tr, s1, s2, t0))
}

fn zeroize_poly_vec(polys: &mut [Poly]) {
    for poly in polys {
        poly.zeroize();
    }
}

fn sign_internal_core(
    sk: &SigningKey,
    msg: &[u8],
    pre: &[u8],
    rnd: &[u8; ML_DSA_RNDBYTES],
    external_mu: bool,
    params: &Params,
) -> Result<Signature, Error> {
    params.validate()?;
    let alpha = 2 * params.gamma2;

    if external_mu && msg.len() != 64 {
        return Err(Error::InvalidParameter);
    }

    let (rho, key_k, tr, s1, s2, t0) = parse_signing_key(sk, params)?;

    let mut s1_hat: Vec<Poly> = s1.clone();
    let mut s2_hat: Vec<Poly> = s2.clone();
    let mut t0_hat: Vec<Poly> = t0.clone();
    for p in &mut s1_hat {
        p.ntt();
    }
    for p in &mut s2_hat {
        p.ntt();
    }
    for p in &mut t0_hat {
        p.ntt();
    }

    let a_hat = expand_matrix(rho, params);

    let mut mu = [0u8; 64];
    if external_mu {
        mu.copy_from_slice(msg);
    } else {
        let mut mu_hasher = Shake256::default();
        sha3::digest::Update::update(&mut mu_hasher, tr);
        sha3::digest::Update::update(&mut mu_hasher, pre);
        sha3::digest::Update::update(&mut mu_hasher, msg);
        let mut mu_reader = mu_hasher.finalize_xof();
        mu_reader.read(&mut mu);
    }

    let mut rho_pp_hasher = Shake256::default();
    sha3::digest::Update::update(&mut rho_pp_hasher, key_k);
    sha3::digest::Update::update(&mut rho_pp_hasher, rnd);
    sha3::digest::Update::update(&mut rho_pp_hasher, &mu);
    let mut rho_pp_reader = rho_pp_hasher.finalize_xof();
    let mut rho_pp = [0u8; 64];
    rho_pp_reader.read(&mut rho_pp);

    let mut kappa: u16 = 0;
    let signature = loop {
        let mut y: Vec<Poly> = Vec::with_capacity(params.l);
        for i in 0..params.l {
            let counter = kappa + i as u16;
            let mut seed = Vec::with_capacity(66);
            seed.extend_from_slice(&rho_pp);
            seed.push((counter & 0xFF) as u8);
            seed.push((counter >> 8) as u8);
            y.push(dsa::sample_gamma1(&seed, params.gamma1_bits));
        }
        kappa += params.l as u16;

        let mut y_hat: Vec<Poly> = y.clone();
        for p in &mut y_hat {
            p.ntt();
        }

        let mut w: Vec<Poly> = Vec::with_capacity(params.k);
        for row in a_hat.iter().take(params.k) {
            let mut wi = Poly::zero();
            for (j, poly) in row.iter().enumerate().take(params.l) {
                let prod = poly.pointwise_mul(&y_hat[j]);
                wi.add_assign(&prod);
            }
            wi.reduce();
            wi.inv_ntt();
            wi.caddq();
            w.push(wi);
        }

        let mut w1: Vec<Poly> = Vec::with_capacity(params.k);
        let mut w0: Vec<Poly> = Vec::with_capacity(params.k);
        for wi in &w {
            let mut w1i = Poly::zero();
            let mut w0i = Poly::zero();
            for j in 0..256 {
                let (hi, lo) = hint::decompose(wi.coeffs[j], alpha);
                w1i.coeffs[j] = hi;
                w0i.coeffs[j] = lo;
            }
            w1.push(w1i);
            w0.push(w0i);
        }

        let mut c_hasher = Shake256::default();
        sha3::digest::Update::update(&mut c_hasher, &mu);
        for p in &w1 {
            let packed = encode::pack_w1(p, params.gamma2);
            sha3::digest::Update::update(&mut c_hasher, &packed);
        }
        let mut c_reader = c_hasher.finalize_xof();
        let mut c_tilde = alloc::vec![0u8; params.c_tilde_bytes];
        c_reader.read(&mut c_tilde);

        let mut c = dsa::sample_in_ball(&c_tilde, params.tau);
        c.ntt();

        let mut z: Vec<Poly> = Vec::with_capacity(params.l);
        for i in 0..params.l {
            let mut cs1_time = c.pointwise_mul(&s1_hat[i]);
            cs1_time.inv_ntt();
            let mut zi = y[i].add(&cs1_time);
            zi.reduce();
            z.push(zi);
        }

        let mut cs2: Vec<Poly> = Vec::with_capacity(params.k);
        for poly in s2_hat.iter().take(params.k) {
            let mut p = c.pointwise_mul(poly);
            p.inv_ntt();
            cs2.push(p);
        }

        let z_bound = params.gamma1 - params.beta;
        if z.iter().any(|zi| !zi.check_norm(z_bound)) {
            continue;
        }

        let mut w0_minus_cs2: Vec<Poly> = Vec::with_capacity(params.k);
        for i in 0..params.k {
            let mut w0i = w0[i].sub(&cs2[i]);
            w0i.reduce();
            w0_minus_cs2.push(w0i);
        }

        let r0_bound = params.gamma2 - params.beta;
        if w0_minus_cs2.iter().any(|w0i| !w0i.check_norm(r0_bound)) {
            continue;
        }

        let mut ct0: Vec<Poly> = Vec::with_capacity(params.k);
        for poly in t0_hat.iter().take(params.k) {
            let mut p = c.pointwise_mul(poly);
            p.inv_ntt();
            p.reduce();
            ct0.push(p);
        }

        if ct0.iter().any(|ct0i| !ct0i.check_norm(params.gamma2)) {
            continue;
        }

        let mut hint_vec: Vec<Vec<bool>> = Vec::with_capacity(params.k);
        let mut total_hints = 0usize;
        for i in 0..params.k {
            let mut adjusted_w0 = w0_minus_cs2[i].add(&ct0[i]);
            adjusted_w0.caddq();
            let mut hi = alloc::vec![false; 256];
            for j in 0..256 {
                hi[j] = hint::make_hint(adjusted_w0.coeffs[j], w1[i].coeffs[j], alpha);
                if hi[j] {
                    total_hints += 1;
                }
            }
            hint_vec.push(hi);
        }

        if total_hints > params.omega {
            continue;
        }

        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(&c_tilde);
        for zi in &z {
            sig_bytes.extend_from_slice(&encode::pack_z(zi, params.gamma1_bits));
        }
        sig_bytes.extend_from_slice(&encode::pack_hint(&hint_vec, params.omega));

        break Signature { bytes: sig_bytes };
    };

    zeroize_poly_vec(&mut s1_hat);
    zeroize_poly_vec(&mut s2_hat);
    zeroize_poly_vec(&mut t0_hat);
    mu.zeroize();
    rho_pp.zeroize();
    Ok(signature)
}

fn zero_rnd() -> [u8; ML_DSA_RNDBYTES] {
    [0u8; ML_DSA_RNDBYTES]
}

fn random_rnd(rng: &mut (impl rand_core::CryptoRng + rand_core::Rng)) -> [u8; ML_DSA_RNDBYTES] {
    let mut rnd = [0u8; ML_DSA_RNDBYTES];
    rng.fill_bytes(&mut rnd);
    rnd
}

/// Signs a message with ML-DSA using the supplied parameter set.
pub fn ml_dsa_sign(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<Signature, Error> {
    ml_dsa_sign_with_context(sk, msg, &[], rng, params)
}

/// Signs a message with ML-DSA and an application-supplied context string.
pub fn ml_dsa_sign_with_context(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<Signature, Error> {
    let (pre, prelen) = build_context_prefix(ctx)?;
    let rnd = random_rnd(rng);
    sign_internal_core(sk, msg, &pre[..prelen], &rnd, false, params)
}

/// Signs a message with the deterministic ML-DSA variant.
pub fn ml_dsa_sign_deterministic(
    sk: &SigningKey,
    msg: &[u8],
    params: &Params,
) -> Result<Signature, Error> {
    ml_dsa_sign_deterministic_with_context(sk, msg, &[], params)
}

/// Signs a message with the deterministic ML-DSA variant and a context string.
pub fn ml_dsa_sign_deterministic_with_context(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    params: &Params,
) -> Result<Signature, Error> {
    let (pre, prelen) = build_context_prefix(ctx)?;
    let rnd = zero_rnd();
    sign_internal_core(sk, msg, &pre[..prelen], &rnd, false, params)
}

/// Internal ML-DSA signing primitive from FIPS 204.
pub fn ml_dsa_sign_internal(
    sk: &SigningKey,
    msg: &[u8],
    pre: &[u8],
    rnd: &[u8; ML_DSA_RNDBYTES],
    external_mu: bool,
    params: &Params,
) -> Result<Signature, Error> {
    sign_internal_core(sk, msg, pre, rnd, external_mu, params)
}

/// Signs an externally supplied `mu` value using fresh randomness.
pub fn ml_dsa_sign_extmu(
    sk: &SigningKey,
    mu: &[u8; 64],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<Signature, Error> {
    let rnd = random_rnd(rng);
    sign_internal_core(sk, mu, &[], &rnd, true, params)
}

/// Signs an externally supplied `mu` value with the deterministic ML-DSA variant.
pub fn ml_dsa_sign_extmu_deterministic(
    sk: &SigningKey,
    mu: &[u8; 64],
    params: &Params,
) -> Result<Signature, Error> {
    let rnd = zero_rnd();
    sign_internal_core(sk, mu, &[], &rnd, true, params)
}

/// Signs a pre-hashed message using the supplied digest and hash identifier.
pub fn ml_dsa_sign_prehash(
    sk: &SigningKey,
    digest: &[u8],
    ctx: &[u8],
    hashalg: PreHashAlgorithm,
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<Signature, Error> {
    let rnd = random_rnd(rng);
    ml_dsa_sign_prehash_internal(sk, digest, ctx, &rnd, hashalg, params)
}

/// Signs a pre-hashed message deterministically.
pub fn ml_dsa_sign_prehash_deterministic(
    sk: &SigningKey,
    digest: &[u8],
    ctx: &[u8],
    hashalg: PreHashAlgorithm,
    params: &Params,
) -> Result<Signature, Error> {
    let rnd = zero_rnd();
    ml_dsa_sign_prehash_internal(sk, digest, ctx, &rnd, hashalg, params)
}

/// Internal HashML-DSA signing primitive for caller-supplied digests.
pub fn ml_dsa_sign_prehash_internal(
    sk: &SigningKey,
    digest: &[u8],
    ctx: &[u8],
    rnd: &[u8; ML_DSA_RNDBYTES],
    hashalg: PreHashAlgorithm,
    params: &Params,
) -> Result<Signature, Error> {
    let (pre, prelen) = build_prehash_prefix(digest, ctx, hashalg)?;
    sign_internal_core(sk, &pre[..prelen], &[], rnd, false, params)
}

/// Signs a message using the SHAKE256 HashML-DSA convenience API.
pub fn ml_dsa_sign_prehash_shake256(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<Signature, Error> {
    let digest = shake256_prehash(msg);
    ml_dsa_sign_prehash(sk, &digest, ctx, PreHashAlgorithm::Shake256, rng, params)
}

/// Signs a message using the deterministic SHAKE256 HashML-DSA convenience API.
pub fn ml_dsa_sign_prehash_shake256_deterministic(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    params: &Params,
) -> Result<Signature, Error> {
    let digest = shake256_prehash(msg);
    ml_dsa_sign_prehash_deterministic(sk, &digest, ctx, PreHashAlgorithm::Shake256, params)
}

/// Signs a message and returns the serialized `signature || message` form.
pub fn ml_dsa_sign_message(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<SignedMessage, Error> {
    ml_dsa_sign_message_with_context(sk, msg, &[], rng, params)
}

/// Signs a message with context and returns the serialized `signature || message` form.
pub fn ml_dsa_sign_message_with_context(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<SignedMessage, Error> {
    let sig = ml_dsa_sign_with_context(sk, msg, ctx, rng, params)?;
    let mut bytes = sig.bytes;
    bytes.extend_from_slice(msg);
    Ok(SignedMessage { bytes })
}

/// Deterministically signs a message and returns the serialized `signature || message` form.
pub fn ml_dsa_sign_message_deterministic(
    sk: &SigningKey,
    msg: &[u8],
    params: &Params,
) -> Result<SignedMessage, Error> {
    ml_dsa_sign_message_deterministic_with_context(sk, msg, &[], params)
}

/// Deterministically signs a message with context and returns `signature || message`.
pub fn ml_dsa_sign_message_deterministic_with_context(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    params: &Params,
) -> Result<SignedMessage, Error> {
    let sig = ml_dsa_sign_deterministic_with_context(sk, msg, ctx, params)?;
    let mut bytes = sig.bytes;
    bytes.extend_from_slice(msg);
    Ok(SignedMessage { bytes })
}
