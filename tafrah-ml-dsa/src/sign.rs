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
use crate::types::{Signature, SigningKey};
use tafrah_traits::Error;

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
    params.validate()?;
    let k = params.k;
    let l = params.l;

    if sk.bytes.len() != params.sk_size() {
        return Err(Error::InvalidKeyLength);
    }

    let eta_bytes = params.eta_bytes();
    if eta_bytes == 0 {
        return Err(Error::InvalidParameter);
    }

    let (pre, prelen) = build_context_prefix(ctx)?;

    // Parse sk = ρ || K || tr || s1 || s2 || t0
    let rho = &sk.bytes[..32];
    let key_k = &sk.bytes[32..64];
    let tr = &sk.bytes[64..128];

    let mut offset = 128;
    let mut s1: Vec<Poly> = Vec::with_capacity(l);
    for _ in 0..l {
        s1.push(encode::unpack_eta(
            &sk.bytes[offset..offset + eta_bytes],
            params.eta,
        ));
        offset += eta_bytes;
    }
    let mut s2: Vec<Poly> = Vec::with_capacity(k);
    for _ in 0..k {
        s2.push(encode::unpack_eta(
            &sk.bytes[offset..offset + eta_bytes],
            params.eta,
        ));
        offset += eta_bytes;
    }
    let t0_bytes = 416; // 256 * 13 / 8
    let mut t0: Vec<Poly> = Vec::with_capacity(k);
    for _ in 0..k {
        t0.push(encode::unpack_t0(&sk.bytes[offset..offset + t0_bytes]));
        offset += t0_bytes;
    }

    // NTT(s1), NTT(s2), NTT(t0)
    let mut s1_hat: Vec<Poly> = s1.clone();
    let mut s2_hat: Vec<Poly> = s2.clone();
    let mut t0_hat: Vec<Poly> = t0.clone();
    for p in s1_hat.iter_mut() {
        p.ntt();
    }
    for p in s2_hat.iter_mut() {
        p.ntt();
    }
    for p in t0_hat.iter_mut() {
        p.ntt();
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

    // μ = H(tr || pre || M)
    let mut mu_hasher = Shake256::default();
    sha3::digest::Update::update(&mut mu_hasher, tr);
    sha3::digest::Update::update(&mut mu_hasher, &pre[..prelen]);
    sha3::digest::Update::update(&mut mu_hasher, msg);
    let mut mu_reader = mu_hasher.finalize_xof();
    let mut mu = [0u8; 64];
    mu_reader.read(&mut mu);

    // ρ'' = H(K || rnd || μ) where rnd is random or deterministic
    let mut rnd = [0u8; 32];
    rng.fill_bytes(&mut rnd);

    let mut rho_pp_hasher = Shake256::default();
    sha3::digest::Update::update(&mut rho_pp_hasher, key_k);
    sha3::digest::Update::update(&mut rho_pp_hasher, &rnd);
    sha3::digest::Update::update(&mut rho_pp_hasher, &mu);
    let mut rho_pp_reader = rho_pp_hasher.finalize_xof();
    let mut rho_pp = [0u8; 64];
    rho_pp_reader.read(&mut rho_pp);

    // Rejection sampling loop
    let mut kappa: u16 = 0;
    let alpha = 2 * params.gamma2;

    loop {
        // y = ExpandMask(ρ'', κ)
        let mut y: Vec<Poly> = Vec::with_capacity(l);
        for i in 0..l {
            let counter = kappa + i as u16;
            let mut seed = Vec::with_capacity(66);
            seed.extend_from_slice(&rho_pp);
            seed.push((counter & 0xFF) as u8);
            seed.push((counter >> 8) as u8);
            y.push(dsa::sample_gamma1(&seed, params.gamma1_bits));
        }
        kappa += l as u16;

        // w = NTT^{-1}(A_hat * NTT(y))
        let mut y_hat: Vec<Poly> = y.clone();
        for p in y_hat.iter_mut() {
            p.ntt();
        }

        let mut w: Vec<Poly> = Vec::with_capacity(k);
        for i in 0..k {
            let mut wi = Poly::zero();
            for j in 0..l {
                let prod = a_hat[i][j].pointwise_mul(&y_hat[j]);
                wi.add_assign(&prod);
            }
            wi.reduce(); // reduce before inv_ntt to prevent i32 overflow
            wi.inv_ntt();
            wi.caddq();
            w.push(wi);
        }

        // Decompose w into high and low bits.
        let mut w1: Vec<Poly> = Vec::with_capacity(k);
        let mut w0: Vec<Poly> = Vec::with_capacity(k);
        for i in 0..k {
            let mut w1i = Poly::zero();
            let mut w0i = Poly::zero();
            for j in 0..256 {
                let (hi, lo) = hint::decompose(w[i].coeffs[j], alpha);
                w1i.coeffs[j] = hi;
                w0i.coeffs[j] = lo;
            }
            w1.push(w1i);
            w0.push(w0i);
        }

        // c_tilde = H(μ || w1Encode(w1))
        let mut c_hasher = Shake256::default();
        sha3::digest::Update::update(&mut c_hasher, &mu);
        for p in &w1 {
            let packed = encode::pack_w1(p, params.gamma2);
            sha3::digest::Update::update(&mut c_hasher, &packed);
        }
        let mut c_reader = c_hasher.finalize_xof();
        let mut c_tilde = alloc::vec![0u8; params.c_tilde_bytes];
        c_reader.read(&mut c_tilde);

        // c = SampleInBall(c_tilde)
        let mut c = dsa::sample_in_ball(&c_tilde, params.tau);
        c.ntt();

        // z = y + c * s1
        let mut z: Vec<Poly> = Vec::with_capacity(l);
        for i in 0..l {
            let mut cs1_time = c.pointwise_mul(&s1_hat[i]);
            cs1_time.inv_ntt();
            let mut zi = y[i].add(&cs1_time);
            zi.reduce(); // center z for check_norm
            z.push(zi);
        }

        // c * s2
        let mut cs2: Vec<Poly> = Vec::with_capacity(k);
        for i in 0..k {
            let mut p = c.pointwise_mul(&s2_hat[i]);
            p.inv_ntt();
            cs2.push(p);
        }

        // Check ||z||_inf < gamma1 - beta
        let z_bound = params.gamma1 - params.beta;
        let mut reject = false;
        for zi in &z {
            if !zi.check_norm(z_bound) {
                reject = true;
                break;
            }
        }
        if reject {
            continue;
        }

        // Check ||w0 - c*s2||_inf < gamma2 - beta
        let mut w0_minus_cs2: Vec<Poly> = Vec::with_capacity(k);
        for i in 0..k {
            let mut w0i = w0[i].sub(&cs2[i]);
            w0i.reduce();
            w0_minus_cs2.push(w0i);
        }

        let r0_bound = params.gamma2 - params.beta;
        reject = false;
        for w0i in &w0_minus_cs2 {
            if !w0i.check_norm(r0_bound) {
                reject = true;
                break;
            }
        }
        if reject {
            continue;
        }

        // Compute hint
        let mut ct0: Vec<Poly> = Vec::with_capacity(k);
        for i in 0..k {
            let mut p = c.pointwise_mul(&t0_hat[i]);
            p.inv_ntt();
            p.reduce(); // center for check_norm
            ct0.push(p);
        }

        // Check ||ct0||_inf < gamma2
        reject = false;
        for ct0i in &ct0 {
            if !ct0i.check_norm(params.gamma2) {
                reject = true;
                break;
            }
        }
        if reject {
            continue;
        }

        // w0 - c*s2 + c*t0 for hint generation
        let mut hint_vec: Vec<Vec<bool>> = Vec::with_capacity(k);
        let mut total_hints = 0usize;
        for i in 0..k {
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

        // Encode signature: c_tilde || z || hint
        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(&c_tilde);
        for zi in &z {
            sig_bytes.extend_from_slice(&encode::pack_z(zi, params.gamma1_bits));
        }
        sig_bytes.extend_from_slice(&encode::pack_hint(&hint_vec, params.omega));

        return Ok(Signature { bytes: sig_bytes });
    }
}
