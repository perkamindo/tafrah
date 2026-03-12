//! Generic ML-DSA key generation entry point.

extern crate alloc;
use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, XofReader};
use sha3::Shake256;

use tafrah_math::poly::dsa::Poly;
use tafrah_math::sampling::dsa;

use crate::encode;
use crate::hint;
use crate::params::Params;
use crate::types::{SigningKey, VerifyingKey};
use tafrah_traits::Error;

fn ml_dsa_keygen_from_seed(
    seed: &[u8; 32],
    params: &Params,
) -> Result<(VerifyingKey, SigningKey), Error> {
    params.validate()?;
    let k = params.k;
    let l = params.l;

    // (ρ, ρ', K) = H(ξ || k || l)
    let mut h_input = Vec::with_capacity(34);
    h_input.extend_from_slice(seed);
    h_input.push(k as u8);
    h_input.push(l as u8);

    let mut hasher = Shake256::default();
    sha3::digest::Update::update(&mut hasher, &h_input);
    let mut reader = hasher.finalize_xof();
    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut key_k = [0u8; 32];
    reader.read(&mut rho);
    reader.read(&mut rho_prime);
    reader.read(&mut key_k);

    // Expand matrix A from ρ
    let mut a_hat: Vec<Vec<Poly>> = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(l);
        for j in 0..l {
            let mut seed = Vec::with_capacity(34);
            seed.extend_from_slice(&rho);
            seed.push(j as u8);
            seed.push(i as u8);
            row.push(dsa::sample_uniform(&seed));
        }
        a_hat.push(row);
    }

    // Sample s1, s2 from CBD
    let mut s1: Vec<Poly> = Vec::with_capacity(l);
    let mut s2: Vec<Poly> = Vec::with_capacity(k);

    for i in 0..l {
        let mut seed = Vec::with_capacity(66);
        seed.extend_from_slice(&rho_prime);
        seed.push(i as u8);
        seed.push(0u8);
        s1.push(dsa::sample_cbd_eta(&seed, params.eta)?);
    }
    for i in 0..k {
        let mut seed = Vec::with_capacity(66);
        seed.extend_from_slice(&rho_prime);
        seed.push((l + i) as u8);
        seed.push(0u8);
        s2.push(dsa::sample_cbd_eta(&seed, params.eta)?);
    }

    // NTT(s1)
    let mut s1_hat: Vec<Poly> = s1.clone();
    for p in &mut s1_hat {
        p.ntt();
    }

    // t = A * s1 + s2 (in NTT domain, then INTT)
    let mut t: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut ti = Poly::zero();
        for j in 0..l {
            let prod = a_hat[i][j].pointwise_mul(&s1_hat[j]);
            ti.add_assign(&prod);
        }
        ti.reduce();
        ti.inv_ntt();
        ti = ti.add(&s2[i]);
        ti.caddq();
        t.push(ti);
    }

    // (t1, t0) = Power2Round(t)
    let mut t1: Vec<Poly> = Vec::with_capacity(k);
    let mut t0: Vec<Poly> = Vec::with_capacity(k);
    for poly in &t {
        let mut t1i = Poly::zero();
        let mut t0i = Poly::zero();
        for j in 0..256 {
            let (hi, lo) = hint::power2round(poly.coeffs[j], params.d);
            t1i.coeffs[j] = hi;
            t0i.coeffs[j] = lo;
        }
        t1.push(t1i);
        t0.push(t0i);
    }

    // pk = ρ || ByteEncode(t1)
    let mut pk_bytes = Vec::new();
    pk_bytes.extend_from_slice(&rho);
    for p in &t1 {
        pk_bytes.extend_from_slice(&encode::pack_t1(p));
    }

    // tr = H(pk)
    let mut tr_hasher = Shake256::default();
    sha3::digest::Update::update(&mut tr_hasher, &pk_bytes);
    let mut tr_reader = tr_hasher.finalize_xof();
    let mut tr = [0u8; 64];
    tr_reader.read(&mut tr);

    // sk = ρ || K || tr || ByteEncode(s1) || ByteEncode(s2) || ByteEncode(t0)
    let mut sk_bytes = Vec::new();
    sk_bytes.extend_from_slice(&rho);
    sk_bytes.extend_from_slice(&key_k);
    sk_bytes.extend_from_slice(&tr);
    for p in &s1 {
        sk_bytes.extend_from_slice(&encode::pack_eta(p, params.eta));
    }
    for p in &s2 {
        sk_bytes.extend_from_slice(&encode::pack_eta(p, params.eta));
    }
    for p in &t0 {
        sk_bytes.extend_from_slice(&encode::pack_t0(p));
    }

    Ok((
        VerifyingKey { bytes: pk_bytes },
        SigningKey { bytes: sk_bytes },
    ))
}

/// Generates an ML-DSA verifying key and signing key pair.
///
/// This is the public FIPS 204 key generation entry point for callers that
/// work with explicit [`Params`] values.
pub fn ml_dsa_keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<(VerifyingKey, SigningKey), Error> {
    let mut xi = [0u8; 32];
    rng.fill_bytes(&mut xi);
    ml_dsa_keygen_internal(&xi, params)
}

/// Generates an ML-DSA keypair from caller-supplied seed bytes.
///
/// This matches the internal FIPS 204 key generation flow and is useful for
/// deterministic KAT reproduction.
pub fn ml_dsa_keygen_internal(
    seed: &[u8; 32],
    params: &Params,
) -> Result<(VerifyingKey, SigningKey), Error> {
    ml_dsa_keygen_from_seed(seed, params)
}
