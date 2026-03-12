//! Generic ML-KEM key generation entry points.
//!
//! This module exposes both the internal K-PKE key generation primitive and the
//! public ML-KEM key generation API from FIPS 203.
extern crate alloc;
use alloc::vec::Vec;

use sha3::digest::Digest;
use sha3::{Sha3_256, Sha3_512};

use tafrah_math::poly::kem::Poly;
use tafrah_math::sampling::kem;

use crate::encode;
use crate::params::Params;
use crate::types::{DecapsulationKey, EncapsulationKey};
use tafrah_traits::Error;

/// Runs the internal K-PKE key generation primitive from FIPS 203 Algorithm 13.
///
/// The returned tuple is `(ek_pke, dk_pke)` before the ML-KEM decapsulation key
/// wrapper appends the public key hash and implicit-rejection seed.
pub fn k_pke_keygen(d: &[u8; 32], params: &Params) -> Result<(Vec<u8>, Vec<u8>), Error> {
    params.validate()?;
    let k = params.k;

    // (ρ, σ) = G(d || k)
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = k as u8;

    let g_output = Sha3_512::digest(&g_input);
    let rho: [u8; 32] = g_output[..32].try_into().unwrap();
    let sigma: [u8; 32] = g_output[32..64].try_into().unwrap();

    // Generate matrix A in NTT domain from ρ
    let mut a_hat: Vec<Vec<Poly>> = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(k);
        for j in 0..k {
            let seed = kem::xof_seed(&rho, i as u8, j as u8);
            row.push(kem::sample_ntt(&seed));
        }
        a_hat.push(row);
    }

    // Sample s and e using CBD
    let mut s: Vec<Poly> = Vec::with_capacity(k);
    let mut e: Vec<Poly> = Vec::with_capacity(k);
    let mut n: u8 = 0;

    for _ in 0..k {
        let prf_output = kem::prf(&sigma, n, params.eta1_bytes);
        s.push(kem::sample_cbd(&prf_output, params.eta1)?);
        n += 1;
    }
    for _ in 0..k {
        let prf_output = kem::prf(&sigma, n, params.eta1_bytes);
        e.push(kem::sample_cbd(&prf_output, params.eta1)?);
        n += 1;
    }

    // NTT(s), NTT(e)
    let mut s_hat: Vec<Poly> = s;
    let mut e_hat: Vec<Poly> = e;
    for p in s_hat.iter_mut() {
        p.ntt();
    }
    for p in e_hat.iter_mut() {
        p.ntt();
    }

    // t_hat = A_hat * s_hat + e_hat
    // Per Kyber ref: basemul_acc, then tomont (convert from Montgomery), then add e
    let mut t_hat: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut ti = Poly::zero();
        for j in 0..k {
            let prod = a_hat[i][j].basemul_montgomery(&s_hat[j]);
            ti.add_assign(&prod);
        }
        ti.reduce();
        ti.tomont();
        ti.add_assign(&e_hat[i]);
        ti.reduce();
        t_hat.push(ti);
    }

    // ek = ByteEncode_12(t_hat) || ρ
    let mut ek_bytes = encode::encode_poly_vec(&t_hat);
    ek_bytes.extend_from_slice(&rho);

    // dk = ByteEncode_12(s_hat) — must reduce to [0, q) before 12-bit encoding
    for p in s_hat.iter_mut() {
        p.reduce();
    }
    let dk_bytes = encode::encode_poly_vec(&s_hat);

    Ok((ek_bytes, dk_bytes))
}

/// Generates an ML-KEM encapsulation key and decapsulation key pair.
///
/// This is the public FIPS 203 Algorithm 16 entry point for callers that work
/// with explicit [`Params`] values.
pub fn ml_kem_keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<(EncapsulationKey, DecapsulationKey), Error> {
    params.validate()?;
    let mut d = [0u8; 32];
    rng.fill_bytes(&mut d);
    let mut z = [0u8; 32];
    rng.fill_bytes(&mut z);

    let (ek_pke, dk_pke) = k_pke_keygen(&d, params)?;

    let h_ek = Sha3_256::digest(&ek_pke);

    // dk = dk_pke || ek || H(ek) || z
    let mut dk_bytes = dk_pke;
    dk_bytes.extend_from_slice(&ek_pke);
    dk_bytes.extend_from_slice(&h_ek);
    dk_bytes.extend_from_slice(&z);

    Ok((
        EncapsulationKey { bytes: ek_pke },
        DecapsulationKey { bytes: dk_bytes },
    ))
}
