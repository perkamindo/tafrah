//! Generic ML-KEM encapsulation entry points.
//!
//! This module exposes the internal K-PKE encryption primitive and the public
//! ML-KEM encapsulation algorithm from FIPS 203.
extern crate alloc;
use alloc::vec::Vec;

use sha3::digest::Digest;
use sha3::{Sha3_256, Sha3_512};

use tafrah_math::compress;
use tafrah_math::field::kem as field;
use tafrah_math::poly::kem::Poly;
use tafrah_math::sampling::kem;

use crate::encode;
use crate::params::Params;
use crate::types::{Ciphertext, EncapsulationKey, SharedSecret};
use tafrah_traits::Error;

/// Runs the internal K-PKE encryption primitive from FIPS 203 Algorithm 14.
pub fn k_pke_encrypt(
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
    params: &Params,
) -> Result<Vec<u8>, Error> {
    params.validate()?;
    let k = params.k;

    if ek.len() != params.ek_size() {
        return Err(Error::InvalidKeyLength);
    }

    // Parse ek = t_hat || ρ
    let t_hat = encode::decode_poly_vec(&ek[..384 * k], k);
    let rho: [u8; 32] = ek[384 * k..384 * k + 32].try_into().unwrap();

    // Reconstruct A_hat from ρ
    let mut a_hat: Vec<Vec<Poly>> = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(k);
        for j in 0..k {
            let seed = kem::xof_seed(&rho, i as u8, j as u8);
            row.push(kem::sample_ntt(&seed));
        }
        a_hat.push(row);
    }

    // Sample r_vec, e1, e2 using CBD
    let mut r_vec: Vec<Poly> = Vec::with_capacity(k);
    let mut e1: Vec<Poly> = Vec::with_capacity(k);
    let mut n: u8 = 0;

    for _ in 0..k {
        let prf_output = kem::prf(r, n, params.eta1_bytes);
        r_vec.push(kem::sample_cbd(&prf_output, params.eta1)?);
        n += 1;
    }
    for _ in 0..k {
        let prf_output = kem::prf(r, n, params.eta2_bytes);
        e1.push(kem::sample_cbd(&prf_output, params.eta2)?);
        n += 1;
    }
    let prf_output = kem::prf(r, n, params.eta2_bytes);
    let e2 = kem::sample_cbd(&prf_output, params.eta2)?;

    // NTT(r)
    let mut r_hat: Vec<Poly> = r_vec;
    for p in r_hat.iter_mut() {
        p.ntt();
    }

    // u = NTT^{-1}(A^T * r_hat) + e1
    let mut u: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let mut ui = Poly::zero();
        for j in 0..k {
            let prod = a_hat[j][i].basemul_montgomery(&r_hat[j]);
            ui.add_assign(&prod);
        }
        ui.reduce();
        ui.inv_ntt();
        ui = ui.add(&e1[i]);
        ui.reduce();
        u.push(ui);
    }

    // v = NTT^{-1}(t_hat^T * r_hat) + e2 + Decompress_1(m)
    let mut v = Poly::zero();
    for j in 0..k {
        let prod = t_hat[j].basemul_montgomery(&r_hat[j]);
        v.add_assign(&prod);
    }
    v.reduce();
    v.inv_ntt();
    v = v.add(&e2);
    v.reduce();

    // Decode message m as polynomial and add
    let m_poly = encode::byte_decode(m, 1);
    let mut m_decompressed = Poly::zero();
    for i in 0..256 {
        m_decompressed.coeffs[i] = compress::decompress(m_poly.coeffs[i] as u16, 1);
    }
    v = v.add(&m_decompressed);

    // c1 = ByteEncode_du(Compress_du(u))
    let mut ct = Vec::new();
    for ui in &u {
        let mut compressed = Poly::zero();
        for j in 0..256 {
            compressed.coeffs[j] = compress::compress(field::caddq(ui.coeffs[j]), params.du) as i16;
        }
        ct.extend_from_slice(&encode::byte_encode(&compressed, params.du));
    }

    // c2 = ByteEncode_dv(Compress_dv(v))
    let mut v_compressed = Poly::zero();
    for j in 0..256 {
        v_compressed.coeffs[j] = compress::compress(field::caddq(v.coeffs[j]), params.dv) as i16;
    }
    ct.extend_from_slice(&encode::byte_encode(&v_compressed, params.dv));

    Ok(ct)
}

/// Encapsulates a fresh shared secret for an ML-KEM public key.
///
/// This is the public FIPS 203 Algorithm 17 entry point for callers that work
/// with explicit [`Params`] values.
pub fn ml_kem_encaps(
    ek: &EncapsulationKey,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    params: &Params,
) -> Result<(Ciphertext, SharedSecret), Error> {
    params.validate()?;
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);

    let h_ek = Sha3_256::digest(&ek.bytes);

    // (K, r) = G(m || H(ek))
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m);
    g_input[32..].copy_from_slice(&h_ek);
    let g_output = Sha3_512::digest(&g_input);

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&g_output[..32]);
    let r: [u8; 32] = g_output[32..64].try_into().unwrap();

    let ct_bytes = k_pke_encrypt(&ek.bytes, &m, &r, params)?;

    Ok((
        Ciphertext { bytes: ct_bytes },
        SharedSecret {
            bytes: shared_secret,
        },
    ))
}
