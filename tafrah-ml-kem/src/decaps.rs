//! Generic ML-KEM decapsulation entry points.
//!
//! This module exposes the internal K-PKE decryption primitive and the public
//! ML-KEM decapsulation algorithm with implicit rejection from FIPS 203.
extern crate alloc;
use alloc::vec::Vec;

use sha3::digest::{Digest, ExtendableOutput, XofReader};
use sha3::{Sha3_512, Shake256};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use tafrah_math::compress;
use tafrah_math::field::kem as field;
use tafrah_math::poly::kem::Poly;

use crate::encaps::k_pke_encrypt;
use crate::encode;
use crate::params::Params;
use crate::types::{Ciphertext, DecapsulationKey, SharedSecret};
use tafrah_traits::Error;

/// Runs the internal K-PKE decryption primitive from FIPS 203 Algorithm 15.
pub fn k_pke_decrypt(dk: &[u8], ct: &[u8], params: &Params) -> Result<[u8; 32], Error> {
    params.validate()?;
    let k = params.k;

    if dk.len() != 384 * k {
        return Err(Error::InvalidKeyLength);
    }

    if ct.len() != params.ct_size() {
        return Err(Error::InvalidCiphertextLength);
    }

    // Parse s_hat from dk
    let s_hat = encode::decode_poly_vec(dk, k);

    // Parse ciphertext: c1 || c2
    let c1_len = 32 * params.du as usize * k;

    // Decode and decompress u from c1
    let mut u: Vec<Poly> = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * 32 * params.du as usize;
        let compressed =
            encode::byte_decode(&ct[start..start + 32 * params.du as usize], params.du);
        let mut ui = Poly::zero();
        for j in 0..256 {
            ui.coeffs[j] = compress::decompress(compressed.coeffs[j] as u16, params.du);
        }
        u.push(ui);
    }

    // Decode and decompress v from c2
    let v_compressed = encode::byte_decode(&ct[c1_len..], params.dv);
    let mut v = Poly::zero();
    for j in 0..256 {
        v.coeffs[j] = compress::decompress(v_compressed.coeffs[j] as u16, params.dv);
    }

    // NTT(u)
    let mut u_hat: Vec<Poly> = u;
    for p in u_hat.iter_mut() {
        p.ntt();
    }

    // w = v - NTT^{-1}(s_hat^T * u_hat)
    let mut inner = Poly::zero();
    for j in 0..k {
        let prod = s_hat[j].basemul_montgomery(&u_hat[j]);
        inner.add_assign(&prod);
    }
    inner.reduce();
    inner.inv_ntt();

    let mut w = v.sub(&inner);
    w.reduce();

    // m = ByteEncode_1(Compress_1(w))
    let mut m_poly = Poly::zero();
    for j in 0..256 {
        m_poly.coeffs[j] = compress::compress(field::caddq(w.coeffs[j]), 1) as i16;
    }
    let m_bytes = encode::byte_encode(&m_poly, 1);

    let mut m = [0u8; 32];
    m.copy_from_slice(&m_bytes);
    Ok(m)
}

/// Decapsulates an ML-KEM ciphertext with implicit rejection.
///
/// This is the public FIPS 203 Algorithm 18 entry point for callers that work
/// with explicit [`Params`] values.
pub fn ml_kem_decaps(
    dk: &DecapsulationKey,
    ct: &Ciphertext,
    params: &Params,
) -> Result<SharedSecret, Error> {
    params.validate()?;
    let k = params.k;

    if dk.bytes.len() != params.dk_size() {
        return Err(Error::InvalidKeyLength);
    }

    // Parse dk = dk_pke || ek || H(ek) || z
    let dk_pke_len = 384 * k;
    let ek_len = 384 * k + 32;

    let dk_pke = &dk.bytes[..dk_pke_len];
    let ek = &dk.bytes[dk_pke_len..dk_pke_len + ek_len];
    let h_ek = &dk.bytes[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
    let z = &dk.bytes[dk_pke_len + ek_len + 32..dk_pke_len + ek_len + 64];

    // K_bar = J(z || c) -- implicit rejection value
    let mut j_hasher = Shake256::default();
    sha3::digest::Update::update(&mut j_hasher, z);
    sha3::digest::Update::update(&mut j_hasher, &ct.bytes);
    let mut j_reader = j_hasher.finalize_xof();
    let mut k_bar = [0u8; 32];
    j_reader.read(&mut k_bar);

    if ct.bytes.len() != params.ct_size() {
        return Ok(SharedSecret { bytes: k_bar });
    }

    // m' = K-PKE.Decrypt(dk_pke, ct)
    let m_prime = match k_pke_decrypt(dk_pke, &ct.bytes, params) {
        Ok(m_prime) => m_prime,
        Err(Error::InvalidCiphertextLength) => {
            return Ok(SharedSecret { bytes: k_bar });
        }
        Err(err) => return Err(err),
    };

    // (K', r') = G(m' || h(ek))
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(h_ek);
    let g_output = Sha3_512::digest(&g_input);

    let k_prime: [u8; 32] = g_output[..32].try_into().unwrap();
    let r_prime: [u8; 32] = g_output[32..64].try_into().unwrap();

    // c' = K-PKE.Encrypt(ek, m', r')
    let ct_prime = k_pke_encrypt(ek, &m_prime, &r_prime, params)?;

    // If c' == c, return K'; else return K_bar (constant-time)
    let ct_eq = ct.bytes.ct_eq(ct_prime.as_slice());

    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = u8::conditional_select(&k_bar[i], &k_prime[i], ct_eq);
    }

    Ok(SharedSecret { bytes: result })
}
