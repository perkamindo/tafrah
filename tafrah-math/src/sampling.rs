extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use tafrah_traits::Error;

/// Sampling functions for ML-KEM
pub mod kem {
    use super::*;
    use crate::field::kem::Q;
    use crate::poly::kem::Poly;

    /// SampleNTT: rejection sampling from SHAKE128 (Algorithm 6, FIPS 203)
    pub fn sample_ntt(seed: &[u8; 34]) -> Poly {
        use sha3::Shake128;

        let mut hasher = Shake128::default();
        hasher.update(seed);
        let mut reader = hasher.finalize_xof();

        let mut poly = Poly::zero();
        let mut j = 0;
        let mut buf = [0u8; 3];

        while j < 256 {
            reader.read(&mut buf);
            let d1 = (buf[0] as u16) | ((buf[1] as u16 & 0x0F) << 8);
            let d2 = ((buf[1] as u16) >> 4) | ((buf[2] as u16) << 4);

            if d1 < Q as u16 {
                poly.coeffs[j] = d1 as i16;
                j += 1;
            }
            if j < 256 && d2 < Q as u16 {
                poly.coeffs[j] = d2 as i16;
                j += 1;
            }
        }
        poly
    }

    /// SamplePolyCBD_eta (Algorithm 7, FIPS 203)
    pub fn sample_cbd(bytes: &[u8], eta: usize) -> Result<Poly, Error> {
        let mut poly = Poly::zero();

        match eta {
            2 => {
                if bytes.len() < 128 {
                    return Err(Error::InvalidParameter);
                }
                // CBD_2: 256/8 = 32 iterations, each reads 4 bytes → 128 bytes total
                for i in 0..32 {
                    let t = u32::from_le_bytes([
                        bytes[4 * i],
                        bytes[4 * i + 1],
                        bytes[4 * i + 2],
                        bytes[4 * i + 3],
                    ]);
                    let mut d = t & 0x55555555;
                    d += (t >> 1) & 0x55555555;
                    for j in 0..8 {
                        let a = ((d >> (4 * j)) & 0x3) as i16;
                        let b = ((d >> (4 * j + 2)) & 0x3) as i16;
                        poly.coeffs[8 * i + j] = a - b;
                    }
                }
            }
            3 => {
                if bytes.len() < 192 {
                    return Err(Error::InvalidParameter);
                }
                // CBD_3: 256/4 = 64 iterations, each reads 3 bytes → 192 bytes total
                for i in 0..64 {
                    let mut t: u32 = 0;
                    t |= bytes[3 * i] as u32;
                    t |= (bytes[3 * i + 1] as u32) << 8;
                    t |= (bytes[3 * i + 2] as u32) << 16;

                    let mut d = t & 0x249249;
                    d += (t >> 1) & 0x249249;
                    d += (t >> 2) & 0x249249;

                    for j in 0..4 {
                        let a = ((d >> (6 * j)) & 0x7) as i16;
                        let b = ((d >> (6 * j + 3)) & 0x7) as i16;
                        poly.coeffs[4 * i + j] = a - b;
                    }
                }
            }
            _ => return Err(Error::InvalidParameter),
        }

        Ok(poly)
    }

    /// PRF_eta: SHAKE256(s || b) → len bytes
    pub fn prf(seed: &[u8; 32], nonce: u8, len: usize) -> Vec<u8> {
        use sha3::Shake256;
        let mut hasher = Shake256::default();
        hasher.update(seed);
        hasher.update(&[nonce]);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; len];
        reader.read(&mut output);
        output
    }

    /// XOF: SHAKE128(rho || i || j) for matrix expansion
    pub fn xof_seed(rho: &[u8; 32], i: u8, j: u8) -> [u8; 34] {
        let mut seed = [0u8; 34];
        seed[..32].copy_from_slice(rho);
        seed[32] = j;
        seed[33] = i;
        seed
    }
}

/// Sampling functions for ML-DSA
pub mod dsa {
    use super::*;
    use crate::field::dsa::Q;
    use crate::poly::dsa::Poly;

    /// Expand matrix element from seed (rejection sampling via SHAKE128)
    pub fn sample_uniform(seed: &[u8]) -> Poly {
        use sha3::Shake128;

        let mut hasher = Shake128::default();
        hasher.update(seed);
        let mut reader = hasher.finalize_xof();

        let mut poly = Poly::zero();
        let mut j = 0;
        let mut buf = [0u8; 3];

        while j < 256 {
            reader.read(&mut buf);
            let t = (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16);
            let t = t & 0x7FFFFF;

            if t < Q {
                poly.coeffs[j] = t as i32;
                j += 1;
            }
        }
        poly
    }

    /// RejBoundedPoly: Sample polynomial with uniformly random coefficients
    /// in [-eta, eta] via rejection sampling on SHAKE256 output.
    /// From pq-crystals/dilithium/ref/poly.c: rej_eta()
    pub fn sample_cbd_eta(seed: &[u8], eta: usize) -> Result<Poly, Error> {
        use sha3::Shake256;

        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut reader = hasher.finalize_xof();

        let mut poly = Poly::zero();
        let mut ctr = 0usize;
        let mut buf = [0u8; 1];

        while ctr < 256 {
            reader.read(&mut buf);
            let t0 = (buf[0] & 0x0F) as u32;
            let t1 = (buf[0] >> 4) as u32;

            match eta {
                2 => {
                    if t0 < 15 {
                        // t0 mod 5 via: t0 - (205*t0 >> 10)*5
                        let t0 = t0 - (205 * t0 >> 10) * 5;
                        poly.coeffs[ctr] = 2 - t0 as i32;
                        ctr += 1;
                    }
                    if t1 < 15 && ctr < 256 {
                        let t1 = t1 - (205 * t1 >> 10) * 5;
                        poly.coeffs[ctr] = 2 - t1 as i32;
                        ctr += 1;
                    }
                }
                4 => {
                    if t0 < 9 {
                        poly.coeffs[ctr] = 4 - t0 as i32;
                        ctr += 1;
                    }
                    if t1 < 9 && ctr < 256 {
                        poly.coeffs[ctr] = 4 - t1 as i32;
                        ctr += 1;
                    }
                }
                _ => return Err(Error::InvalidParameter),
            }
        }

        Ok(poly)
    }

    /// Sample mask polynomial with coefficients in [-(gamma1-1), gamma1]
    pub fn sample_gamma1(seed: &[u8], gamma1_bits: u32) -> Poly {
        use sha3::Shake256;

        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut reader = hasher.finalize_xof();

        let gamma1 = 1i32 << gamma1_bits;
        let mut poly = Poly::zero();

        if gamma1_bits == 17 {
            let mut buf = vec![0u8; 576];
            reader.read(&mut buf);
            for i in 0..256 {
                let bit_offset = i * 18;
                let byte_idx = bit_offset / 8;
                let bit_idx = bit_offset % 8;
                let mut val = (buf[byte_idx] as u32) >> bit_idx;
                if byte_idx + 1 < buf.len() {
                    val |= (buf[byte_idx + 1] as u32) << (8 - bit_idx);
                }
                if byte_idx + 2 < buf.len() {
                    val |= (buf[byte_idx + 2] as u32) << (16 - bit_idx);
                }
                if bit_idx > 6 && byte_idx + 3 < buf.len() {
                    val |= (buf[byte_idx + 3] as u32) << (24 - bit_idx);
                }
                val &= 0x3FFFF;
                poly.coeffs[i] = gamma1 - val as i32;
            }
        } else if gamma1_bits == 19 {
            let mut buf = vec![0u8; 640];
            reader.read(&mut buf);
            for i in 0..256 {
                let bit_offset = i * 20;
                let byte_idx = bit_offset / 8;
                let bit_idx = bit_offset % 8;
                let mut val = (buf[byte_idx] as u32) >> bit_idx;
                if byte_idx + 1 < buf.len() {
                    val |= (buf[byte_idx + 1] as u32) << (8 - bit_idx);
                }
                if byte_idx + 2 < buf.len() {
                    val |= (buf[byte_idx + 2] as u32) << (16 - bit_idx);
                }
                if byte_idx + 3 < buf.len() {
                    val |= (buf[byte_idx + 3] as u32) << (24 - bit_idx);
                }
                val &= 0xFFFFF;
                poly.coeffs[i] = gamma1 - val as i32;
            }
        }

        poly
    }

    /// SampleInBall: sample challenge polynomial c with tau nonzero coefficients in {-1,1}
    pub fn sample_in_ball(seed: &[u8], tau: usize) -> Poly {
        use sha3::Shake256;

        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut reader = hasher.finalize_xof();

        let mut sign_bytes = [0u8; 8];
        reader.read(&mut sign_bytes);
        let signs = u64::from_le_bytes(sign_bytes);

        let mut poly = Poly::zero();
        let mut buf = [0u8; 1];

        for i in (256 - tau)..256 {
            loop {
                reader.read(&mut buf);
                let j = buf[0] as usize;
                if j <= i {
                    poly.coeffs[i] = poly.coeffs[j];
                    let sign_bit = (signs >> (i - (256 - tau))) & 1;
                    poly.coeffs[j] = if sign_bit == 0 { 1 } else { -1 };
                    break;
                }
            }
        }

        poly
    }
}
