/// Bit packing/unpacking for ML-DSA (FIPS 204)
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use tafrah_math::field::dsa::Q_I32;
use tafrah_math::poly::dsa::Poly;

/// Pack polynomial with coefficients in [0, 2^bits - 1]
pub fn pack_poly(poly: &Poly, bits: u32) -> Vec<u8> {
    let num_bytes = (256 * bits as usize + 7) / 8;
    let mut bytes = vec![0u8; num_bytes];
    let mask = (1u64 << bits) - 1;

    let mut bit_pos = 0usize;
    for i in 0..256 {
        let val = (poly.coeffs[i] as u64) & mask;
        for b in 0..bits as usize {
            if (val >> b) & 1 == 1 {
                bytes[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
            bit_pos += 1;
        }
    }
    bytes
}

/// Unpack polynomial with coefficients in [0, 2^bits - 1]
pub fn unpack_poly(bytes: &[u8], bits: u32) -> Poly {
    let mut poly = Poly::zero();
    let mask = (1u64 << bits) - 1;

    let mut bit_pos = 0usize;
    for i in 0..256 {
        let mut val = 0u64;
        for b in 0..bits as usize {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < bytes.len() {
                val |= (((bytes[byte_idx] >> bit_idx) & 1) as u64) << b;
            }
            bit_pos += 1;
        }
        poly.coeffs[i] = (val & mask) as i32;
    }
    poly
}

/// Pack t1 (coefficients in [0, 2^(ceil(log2(q)) - d) - 1])
/// For ML-DSA, d=13, so t1 coefficients are 10 bits
pub fn pack_t1(poly: &Poly) -> Vec<u8> {
    pack_poly(poly, 10)
}

/// Unpack t1
pub fn unpack_t1(bytes: &[u8]) -> Poly {
    unpack_poly(bytes, 10)
}

/// Pack t0 (coefficients centered around 0, range [-(2^(d-1)-1), 2^(d-1)])
/// For d=13, t0 in [-4095, 4096], stored as 13-bit unsigned (offset by 2^(d-1))
pub fn pack_t0(poly: &Poly) -> Vec<u8> {
    let mut adjusted = Poly::zero();
    for i in 0..256 {
        // Map from [-(2^12-1), 2^12] = [-4095, 4096] to [0, 8191]
        adjusted.coeffs[i] = (1 << 12) - poly.coeffs[i];
    }
    pack_poly(&adjusted, 13)
}

/// Unpack t0
pub fn unpack_t0(bytes: &[u8]) -> Poly {
    let mut poly = unpack_poly(bytes, 13);
    for i in 0..256 {
        poly.coeffs[i] = (1 << 12) - poly.coeffs[i];
    }
    poly
}

/// Pack eta (coefficients in [-eta, eta])
pub(crate) fn pack_eta(poly: &Poly, eta: usize) -> Vec<u8> {
    match eta {
        2 => {
            // Map [-2, 2] → [0, 4], pack 3 bits per coefficient
            let mut adjusted = Poly::zero();
            for i in 0..256 {
                adjusted.coeffs[i] = (eta as i32 - poly.coeffs[i]) as i32;
            }
            pack_poly(&adjusted, 3)
        }
        4 => {
            // Map [-4, 4] → [0, 8], pack 4 bits per coefficient
            let mut adjusted = Poly::zero();
            for i in 0..256 {
                adjusted.coeffs[i] = (eta as i32 - poly.coeffs[i]) as i32;
            }
            pack_poly(&adjusted, 4)
        }
        _ => panic!("unsupported eta: {}", eta),
    }
}

/// Unpack eta
pub(crate) fn unpack_eta(bytes: &[u8], eta: usize) -> Poly {
    match eta {
        2 => {
            let mut poly = unpack_poly(bytes, 3);
            for i in 0..256 {
                poly.coeffs[i] = eta as i32 - poly.coeffs[i];
            }
            poly
        }
        4 => {
            let mut poly = unpack_poly(bytes, 4);
            for i in 0..256 {
                poly.coeffs[i] = eta as i32 - poly.coeffs[i];
            }
            poly
        }
        _ => panic!("unsupported eta: {}", eta),
    }
}

/// Pack z (coefficients in [-(gamma1-1), gamma1])
pub fn pack_z(poly: &Poly, gamma1_bits: u32) -> Vec<u8> {
    let gamma1 = 1i32 << gamma1_bits;
    let mut adjusted = Poly::zero();
    for i in 0..256 {
        adjusted.coeffs[i] = gamma1 - poly.coeffs[i];
    }
    pack_poly(&adjusted, gamma1_bits + 1)
}

/// Unpack z
pub fn unpack_z(bytes: &[u8], gamma1_bits: u32) -> Poly {
    let gamma1 = 1i32 << gamma1_bits;
    let mut poly = unpack_poly(bytes, gamma1_bits + 1);
    for i in 0..256 {
        poly.coeffs[i] = gamma1 - poly.coeffs[i];
    }
    poly
}

/// Pack w1 (the high-order bits)
pub fn pack_w1(poly: &Poly, gamma2: i32) -> Vec<u8> {
    let q_minus_1 = Q_I32 - 1;
    if gamma2 == q_minus_1 / 88 {
        // ML-DSA-44: w1 in [0, 43], need 6 bits
        pack_poly(poly, 6)
    } else {
        // ML-DSA-65/87: w1 in [0, 15], need 4 bits
        pack_poly(poly, 4)
    }
}

/// Encode hint vector as per FIPS 204
pub fn pack_hint(hint: &[Vec<bool>], omega: usize) -> Vec<u8> {
    let k = hint.len();
    let mut bytes = vec![0u8; omega + k];
    let mut idx = 0;

    for i in 0..k {
        for j in 0..256 {
            if hint[i][j] {
                bytes[idx] = j as u8;
                idx += 1;
            }
        }
        bytes[omega + i] = idx as u8;
    }

    bytes
}

/// Decode hint vector (matches reference packing.c unpack_sig hint section)
pub fn unpack_hint(bytes: &[u8], k: usize, omega: usize) -> Option<Vec<Vec<bool>>> {
    let mut hint: Vec<Vec<bool>> = Vec::with_capacity(k);
    let mut idx: usize = 0;

    for i in 0..k {
        let mut h = vec![false; 256];
        let limit = bytes[omega + i] as usize;

        if limit < idx || limit > omega {
            return None;
        }

        let start = idx;
        while idx < limit {
            // Only check ordering within the same polynomial (not across boundaries)
            if idx > start && bytes[idx] <= bytes[idx - 1] {
                return None;
            }
            h[bytes[idx] as usize] = true;
            idx += 1;
        }

        hint.push(h);
    }

    // Remaining entries must be zero
    while idx < omega {
        if bytes[idx] != 0 {
            return None;
        }
        idx += 1;
    }

    Some(hint)
}
