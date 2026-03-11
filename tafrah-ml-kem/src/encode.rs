/// Byte encoding/decoding for ML-KEM (FIPS 203, Section 4.2.1)
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use tafrah_math::field::kem;
use tafrah_math::poly::kem::Poly;

/// ByteEncode_d: encode polynomial coefficients into bytes
/// Each coefficient is d bits, total = 256*d/8 = 32*d bytes
pub fn byte_encode(poly: &Poly, d: u32) -> Vec<u8> {
    let num_bytes = 32 * d as usize;
    let mut bytes = vec![0u8; num_bytes];

    if d == 12 {
        // Special case for d=12: 3 bytes per 2 coefficients
        for i in 0..128 {
            let a = kem::csubq(kem::caddq(poly.coeffs[2 * i])) as u16;
            let b = kem::csubq(kem::caddq(poly.coeffs[2 * i + 1])) as u16;
            bytes[3 * i] = a as u8;
            bytes[3 * i + 1] = ((a >> 8) | (b << 4)) as u8;
            bytes[3 * i + 2] = (b >> 4) as u8;
        }
    } else {
        // General case: pack d-bit values
        let mask = (1u32 << d) - 1;
        let mut bit_pos = 0usize;
        for i in 0..256 {
            let val = (kem::caddq(poly.coeffs[i]) as u16 as u32) & mask;
            for b in 0..d as usize {
                if (val >> b) & 1 == 1 {
                    let byte_idx = bit_pos / 8;
                    let bit_idx = bit_pos % 8;
                    bytes[byte_idx] |= 1 << bit_idx;
                }
                bit_pos += 1;
            }
        }
    }

    bytes
}

/// ByteDecode_d: decode bytes into polynomial coefficients
pub fn byte_decode(bytes: &[u8], d: u32) -> Poly {
    let mut poly = Poly::zero();

    if d == 12 {
        for i in 0..128 {
            poly.coeffs[2 * i] = (bytes[3 * i] as i16) | (((bytes[3 * i + 1] & 0x0F) as i16) << 8);
            poly.coeffs[2 * i + 1] =
                ((bytes[3 * i + 1] >> 4) as i16) | ((bytes[3 * i + 2] as i16) << 4);
        }
    } else {
        let mask = (1u32 << d) - 1;
        let mut bit_pos = 0usize;
        for i in 0..256 {
            let mut val = 0u32;
            for b in 0..d as usize {
                let byte_idx = bit_pos / 8;
                let bit_idx = bit_pos % 8;
                if byte_idx < bytes.len() {
                    val |= (((bytes[byte_idx] >> bit_idx) & 1) as u32) << b;
                }
                bit_pos += 1;
            }
            poly.coeffs[i] = (val & mask) as i16;
        }
    }

    poly
}

/// Encode a vector of polynomials (each at 12 bits per coefficient)
pub fn encode_poly_vec(polys: &[Poly]) -> Vec<u8> {
    let mut result = Vec::new();
    for p in polys {
        result.extend_from_slice(&byte_encode(p, 12));
    }
    result
}

/// Decode bytes into a vector of polynomials (each at 12 bits per coefficient)
pub fn decode_poly_vec(bytes: &[u8], k: usize) -> Vec<Poly> {
    let mut polys = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * 384; // 32 * 12 = 384
        polys.push(byte_decode(&bytes[start..start + 384], 12));
    }
    polys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip_d12() {
        let mut poly = Poly::zero();
        for i in 0..256 {
            poly.coeffs[i] = (i as i16) % 3329;
        }
        let encoded = byte_encode(&poly, 12);
        let decoded = byte_decode(&encoded, 12);
        for i in 0..256 {
            let orig = kem::caddq(poly.coeffs[i]);
            assert_eq!(decoded.coeffs[i], orig, "mismatch at {}", i);
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_d10() {
        let mut poly = Poly::zero();
        for i in 0..256 {
            poly.coeffs[i] = (i as i16) % 1024;
        }
        let encoded = byte_encode(&poly, 10);
        let decoded = byte_decode(&encoded, 10);
        for i in 0..256 {
            assert_eq!(decoded.coeffs[i], poly.coeffs[i], "mismatch at {}", i);
        }
    }
}
