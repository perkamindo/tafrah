/// Compress and Decompress for ML-KEM (FIPS 203, Section 4.2.1)
use crate::field::kem::Q;

/// Compress_d(x) = round((2^d / q) * x) mod 2^d
#[inline]
pub fn compress(x: i16, d: u32) -> u16 {
    // Ensure x is in [0, q)
    let x = ((x as i32 % Q as i32 + Q as i32) % Q as i32) as u32;
    let two_d = 1u64 << d;
    let result = ((x as u64 * two_d + Q as u64 / 2) / Q as u64) & (two_d - 1);
    result as u16
}

/// Decompress_d(y) = round((q / 2^d) * y)
#[inline]
pub fn decompress(y: u16, d: u32) -> i16 {
    let two_d = 1u64 << d;
    let result = (y as u64 * Q as u64 + (two_d / 2)) / two_d;
    result as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        for d in [1u32, 4, 5, 10, 11] {
            for x in (0..Q as i16).step_by(100) {
                let compressed = compress(x, d);
                let decompressed = decompress(compressed, d);

                let diff = (x as i32 - decompressed as i32).abs();
                let diff = core::cmp::min(diff, Q as i32 - diff);
                let max_error = (Q as i32) / (1i32 << (d + 1)) + 1;
                assert!(
                    diff <= max_error,
                    "d={}, x={}, c={}, dec={}, diff={}, max_err={}",
                    d,
                    x,
                    compressed,
                    decompressed,
                    diff,
                    max_error
                );
            }
        }
    }

    #[test]
    fn test_compress_range() {
        for d in [1u32, 4, 10, 11] {
            let max_val = (1u16 << d) - 1;
            for x in 0..Q as i16 {
                let c = compress(x, d);
                assert!(c <= max_val, "d={}, x={}, compressed={}", d, x, c);
            }
        }
    }
}
