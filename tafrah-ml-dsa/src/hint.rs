/// Hint functions for ML-DSA (FIPS 204)
/// Power2Round, Decompose, MakeHint, UseHint
use tafrah_math::field::dsa::{freeze, Q_I32};
use tafrah_traits::Error;

/// Power2Round: split r into (r1, r0) such that r = r1 * 2^d + r0
/// Returns (r1, r0) with r0 in ]-2^(d-1), 2^(d-1)].
pub fn power2round(r: i32, d: u32) -> (i32, i32) {
    let r = freeze(r);
    let r1 = (r + (1 << (d - 1)) - 1) >> d;
    let r0 = r - (r1 << d);
    (r1, r0)
}

/// Decompose: split r into (r1, r0) such that r = r1 * alpha + r0
/// with the same corner cases as the Dilithium/ML-DSA reference implementation.
pub(crate) fn decompose(r: i32, alpha: i32) -> (i32, i32) {
    let r = freeze(r);
    let mut r1 = (r + 127) >> 7;

    if alpha == 2 * ((Q_I32 - 1) / 32) {
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15;
    } else if alpha == 2 * ((Q_I32 - 1) / 88) {
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        r1 ^= ((43 - r1) >> 31) & r1;
    } else {
        panic!("unsupported alpha: {alpha}");
    }

    let mut r0 = r - r1 * alpha;
    r0 -= (((Q_I32 - 1) / 2 - r0) >> 31) & Q_I32;
    (r1, r0)
}

/// HighBits: extract r1 from decompose
#[cfg(test)]
pub(crate) fn high_bits(r: i32, alpha: i32) -> i32 {
    decompose(r, alpha).0
}

/// LowBits: extract r0 from decompose
#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn low_bits(r: i32, alpha: i32) -> i32 {
    decompose(r, alpha).1
}

/// MakeHint: compute hint bit from the adjusted low bits and current high bits.
pub fn make_hint(a0: i32, a1: i32, alpha: i32) -> bool {
    let gamma2 = alpha / 2;
    !(a0 <= gamma2 || a0 > Q_I32 - gamma2 || (a0 == Q_I32 - gamma2 && a1 == 0))
}

/// UseHint: apply hint to adjust HighBits
pub(crate) fn use_hint(h: bool, r: i32, alpha: i32) -> i32 {
    let (r1, r0) = decompose(r, alpha);

    if !h {
        return r1;
    }

    if alpha == 2 * ((Q_I32 - 1) / 32) {
        if r0 > 0 {
            (r1 + 1) & 15
        } else {
            (r1 - 1) & 15
        }
    } else if alpha == 2 * ((Q_I32 - 1) / 88) {
        if r0 > 0 {
            if r1 == 43 {
                0
            } else {
                r1 + 1
            }
        } else if r1 == 0 {
            43
        } else {
            r1 - 1
        }
    } else {
        panic!("unsupported alpha: {alpha}");
    }
}

pub fn try_use_hint(h: bool, r: i32, alpha: i32) -> Result<i32, Error> {
    match alpha {
        a if a == 2 * ((Q_I32 - 1) / 32) || a == 2 * ((Q_I32 - 1) / 88) => Ok(use_hint(h, r, a)),
        _ => Err(Error::InvalidParameter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power2round() {
        let (r1, r0) = power2round(1234567, 13);
        let reconstructed = r1 * (1 << 13) + r0;
        assert_eq!(reconstructed % Q_I32, freeze(1234567));
    }

    #[test]
    fn test_decompose() {
        let alpha = 2 * 95232; // gamma2 * 2 for ML-DSA-44
        let (r1, r0) = decompose(1234567, alpha);
        let reconstructed =
            ((r1 as i64 * alpha as i64 + r0 as i64) % Q_I32 as i64 + Q_I32 as i64) % Q_I32 as i64;
        assert_eq!(reconstructed as i32, 1234567 % Q_I32);
    }

    #[test]
    fn test_make_use_hint_gamma2_88_wraps() {
        let alpha = 2 * 95232;
        assert_eq!(use_hint(true, Q_I32 - 1, alpha), 43);
        assert!(!make_hint(95232, 0, alpha));
        assert!(make_hint(95233, 0, alpha));
    }

    #[test]
    fn test_make_use_hint_gamma2_32_wraps() {
        let alpha = 2 * ((Q_I32 - 1) / 32);
        let r = freeze(alpha - 1);
        let r1 = high_bits(r, alpha);
        assert_eq!(use_hint(false, r, alpha), r1);
    }
}
