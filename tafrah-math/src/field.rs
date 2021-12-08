/// Modular arithmetic for ML-KEM (q = 3329)
pub mod kem {
    pub const Q: i16 = 3329;
    pub const Q_U32: u32 = 3329;

    /// Barrett reduction: given a, compute a mod q
    /// For 16-bit signed inputs
    #[inline(always)]
    pub fn barrett_reduce(a: i16) -> i16 {
        // v = round(2^26 / q) = 20159
        const V: i32 = 20159;
        let t = ((V * a as i32 + (1 << 25)) >> 26) as i16;
        a - t * Q
    }

    /// Montgomery reduction
    /// Given a 32-bit integer a, compute a * 2^{-16} mod q
    #[inline(always)]
    pub fn montgomery_reduce(a: i32) -> i16 {
        // q_inv = -q^{-1} mod 2^16 = 3327 (i.e., 3329*3327 ≡ -1 mod 2^16)
        const Q_INV: i16 = -3327;
        let t = (a as i16).wrapping_mul(Q_INV);
        ((a - t as i32 * Q as i32) >> 16) as i16
    }

    /// Modular multiplication via Montgomery: a*b*2^{-16} mod q
    #[inline(always)]
    pub fn fqmul(a: i16, b: i16) -> i16 {
        montgomery_reduce(a as i32 * b as i32)
    }

    /// Conditional add q: if a < 0, add q
    #[inline(always)]
    pub fn caddq(a: i16) -> i16 {
        if a < 0 {
            a + Q
        } else {
            a
        }
    }

    /// Conditional subtract q: if a >= q, subtract q
    #[inline(always)]
    pub fn csubq(a: i16) -> i16 {
        let mut r = a - Q;
        r += (r >> 15) & Q;
        r
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_barrett_reduce() {
            assert_eq!(barrett_reduce(0), 0);
            // Barrett reduces magnitude; result is congruent mod q
            for i in 0..Q {
                let r = barrett_reduce(i);
                let canonical = ((r as i32 % Q as i32 + Q as i32) % Q as i32) as i16;
                assert_eq!(
                    canonical, i,
                    "barrett_reduce({}) = {}, canonical = {}",
                    i, r, canonical
                );
            }
        }

        #[test]
        fn test_montgomery_reduce() {
            let r = montgomery_reduce(100 * Q as i32);
            assert!(r.abs() <= Q, "montgomery_reduce gave {}", r);
        }

        #[test]
        fn test_caddq() {
            assert_eq!(caddq(0), 0);
            assert_eq!(caddq(-1), Q - 1);
            assert_eq!(caddq(100), 100);
        }

        #[test]
        fn test_csubq() {
            assert_eq!(csubq(0), 0);
            assert_eq!(csubq(Q - 1), Q - 1);
            assert_eq!(csubq(Q), 0);
            assert_eq!(csubq(Q + 1), 1);
        }
    }
}

/// Modular arithmetic for ML-DSA (q = 8380417)
pub mod dsa {
    pub const Q: u32 = 8380417;
    pub const Q_I32: i32 = Q as i32;

    /// Reduce mod q into centered representation
    #[inline(always)]
    pub fn reduce(a: i64) -> i32 {
        let mut r = (a % Q as i64) as i32;
        if r < 0 {
            r += Q_I32;
        }
        r
    }

    /// Modular addition mod q, result in [0, q)
    #[inline(always)]
    pub fn add(a: i32, b: i32) -> i32 {
        let r = a + b;
        if r >= Q_I32 {
            r - Q_I32
        } else if r < 0 {
            r + Q_I32
        } else {
            r
        }
    }

    /// Modular subtraction mod q, result in [0, q)
    #[inline(always)]
    pub fn sub(a: i32, b: i32) -> i32 {
        let r = a - b;
        if r >= Q_I32 {
            r - Q_I32
        } else if r < 0 {
            r + Q_I32
        } else {
            r
        }
    }

    /// Modular multiplication mod q
    #[inline(always)]
    pub fn mul(a: i32, b: i32) -> i32 {
        reduce(a as i64 * b as i64)
    }

    /// Montgomery reduction for DSA
    /// Given a, compute a * 2^{-32} mod q
    #[inline(always)]
    pub fn montgomery_reduce(a: i64) -> i32 {
        // q^{-1} mod 2^32 = 58728449
        const Q_INV: i32 = 58728449;
        let t = (a as i32).wrapping_mul(Q_INV);
        let r = (a - t as i64 * Q as i64) >> 32;
        r as i32
    }

    /// Barrett-like reduction: reduce to approximately [-6283008, 6283008]
    /// From pq-crystals/dilithium/ref/reduce.c: reduce32()
    #[inline(always)]
    pub fn reduce32(a: i32) -> i32 {
        let t = (a + (1 << 22)) >> 23;
        a - t * Q_I32
    }

    /// Freeze: reduce coefficient to [0, q)
    /// Applies reduce32 then caddq (matches reference freeze())
    #[inline(always)]
    pub fn freeze(a: i32) -> i32 {
        caddq(reduce32(a))
    }

    /// Conditional add q: if a is negative, add q
    #[inline(always)]
    pub fn caddq(a: i32) -> i32 {
        let mut r = a;
        r += (r >> 31) & Q_I32;
        r
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_reduce() {
            assert_eq!(reduce(0), 0);
            assert_eq!(reduce(Q as i64), 0);
            assert_eq!(reduce(-1), Q_I32 - 1);
        }

        #[test]
        fn test_add_sub() {
            assert_eq!(add(0, 0), 0);
            assert_eq!(add(Q_I32 - 1, 1), 0);
            assert_eq!(sub(0, 1), Q_I32 - 1);
        }

        #[test]
        fn test_mul() {
            assert_eq!(mul(0, 100), 0);
            assert_eq!(mul(1, 100), 100);
        }
    }
}
