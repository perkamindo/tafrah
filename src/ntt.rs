/// NTT for ML-KEM (q = 3329, n = 256)
/// Direct port from pq-crystals/kyber ref implementation
pub mod kem {
    use crate::field::kem;

    pub const N: usize = 256;

    /// From pq-crystals/kyber/ref/ntt.c
    pub static ZETAS: [i16; 128] = [
        -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474,
        1468, 573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411,
        -205, -1571, 1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618,
        -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725,
        448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235,
        -291, -460, 1574, 1653, -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872,
        349, 418, 329, -156, -75, 817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218,
        -1335, -874, 220, -1187, -1659, -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108,
        -308, 996, 991, 958, -1460, 1522, 1628,
    ];

    /// Forward NTT (Algorithm 9, FIPS 203)
    /// From pq-crystals/kyber/ref/ntt.c: ntt()
    pub fn ntt(r: &mut [i16; N]) {
        let mut k: usize = 1;
        let mut len: usize = 128;
        while len >= 2 {
            let mut start: usize = 0;
            while start < 256 {
                let zeta = ZETAS[k] as i32;
                k += 1;
                for j in start..start + len {
                    let t = kem::fqmul(zeta as i16, r[j + len]);
                    r[j + len] = r[j] - t;
                    r[j] = r[j] + t;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// Inverse NTT (Algorithm 10, FIPS 203)
    /// From pq-crystals/kyber/ref/ntt.c: invntt_tomont()
    pub fn inv_ntt(r: &mut [i16; N]) {
        let mut k: usize = 127;
        let mut len: usize = 2;
        while len <= 128 {
            let mut start: usize = 0;
            while start < 256 {
                let zeta = ZETAS[k] as i32;
                k -= 1;
                for j in start..start + len {
                    let t = r[j];
                    r[j] = kem::barrett_reduce(t + r[j + len]);
                    r[j + len] = r[j + len] - t;
                    r[j + len] = kem::fqmul(zeta as i16, r[j + len]);
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        // f = mont^2/128 = 1441
        const F: i16 = 1441;
        for j in 0..256 {
            r[j] = kem::fqmul(r[j], F);
        }
    }

    /// Base-case multiplication of two degree-1 polynomials in NTT domain
    /// From pq-crystals/kyber/ref/ntt.c: basemul()
    #[inline]
    pub fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
        r[0] = kem::fqmul(a[1], b[1]);
        r[0] = kem::fqmul(r[0], zeta);
        r[0] += kem::fqmul(a[0], b[0]);
        r[1] = kem::fqmul(a[0], b[1]);
        r[1] += kem::fqmul(a[1], b[0]);
    }

    /// Multiply two polynomials in NTT domain
    /// From pq-crystals/kyber/ref/poly.c: poly_basemul_montgomery()
    pub fn poly_basemul_montgomery(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
        for i in 0..64 {
            basemul(&mut r[4 * i..], &a[4 * i..], &b[4 * i..], ZETAS[64 + i]);
            basemul(
                &mut r[4 * i + 2..],
                &a[4 * i + 2..],
                &b[4 * i + 2..],
                -ZETAS[64 + i],
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::field::kem::Q;

        #[test]
        fn test_ntt_inv_ntt_roundtrip() {
            // In Kyber reference, invntt_tomont produces values in Montgomery domain
            // So NTT(f) -> INTT(f) gives f * R mod q where R = 2^16 mod q
            // To verify, we compare (result * R^{-1}) mod q == original
            // R = 2^16 mod 3329 = 2285 (MONT), R^{-1} mod q needs to be found
            // Or simply: fqmul(result, 1) gives result * R^{-1} mod q = result * 2^{-16} mod q
            // But invntt already multiplied by 1441 = R^2/128 mod q
            // So: NTT -> INTT gives f * R mod q

            let mut f = [0i16; N];
            for i in 0..N {
                f[i] = (i as i16) % Q;
            }
            let original = f;

            ntt(&mut f);
            inv_ntt(&mut f);

            // After round trip, result = original * R mod q (Montgomery domain)
            // To get back, multiply by R^{-1} = fqmul(x, 1)
            // Actually, fqmul(a, b) = a*b*R^{-1}, so fqmul(result, 1) = result * R^{-1}
            for i in 0..N {
                let recovered = kem::fqmul(f[i], 1);
                let orig_mod = ((original[i] as i32 % Q as i32 + Q as i32) % Q as i32) as i16;
                let rec_mod = ((recovered as i32 % Q as i32 + Q as i32) % Q as i32) as i16;
                assert_eq!(
                    rec_mod, orig_mod,
                    "mismatch at index {}: got {} expected {}",
                    i, rec_mod, orig_mod
                );
            }
        }

        #[test]
        fn test_ntt_zero() {
            let mut f = [0i16; N];
            ntt(&mut f);
            for coeff in f.iter() {
                assert_eq!(*coeff, 0);
            }
        }
    }
}

/// NTT for ML-DSA (q = 8380417, n = 256)
/// Direct port from pq-crystals/dilithium ref implementation
pub mod dsa {
    use crate::field::dsa;

    pub const N: usize = 256;

    /// From pq-crystals/dilithium/ref/ntt.c
    pub static ZETAS: [i32; N] = [
        0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
        -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928,
        -549488, -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237,
        -19422, 4010497, 280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516,
        3915439, -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
        -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596, 811944,
        531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779, -3930395, -1528703,
        -3677745, -3041255, -1452451, 3475950, 2176455, -1585221, -1257611, 1939314, -4083598,
        -1000202, -3190144, -3157330, -3632928, 126922, 3412210, -983419, 2147896, 2715295,
        -2967645, -3693493, -411027, -2477047, -671102, -1228525, -22981, -1308169, -381987,
        1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516,
        3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856, 189548,
        -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669, -1584928,
        -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
        3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181,
        -3520352, -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174,
        -43260, -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
        342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481,
        -2590150, 1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921,
        -3548272, -2994039, 1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225,
        -451100, 1312455, 3306115, -1962642, -1279661, 1917081, -2546312, -1374803, 1500165,
        777191, 2235880, 3406031, -542412, -2831860, -1671176, -1846953, -2584293, -3724270,
        594136, -3776993, -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
        -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107, -3038916, 3523897,
        3866901, 269760, 2213111, -975884, 1717735, 472078, -426683, 1723600, -1803090, 1910376,
        -1667432, -1104333, -260646, -3833893, -2939036, -2235985, -420899, -2286327, 183443,
        -976891, 1612842, -3545687, -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154,
        1976782,
    ];

    /// Forward NTT for ML-DSA
    /// From pq-crystals/dilithium/ref/ntt.c: ntt()
    pub fn ntt(a: &mut [i32; N]) {
        let mut k: usize = 0;
        let mut len: usize = 128;
        while len > 0 {
            let mut start: usize = 0;
            while start < N {
                k += 1;
                let zeta = ZETAS[k];
                for j in start..start + len {
                    let t = dsa::montgomery_reduce(zeta as i64 * a[j + len] as i64);
                    a[j + len] = a[j] - t;
                    a[j] = a[j] + t;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// Inverse NTT for ML-DSA
    /// From pq-crystals/dilithium/ref/ntt.c: invntt_tomont()
    pub fn inv_ntt(a: &mut [i32; N]) {
        let mut k: usize = 256;
        let mut len: usize = 1;
        while len < N {
            let mut start: usize = 0;
            while start < N {
                k -= 1;
                let zeta = -ZETAS[k];
                for j in start..start + len {
                    let t = a[j];
                    a[j] = t + a[j + len];
                    a[j + len] = t - a[j + len];
                    a[j + len] = dsa::montgomery_reduce(zeta as i64 * a[j + len] as i64);
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        // f = 256^{-1} * mont = 41978
        const F: i64 = 41978;
        for coeff in a.iter_mut() {
            *coeff = dsa::montgomery_reduce(F * *coeff as i64);
        }
    }

    /// Pointwise multiplication in NTT domain for ML-DSA
    /// From pq-crystals/dilithium/ref/ntt.c: pointwise_montgomery()
    pub fn pointwise_mul(a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
        for i in 0..N {
            c[i] = dsa::montgomery_reduce(a[i] as i64 * b[i] as i64);
        }
    }
}
