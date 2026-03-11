extern crate alloc;

use crate::fpr::{fpr_add, fpr_mul, Fpr};
use crate::modp::{
    modp_intt2_ext, modp_mkgm2, modp_montymul, modp_ninv31, modp_ntt2_ext, modp_r2, modp_rx,
    modp_set,
};
use crate::ntru::SMALL_PRIMES;
use crate::zint::{
    zint_add_scaled_mul_small, zint_mod_small_signed, zint_rebuild_crt, zint_sub_scaled,
};

pub(crate) const MAX_BL_LARGE: [usize; 10] = [2, 2, 5, 7, 12, 21, 40, 78, 157, 308];

#[derive(Clone, Copy)]
pub(crate) struct BitLength {
    pub(crate) avg: i32,
    pub(crate) std: i32,
}

pub(crate) const BITLENGTH: [BitLength; 11] = [
    BitLength { avg: 4, std: 0 },
    BitLength { avg: 11, std: 1 },
    BitLength { avg: 24, std: 1 },
    BitLength { avg: 50, std: 1 },
    BitLength { avg: 102, std: 1 },
    BitLength { avg: 202, std: 2 },
    BitLength { avg: 401, std: 4 },
    BitLength { avg: 794, std: 5 },
    BitLength { avg: 1577, std: 8 },
    BitLength { avg: 3138, std: 13 },
    BitLength { avg: 6308, std: 25 },
];

pub(crate) const DEPTH_INT_FG: usize = 4;

const PTWO31: Fpr = Fpr::from_bits(4_746_794_007_248_502_784);

pub(crate) fn poly_big_to_fp(
    d: &mut [Fpr],
    mut f: &[u32],
    flen: usize,
    fstride: usize,
    logn: usize,
) {
    let n = 1usize << logn;
    debug_assert_eq!(d.len(), n);
    if flen == 0 {
        d.fill(0.0);
        return;
    }

    for slot in d.iter_mut() {
        let neg = 0u32.wrapping_sub(f[flen - 1] >> 30);
        let xm = neg >> 1;
        let mut cc = neg & 1;
        let mut x = 0.0;
        let mut fsc = 1.0;
        for &word in &f[..flen] {
            let mut w = (word ^ xm).wrapping_add(cc);
            cc = w >> 31;
            w &= 0x7FFF_FFFF;
            w = w.wrapping_sub((w << 1) & neg);
            x = fpr_add(x, fpr_mul(i32::from_ne_bytes(w.to_ne_bytes()) as Fpr, fsc));
            fsc = fpr_mul(fsc, PTWO31);
        }
        *slot = x;
        f = &f[fstride..];
    }
}

pub(crate) fn poly_sub_scaled(
    f_big: &mut [u32],
    flen_big: usize,
    fstride_big: usize,
    f_small: &[u32],
    flen_small: usize,
    fstride_small: usize,
    k: &[i32],
    sch: u32,
    scl: u32,
    logn: usize,
) {
    let n = 1usize << logn;
    for u in 0..n {
        let mut kf = -k[u];
        let mut x_index = u * fstride_big;
        let mut y_index = 0usize;
        for v in 0..n {
            zint_add_scaled_mul_small(
                &mut f_big[x_index..x_index + flen_big],
                &f_small[y_index..y_index + flen_small],
                kf,
                sch,
                scl,
            );
            if u + v == n - 1 {
                x_index = 0;
                kf = -kf;
            } else {
                x_index += fstride_big;
            }
            y_index += fstride_small;
        }
    }
}

pub(crate) fn poly_sub_scaled_ntt(
    f_big: &mut [u32],
    flen_big: usize,
    fstride_big: usize,
    f_small: &[u32],
    flen_small: usize,
    fstride_small: usize,
    k: &[i32],
    sch: u32,
    scl: u32,
    logn: usize,
    tmp: &mut [u32],
) {
    let n = 1usize << logn;
    let tlen = flen_small + 1;
    debug_assert_eq!(k.len(), n);
    debug_assert!(tmp.len() >= n * (tlen + 3));

    let (gm, rest) = tmp.split_at_mut(n);
    let (igm, rest) = rest.split_at_mut(n);
    let (fk, t1) = rest.split_at_mut(n * tlen);

    for u in 0..tlen {
        let prime = SMALL_PRIMES[u];
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(flen_small as u32, p, p0i, r2);
        modp_mkgm2(gm, igm, logn, prime.g, p, p0i);

        for (dst, &coeff) in t1.iter_mut().zip(k.iter()) {
            *dst = modp_set(coeff, p);
        }
        modp_ntt2_ext(t1, 1, gm, logn, p, p0i);
        for v in 0..n {
            fk[v * tlen + u] = zint_mod_small_signed(
                &f_small[v * fstride_small..v * fstride_small + flen_small],
                p,
                p0i,
                r2,
                rx,
            );
        }
        modp_ntt2_ext(&mut fk[u..], tlen, gm, logn, p, p0i);
        for v in 0..n {
            let idx = v * tlen + u;
            fk[idx] = modp_montymul(modp_montymul(t1[v], fk[idx], p, p0i), r2, p, p0i);
        }
        modp_intt2_ext(&mut fk[u..], tlen, igm, logn, p, p0i);
    }

    zint_rebuild_crt(fk, tlen, tlen, n, &SMALL_PRIMES[..tlen], true, t1);

    for u in 0..n {
        zint_sub_scaled(
            &mut f_big[u * fstride_big..u * fstride_big + flen_big],
            &fk[u * tlen..(u + 1) * tlen],
            sch,
            scl,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;
    use alloc::vec::Vec;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use super::{poly_big_to_fp, poly_sub_scaled, poly_sub_scaled_ntt};

    fn encode_signed_i128(x: i128, len: usize) -> Vec<u32> {
        let bits = 31 * len;
        let modulus = 1i128 << bits;
        let mut y = x;
        if y < 0 {
            y += modulus;
        }
        let mut out = vec![0u32; len];
        let mut v = y as u128;
        for slot in out.iter_mut() {
            *slot = (v & 0x7FFF_FFFF) as u32;
            v >>= 31;
        }
        out
    }

    fn decode_signed_i128(words: &[u32]) -> i128 {
        let mut unsigned = 0u128;
        for &word in words.iter().rev() {
            unsigned <<= 31;
            unsigned |= word as u128;
        }
        let bits = 31 * words.len();
        if ((unsigned >> (bits - 1)) & 1) != 0 {
            unsigned as i128 - (1i128 << bits)
        } else {
            unsigned as i128
        }
    }

    #[test]
    fn test_poly_big_to_fp_matches_signed_decode() {
        let coeffs = [17i128, -123456789i128, (1i128 << 50) - 33, -((1i128 << 55) - 7)];
        let flen = 2usize;
        let stride = flen;
        let mut src = vec![0u32; coeffs.len() * stride];
        for (u, &coeff) in coeffs.iter().enumerate() {
            let enc = encode_signed_i128(coeff, flen);
            src[u * stride..u * stride + flen].copy_from_slice(&enc);
        }
        let mut got = vec![0.0; coeffs.len()];
        poly_big_to_fp(&mut got, &src, flen, stride, 2);
        for (got, &want) in got.iter().zip(coeffs.iter()) {
            assert_eq!(*got, want as f64);
        }
    }

    #[test]
    fn test_poly_sub_scaled_ntt_matches_quadratic() {
        let mut rng = StdRng::from_seed([0x42u8; 32]);
        let logn = 4usize;
        let n = 1usize << logn;
        let flen_big = 4usize;
        let flen_small = 2usize;
        let mut f_big_a = vec![0u32; n * flen_big];
        let mut f_big_b = vec![0u32; n * flen_big];
        let mut f_small = vec![0u32; n * flen_small];
        let mut k = vec![0i32; n];

        for u in 0..n {
            let big = encode_signed_i128(rng.gen_range(-(1i128 << 70)..(1i128 << 70)), flen_big);
            let small =
                encode_signed_i128(rng.gen_range(-(1i128 << 25)..(1i128 << 25)), flen_small);
            f_big_a[u * flen_big..(u + 1) * flen_big].copy_from_slice(&big);
            f_big_b[u * flen_big..(u + 1) * flen_big].copy_from_slice(&big);
            f_small[u * flen_small..(u + 1) * flen_small].copy_from_slice(&small);
            k[u] = rng.gen_range(-50_000..50_000);
        }

        let sch = 1u32;
        let scl = 7u32;
        poly_sub_scaled(
            &mut f_big_a,
            flen_big,
            flen_big,
            &f_small,
            flen_small,
            flen_small,
            &k,
            sch,
            scl,
            logn,
        );
        let mut tmp = vec![0u32; n * (flen_small + 4)];
        poly_sub_scaled_ntt(
            &mut f_big_b,
            flen_big,
            flen_big,
            &f_small,
            flen_small,
            flen_small,
            &k,
            sch,
            scl,
            logn,
            &mut tmp,
        );

        for u in 0..n {
            let a = decode_signed_i128(&f_big_a[u * flen_big..(u + 1) * flen_big]);
            let b = decode_signed_i128(&f_big_b[u * flen_big..(u + 1) * flen_big]);
            assert_eq!(a, b, "coefficient {u} mismatch");
        }
    }
}
