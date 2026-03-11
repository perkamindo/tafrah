#[derive(Clone, Copy, Debug)]
pub(crate) struct SmallPrime {
    pub(crate) p: u32,
    pub(crate) g: u32,
    pub(crate) s: u32,
}

pub(crate) fn modp_set(x: i32, p: u32) -> u32 {
    let mut w = x as u32;
    w = w.wrapping_add(p & 0u32.wrapping_sub(w >> 31));
    w
}

pub(crate) fn modp_norm(x: u32, p: u32) -> i32 {
    x.wrapping_sub(p & (((x.wrapping_sub((p + 1) >> 1)) >> 31).wrapping_sub(1))) as i32
}

pub(crate) fn modp_ninv31(p: u32) -> u32 {
    let mut y = 2u32.wrapping_sub(p);
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    0x7FFF_FFFFu32 & y.wrapping_neg()
}

pub(crate) fn modp_r(p: u32) -> u32 {
    0x8000_0000u32.wrapping_sub(p)
}

pub(crate) fn modp_add(a: u32, b: u32, p: u32) -> u32 {
    let mut d = a.wrapping_add(b).wrapping_sub(p);
    d = d.wrapping_add(p & 0u32.wrapping_sub(d >> 31));
    d
}

pub(crate) fn modp_sub(a: u32, b: u32, p: u32) -> u32 {
    let mut d = a.wrapping_sub(b);
    d = d.wrapping_add(p & 0u32.wrapping_sub(d >> 31));
    d
}

pub(crate) fn modp_montymul(a: u32, b: u32, p: u32, p0i: u32) -> u32 {
    let z = (a as u64) * (b as u64);
    let w = (z.wrapping_mul(p0i as u64) & 0x7FFF_FFFFu64).wrapping_mul(p as u64);
    let mut d = ((z + w) >> 31) as u32;
    d = d.wrapping_sub(p);
    d = d.wrapping_add(p & 0u32.wrapping_sub(d >> 31));
    d
}

pub(crate) fn modp_r2(p: u32, p0i: u32) -> u32 {
    let mut z = modp_r(p);
    z = modp_add(z, z, p);
    for _ in 0..5 {
        z = modp_montymul(z, z, p, p0i);
    }
    (z.wrapping_add(p & 0u32.wrapping_sub(z & 1))) >> 1
}

pub(crate) fn modp_rx(mut x: u32, p: u32, p0i: u32, r2: u32) -> u32 {
    if x == 0 {
        return 1;
    }
    x = x.wrapping_sub(1);
    let mut r = r2;
    let mut z = modp_r(p);
    let mut i = 0u32;
    while (1u32 << i) <= x {
        if (x & (1u32 << i)) != 0 {
            z = modp_montymul(z, r, p, p0i);
        }
        r = modp_montymul(r, r, p, p0i);
        i += 1;
    }
    z
}

pub(crate) fn modp_div(a: u32, b: u32, p: u32, p0i: u32, r: u32) -> u32 {
    if b == 0 {
        return 0;
    }

    let e = p.wrapping_sub(2);
    let mut z = r;
    for i in (0..=30).rev() {
        z = modp_montymul(z, z, p, p0i);
        let z2 = modp_montymul(z, b, p, p0i);
        z ^= (z ^ z2) & 0u32.wrapping_sub((e >> i) & 1);
    }
    z = modp_montymul(z, 1, p, p0i);
    modp_montymul(a, z, p, p0i)
}

fn rev10(mut x: usize) -> usize {
    let mut r = 0usize;
    for _ in 0..10 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

pub(crate) fn modp_mkgm2(
    gm: &mut [u32],
    igm: &mut [u32],
    logn: usize,
    mut g: u32,
    p: u32,
    p0i: u32,
) {
    let n = 1usize << logn;
    debug_assert!(gm.len() >= n);
    debug_assert!(igm.len() >= n);

    let r2 = modp_r2(p, p0i);
    g = modp_montymul(g, r2, p, p0i);
    for _ in logn..10 {
        g = modp_montymul(g, g, p, p0i);
    }

    let ig = modp_div(r2, g, p, p0i, modp_r(p));
    let k = 10 - logn;
    let mut x1 = modp_r(p);
    let mut x2 = modp_r(p);
    for u in 0..n {
        let v = rev10(u << k);
        gm[v] = x1;
        igm[v] = x2;
        x1 = modp_montymul(x1, g, p, p0i);
        x2 = modp_montymul(x2, ig, p, p0i);
    }
}

pub(crate) fn modp_ntt2_ext(
    a: &mut [u32],
    stride: usize,
    gm: &[u32],
    logn: usize,
    p: u32,
    p0i: u32,
) {
    if logn == 0 {
        return;
    }
    let n = 1usize << logn;
    let mut t = n;
    let mut m = 1usize;
    while m < n {
        let ht = t >> 1;
        let mut v1 = 0usize;
        for u in 0..m {
            let s = gm[m + u];
            let mut r1 = v1 * stride;
            let mut r2 = r1 + ht * stride;
            for _ in 0..ht {
                let x = a[r1];
                let y = modp_montymul(a[r2], s, p, p0i);
                a[r1] = modp_add(x, y, p);
                a[r2] = modp_sub(x, y, p);
                r1 += stride;
                r2 += stride;
            }
            v1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

pub(crate) fn modp_intt2_ext(
    a: &mut [u32],
    stride: usize,
    igm: &[u32],
    logn: usize,
    p: u32,
    p0i: u32,
) {
    if logn == 0 {
        return;
    }
    let n = 1usize << logn;
    let mut t = 1usize;
    let mut m = n;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut v1 = 0usize;
        for u in 0..hm {
            let s = igm[hm + u];
            let mut r1 = v1 * stride;
            let mut r2 = r1 + t * stride;
            for _ in 0..t {
                let x = a[r1];
                let y = a[r2];
                a[r1] = modp_add(x, y, p);
                a[r2] = modp_montymul(modp_sub(x, y, p), s, p, p0i);
                r1 += stride;
                r2 += stride;
            }
            v1 += dt;
        }
        t = dt;
        m = hm;
    }

    let ni = 1u32 << (31 - logn);
    for k in 0..n {
        let idx = k * stride;
        a[idx] = modp_montymul(a[idx], ni, p, p0i);
    }
}

pub(crate) fn modp_poly_rec_res(f: &mut [u32], logn: usize, p: u32, p0i: u32, r2: u32) {
    if logn == 0 {
        return;
    }
    let hn = 1usize << (logn - 1);
    debug_assert!(f.len() >= (hn << 1));
    for u in 0..hn {
        let w0 = f[(u << 1) + 0];
        let w1 = f[(u << 1) + 1];
        f[u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

    use super::{
        modp_div, modp_intt2_ext, modp_mkgm2, modp_ninv31, modp_norm, modp_ntt2_ext,
        modp_poly_rec_res, modp_r, modp_r2, modp_set,
    };

    const P: u32 = 2_147_473_409;
    const G: u32 = 383_167_813;

    fn pow_mod(mut base: u64, mut exp: u64, modu: u64) -> u64 {
        let mut acc = 1u64;
        while exp > 0 {
            if (exp & 1) != 0 {
                acc = (acc * base) % modu;
            }
            base = (base * base) % modu;
            exp >>= 1;
        }
        acc
    }

    #[test]
    fn test_modp_set_norm_roundtrip_small_values() {
        for x in -1000..=1000 {
            let w = modp_set(x, P);
            assert_eq!(modp_norm(w, P), x);
        }
    }

    #[test]
    fn test_modp_div_matches_pow_inverse() {
        let p0i = modp_ninv31(P);
        let r = modp_r(P);
        for &(a, b) in &[(1u32, 2u32), (17, 91), (1234567, 7654321), (P - 5, P - 7)] {
            let got = modp_div(a, b, P, p0i, r);
            let want = ((a as u64) * pow_mod(b as u64, (P - 2) as u64, P as u64) % P as u64) as u32;
            assert_eq!(got, want);
        }
    }

    #[test]
    fn test_modp_ntt_roundtrip() {
        let logn = 4usize;
        let n = 1usize << logn;
        let p0i = modp_ninv31(P);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, G, P, p0i);

        let mut poly = (0..n)
            .map(|i| modp_set((i as i32 * 17) - 50, P))
            .collect::<Vec<_>>();
        let original = poly.clone();
        modp_ntt2_ext(&mut poly, 1, &gm, logn, P, p0i);
        modp_intt2_ext(&mut poly, 1, &igm, logn, P, p0i);
        assert_eq!(poly, original);
    }

    #[test]
    fn test_modp_r2_is_montgomery_square() {
        let p0i = modp_ninv31(P);
        let r2 = modp_r2(P, p0i);
        let want = ((1u128 << 62) % P as u128) as u32;
        assert_eq!(r2, want);
    }

    #[test]
    fn test_modp_poly_rec_res_matches_pairwise_ntt_products() {
        let logn = 4usize;
        let n = 1usize << logn;
        let p0i = modp_ninv31(P);
        let r2 = modp_r2(P, p0i);
        let mut values = (0..n)
            .map(|i| modp_set((i as i32 * 29) - 77, P))
            .collect::<Vec<_>>();
        let original = values.clone();

        modp_poly_rec_res(&mut values, logn, P, p0i, r2);

        for u in 0..(n >> 1) {
            let want = super::modp_montymul(
                super::modp_montymul(original[u << 1], original[(u << 1) + 1], P, p0i),
                r2,
                P,
                p0i,
            );
            assert_eq!(values[u], want);
        }
    }
}
