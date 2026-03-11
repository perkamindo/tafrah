extern crate alloc;

use crate::common::is_short;

const Q: u32 = 12289;
const Q0I: u32 = 12287;
const R: u32 = 4091;
const R2: u32 = 10952;
const TABLE_LEN: usize = 1024;

pub(crate) const L2BOUND: [u32; 11] = [
    0, 101_498, 208_714, 428_865, 892_039, 1_852_696, 3_842_630, 7_959_734, 16_468_416, 34_034_726,
    70_265_242,
];

fn rev10(mut x: usize) -> usize {
    let mut r = 0usize;
    for _ in 0..10 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

fn pow_mod(mut base: u32, mut exp: usize) -> u32 {
    let mut acc = 1u32;
    while exp > 0 {
        if (exp & 1) != 0 {
            acc = ((acc as u64 * base as u64) % Q as u64) as u32;
        }
        base = ((base as u64 * base as u64) % Q as u64) as u32;
        exp >>= 1;
    }
    acc
}

pub(crate) fn build_ntt_tables() -> ([u16; TABLE_LEN], [u16; TABLE_LEN]) {
    let mut gmb = [0u16; TABLE_LEN];
    let mut igmb = [0u16; TABLE_LEN];
    let inv_g = 8_778u32;

    for i in 0..TABLE_LEN {
        gmb[i] = ((R as u64 * pow_mod(7, rev10(i)) as u64) % Q as u64) as u16;
        igmb[i] = ((R as u64 * pow_mod(inv_g, rev10(i)) as u64) % Q as u64) as u16;
    }

    (gmb, igmb)
}

fn mq_add(x: u32, y: u32) -> u32 {
    let mut d = x.wrapping_add(y).wrapping_sub(Q);
    d = d.wrapping_add(Q & 0u32.wrapping_sub(d >> 31));
    d
}

fn mq_sub(x: u32, y: u32) -> u32 {
    let mut d = x.wrapping_sub(y);
    d = d.wrapping_add(Q & 0u32.wrapping_sub(d >> 31));
    d
}

fn mq_rshift1(mut x: u32) -> u32 {
    x = x.wrapping_add(Q & 0u32.wrapping_sub(x & 1));
    x >> 1
}

fn mq_conv_small(x: i32) -> u32 {
    let mut y = x as u32;
    y = y.wrapping_add(Q & 0u32.wrapping_sub(y >> 31));
    y
}

fn mq_montymul(x: u32, y: u32) -> u32 {
    let mut z = x.wrapping_mul(y);
    let w = (z.wrapping_mul(Q0I) & 0xFFFF).wrapping_mul(Q);
    z = z.wrapping_add(w) >> 16;
    z = z.wrapping_sub(Q);
    z = z.wrapping_add(Q & 0u32.wrapping_sub(z >> 31));
    z
}

fn mq_ntt(a: &mut [u16], logn: usize, gmb: &[u16; TABLE_LEN]) {
    let n = 1usize << logn;
    let mut t = n;
    let mut m = 1usize;

    while m < n {
        let ht = t >> 1;
        let mut j1 = 0usize;
        for i in 0..m {
            let s = gmb[m + i] as u32;
            let j2 = j1 + ht;
            for j in j1..j2 {
                let u = a[j] as u32;
                let v = mq_montymul(a[j + ht] as u32, s);
                a[j] = mq_add(u, v) as u16;
                a[j + ht] = mq_sub(u, v) as u16;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

fn mq_intt(a: &mut [u16], logn: usize, igmb: &[u16; TABLE_LEN]) {
    let n = 1usize << logn;
    let mut t = 1usize;
    let mut m = n;

    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1 = 0usize;
        for i in 0..hm {
            let j2 = j1 + t;
            let s = igmb[hm + i] as u32;
            for j in j1..j2 {
                let u = a[j] as u32;
                let v = a[j + t] as u32;
                a[j] = mq_add(u, v) as u16;
                let w = mq_sub(u, v);
                a[j + t] = mq_montymul(w, s) as u16;
            }
            j1 += dt;
        }
        t = dt;
        m = hm;
    }

    let mut ni = R;
    let mut mm = n;
    while mm > 1 {
        ni = mq_rshift1(ni);
        mm >>= 1;
    }
    for value in a.iter_mut() {
        *value = mq_montymul(*value as u32, ni) as u16;
    }
}

fn mq_poly_tomonty(f: &mut [u16]) {
    for value in f.iter_mut() {
        *value = mq_montymul(*value as u32, R2) as u16;
    }
}

fn mq_poly_montymul_ntt(f: &mut [u16], g: &[u16]) {
    for (lhs, rhs) in f.iter_mut().zip(g.iter()) {
        *lhs = mq_montymul(*lhs as u32, *rhs as u32) as u16;
    }
}

fn mq_poly_sub(f: &mut [u16], g: &[u16]) {
    for (lhs, rhs) in f.iter_mut().zip(g.iter()) {
        *lhs = mq_sub(*lhs as u32, *rhs as u32) as u16;
    }
}

fn mq_div_12289(x: u32, y: u32) -> u32 {
    let y0 = mq_montymul(y, R2);
    let y1 = mq_montymul(y0, y0);
    let y2 = mq_montymul(y1, y0);
    let y3 = mq_montymul(y2, y1);
    let y4 = mq_montymul(y3, y3);
    let y5 = mq_montymul(y4, y4);
    let y6 = mq_montymul(y5, y5);
    let y7 = mq_montymul(y6, y6);
    let y8 = mq_montymul(y7, y7);
    let y9 = mq_montymul(y8, y2);
    let y10 = mq_montymul(y9, y8);
    let y11 = mq_montymul(y10, y10);
    let y12 = mq_montymul(y11, y11);
    let y13 = mq_montymul(y12, y9);
    let y14 = mq_montymul(y13, y13);
    let y15 = mq_montymul(y14, y14);
    let y16 = mq_montymul(y15, y10);
    let y17 = mq_montymul(y16, y16);
    let y18 = mq_montymul(y17, y0);
    mq_montymul(y18, x)
}

pub(crate) fn to_ntt_monty(h: &mut [u16], logn: usize, gmb: &[u16; TABLE_LEN]) {
    mq_ntt(h, logn, gmb);
    mq_poly_tomonty(h);
}

pub(crate) fn compute_public_from_small(
    f: &[i8],
    g: &[i8],
    logn: usize,
) -> Option<alloc::vec::Vec<u16>> {
    let n = 1usize << logn;
    if f.len() != n || g.len() != n {
        return None;
    }

    let (gmb, igmb) = build_ntt_tables();
    let mut tt = alloc::vec![0u16; n];
    let mut h = alloc::vec![0u16; n];

    for u in 0..n {
        tt[u] = mq_conv_small(f[u] as i32) as u16;
        h[u] = mq_conv_small(g[u] as i32) as u16;
    }

    mq_ntt(&mut h, logn, &gmb);
    mq_ntt(&mut tt, logn, &gmb);
    for u in 0..n {
        if tt[u] == 0 {
            return None;
        }
        h[u] = mq_div_12289(h[u] as u32, tt[u] as u32) as u16;
    }
    mq_intt(&mut h, logn, &igmb);
    Some(h)
}

pub(crate) fn complete_private_from_small(
    f: &[i8],
    g: &[i8],
    capital_f: &[i8],
    logn: usize,
) -> Option<alloc::vec::Vec<i8>> {
    let n = 1usize << logn;
    if f.len() != n || g.len() != n || capital_f.len() != n {
        return None;
    }

    let (gmb, igmb) = build_ntt_tables();
    let mut t1 = alloc::vec![0u16; n];
    let mut t2 = alloc::vec![0u16; n];

    for u in 0..n {
        t1[u] = mq_conv_small(g[u] as i32) as u16;
        t2[u] = mq_conv_small(capital_f[u] as i32) as u16;
    }
    mq_ntt(&mut t1, logn, &gmb);
    mq_ntt(&mut t2, logn, &gmb);
    mq_poly_tomonty(&mut t1);
    mq_poly_montymul_ntt(&mut t1, &t2);

    for u in 0..n {
        t2[u] = mq_conv_small(f[u] as i32) as u16;
    }
    mq_ntt(&mut t2, logn, &gmb);
    for u in 0..n {
        if t2[u] == 0 {
            return None;
        }
        t1[u] = mq_div_12289(t1[u] as u32, t2[u] as u32) as u16;
    }
    mq_intt(&mut t1, logn, &igmb);

    let mut capital_g = alloc::vec![0i8; n];
    for u in 0..n {
        let mut value = t1[u] as i32;
        if value > (Q as i32 >> 1) {
            value -= Q as i32;
        }
        if !(-127..=127).contains(&value) {
            return None;
        }
        capital_g[u] = value as i8;
    }
    Some(capital_g)
}

pub(crate) fn verify_raw(c0: &[u16], s2: &[i16], h_ntt: &[u16], logn: usize) -> bool {
    let n = 1usize << logn;
    let (gmb, igmb) = build_ntt_tables();

    let mut tt = alloc::vec![0u16; n];
    for (dst, &src) in tt.iter_mut().zip(s2.iter()) {
        let mut w = src as i32 as u32;
        w = w.wrapping_add(Q & 0u32.wrapping_sub(w >> 31));
        *dst = w as u16;
    }

    mq_ntt(&mut tt, logn, &gmb);
    mq_poly_montymul_ntt(&mut tt, h_ntt);
    mq_intt(&mut tt, logn, &igmb);
    mq_poly_sub(&mut tt, c0);

    let mut s1 = alloc::vec![0i16; n];
    for (dst, &src) in s1.iter_mut().zip(tt.iter()) {
        let mut w = src as i32;
        if w > (Q as i32 >> 1) {
            w -= Q as i32;
        }
        *dst = w as i16;
    }

    is_short(&s1, s2, logn)
}
