extern crate alloc;

use alloc::vec::Vec;

use crate::fpr::{
    fpr_add, fpr_half, fpr_inv, fpr_mul, fpr_neg, fpr_of, fpr_sqr, fpr_sub, p2, Fpr, GmTable,
};

fn check_len(poly: &[Fpr], logn: usize) {
    debug_assert_eq!(poly.len(), 1usize << logn);
}

fn fpc_mul(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (
        fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im)),
        fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re)),
    )
}

fn fpc_div(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    let m = fpr_inv(fpr_add(fpr_sqr(b_re), fpr_sqr(b_im)));
    let b_re = fpr_mul(b_re, m);
    let b_im = fpr_mul(fpr_neg(b_im), m);
    fpc_mul(a_re, a_im, b_re, b_im)
}

pub(crate) fn fft(poly: &mut [Fpr], logn: usize, gm: &GmTable) {
    check_len(poly, logn);
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = hn;

    for u in 1..logn {
        let m = 1usize << u;
        let ht = t >> 1;
        let hm = m >> 1;
        let mut j1 = 0usize;
        for i1 in 0..hm {
            let j2 = j1 + ht;
            let (s_re, s_im) = gm.get(m + i1);
            for j in j1..j2 {
                let x_re = poly[j];
                let x_im = poly[j + hn];
                let y_re = poly[j + ht];
                let y_im = poly[j + ht + hn];
                let (y_re, y_im) = fpc_mul(y_re, y_im, s_re, s_im);
                poly[j] = fpr_add(x_re, y_re);
                poly[j + hn] = fpr_add(x_im, y_im);
                poly[j + ht] = fpr_sub(x_re, y_re);
                poly[j + ht + hn] = fpr_sub(x_im, y_im);
            }
            j1 += t;
        }
        t = ht;
    }
}

pub(crate) fn ifft(poly: &mut [Fpr], logn: usize, gm: &GmTable) {
    check_len(poly, logn);
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = 1usize;
    let mut m = n;

    for u in (2..=logn).rev() {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1 = 0usize;
        for i1 in 0.. {
            if j1 >= hn {
                break;
            }
            let j2 = j1 + t;
            let (s_re, s_im) = gm.get(hm + i1);
            let s_im = fpr_neg(s_im);
            for j in j1..j2 {
                let x_re = poly[j];
                let x_im = poly[j + hn];
                let y_re = poly[j + t];
                let y_im = poly[j + t + hn];
                poly[j] = fpr_add(x_re, y_re);
                poly[j + hn] = fpr_add(x_im, y_im);
                let x_re = fpr_sub(x_re, y_re);
                let x_im = fpr_sub(x_im, y_im);
                let (z_re, z_im) = fpc_mul(x_re, x_im, s_re, s_im);
                poly[j + t] = z_re;
                poly[j + t + hn] = z_im;
            }
            j1 += dt;
        }
        t = dt;
        m = hm;
        let _ = u;
    }

    if logn > 0 {
        let ni = p2(logn);
        for value in poly.iter_mut() {
            *value = fpr_mul(*value, ni);
        }
    }
}

pub(crate) fn poly_add(a: &mut [Fpr], b: &[Fpr]) {
    debug_assert_eq!(a.len(), b.len());
    for (lhs, rhs) in a.iter_mut().zip(b.iter()) {
        *lhs = fpr_add(*lhs, *rhs);
    }
}

pub(crate) fn poly_sub(a: &mut [Fpr], b: &[Fpr]) {
    debug_assert_eq!(a.len(), b.len());
    for (lhs, rhs) in a.iter_mut().zip(b.iter()) {
        *lhs = fpr_sub(*lhs, *rhs);
    }
}

pub(crate) fn poly_neg(a: &mut [Fpr]) {
    for value in a.iter_mut() {
        *value = fpr_neg(*value);
    }
}

pub(crate) fn poly_adj_fft(a: &mut [Fpr], logn: usize) {
    check_len(a, logn);
    let hn = a.len() >> 1;
    for value in &mut a[hn..] {
        *value = fpr_neg(*value);
    }
}

pub(crate) fn poly_mul_fft(a: &mut [Fpr], b: &[Fpr], logn: usize) {
    check_len(a, logn);
    check_len(b, logn);
    let hn = a.len() >> 1;
    for u in 0..hn {
        let (re, im) = fpc_mul(a[u], a[u + hn], b[u], b[u + hn]);
        a[u] = re;
        a[u + hn] = im;
    }
}

pub(crate) fn poly_muladj_fft(a: &mut [Fpr], b: &[Fpr], logn: usize) {
    check_len(a, logn);
    check_len(b, logn);
    let hn = a.len() >> 1;
    for u in 0..hn {
        let (re, im) = fpc_mul(a[u], a[u + hn], b[u], fpr_neg(b[u + hn]));
        a[u] = re;
        a[u + hn] = im;
    }
}

pub(crate) fn poly_mulselfadj_fft(a: &mut [Fpr], logn: usize) {
    check_len(a, logn);
    let hn = a.len() >> 1;
    for u in 0..hn {
        let a_re = a[u];
        let a_im = a[u + hn];
        a[u] = fpr_add(fpr_sqr(a_re), fpr_sqr(a_im));
        a[u + hn] = 0.0;
    }
}

pub(crate) fn poly_invnorm2_fft(d: &mut [Fpr], a: &[Fpr], b: &[Fpr], logn: usize) {
    check_len(d, logn);
    check_len(a, logn);
    check_len(b, logn);
    let hn = d.len() >> 1;
    for u in 0..hn {
        let a_re = a[u];
        let a_im = a[u + hn];
        let b_re = b[u];
        let b_im = b[u + hn];
        d[u] = fpr_inv(fpr_add(
            fpr_add(fpr_sqr(a_re), fpr_sqr(a_im)),
            fpr_add(fpr_sqr(b_re), fpr_sqr(b_im)),
        ));
    }
    for value in &mut d[hn..] {
        *value = 0.0;
    }
}

pub(crate) fn poly_mul_autoadj_fft(a: &mut [Fpr], b: &[Fpr], logn: usize) {
    check_len(a, logn);
    check_len(b, logn);
    let hn = a.len() >> 1;
    for u in 0..hn {
        a[u] = fpr_mul(a[u], b[u]);
        a[u + hn] = fpr_mul(a[u + hn], b[u]);
    }
}

pub(crate) fn poly_mulconst(a: &mut [Fpr], x: Fpr) {
    for value in a.iter_mut() {
        *value = fpr_mul(*value, x);
    }
}

pub(crate) fn poly_ldlmv_fft(
    d11: &mut [Fpr],
    l10: &mut [Fpr],
    g00: &[Fpr],
    g01: &[Fpr],
    g11: &[Fpr],
    logn: usize,
) {
    check_len(d11, logn);
    check_len(l10, logn);
    check_len(g00, logn);
    check_len(g01, logn);
    check_len(g11, logn);
    let n = 1usize << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (mu_re, mu_im) = fpc_div(g01[u], g01[u + hn], g00[u], g00[u + hn]);
        let (prod_re, prod_im) = fpc_mul(mu_re, mu_im, g01[u], fpr_neg(g01[u + hn]));
        d11[u] = fpr_sub(g11[u], prod_re);
        d11[u + hn] = fpr_sub(g11[u + hn], prod_im);
        l10[u] = mu_re;
        l10[u + hn] = fpr_neg(mu_im);
    }
}

pub(crate) fn poly_split_fft(f0: &mut [Fpr], f1: &mut [Fpr], f: &[Fpr], logn: usize, gm: &GmTable) {
    check_len(f, logn);
    check_len(f0, logn - 1);
    check_len(f1, logn - 1);
    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;

    f0[0] = f[0];
    f1[0] = f[hn];

    for u in 0..qn {
        let a_re = f[u << 1];
        let a_im = f[(u << 1) + hn];
        let b_re = f[(u << 1) + 1];
        let b_im = f[(u << 1) + 1 + hn];

        let t_re = fpr_add(a_re, b_re);
        let t_im = fpr_add(a_im, b_im);
        f0[u] = fpr_half(t_re);
        f0[u + qn] = fpr_half(t_im);

        let t_re = fpr_sub(a_re, b_re);
        let t_im = fpr_sub(a_im, b_im);
        let (gm_re, gm_im) = gm.get(u + hn);
        let (t_re, t_im) = fpc_mul(t_re, t_im, gm_re, fpr_neg(gm_im));
        f1[u] = fpr_half(t_re);
        f1[u + qn] = fpr_half(t_im);
    }
}

#[allow(dead_code)]
pub(crate) fn poly_merge_fft(f: &mut [Fpr], f0: &[Fpr], f1: &[Fpr], logn: usize, gm: &GmTable) {
    check_len(f, logn);
    check_len(f0, logn - 1);
    check_len(f1, logn - 1);
    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;

    f[0] = f0[0];
    f[hn] = f1[0];

    for u in 0..qn {
        let a_re = f0[u];
        let a_im = f0[u + qn];
        let (gm_re, gm_im) = gm.get(u + hn);
        let (b_re, b_im) = fpc_mul(f1[u], f1[u + qn], gm_re, gm_im);

        let t_re = fpr_add(a_re, b_re);
        let t_im = fpr_add(a_im, b_im);
        f[u << 1] = t_re;
        f[(u << 1) + hn] = t_im;
        let t_re = fpr_sub(a_re, b_re);
        let t_im = fpr_sub(a_im, b_im);
        f[(u << 1) + 1] = t_re;
        f[(u << 1) + 1 + hn] = t_im;
    }
}

pub(crate) fn smallints_to_fpr(values: &[i8], logn: usize) -> Vec<Fpr> {
    debug_assert_eq!(values.len(), 1usize << logn);
    values.iter().map(|&value| fpr_of(value as i64)).collect()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{fft, ifft, poly_merge_fft, poly_split_fft, smallints_to_fpr};
    use crate::fpr::GmTable;

    fn approx_eq(lhs: f64, rhs: f64) -> bool {
        (lhs - rhs).abs() <= 1e-9
    }

    #[test]
    fn test_fft_ifft_roundtrip_smallints() {
        let logn = 3usize;
        let mut poly = smallints_to_fpr(&[-3, 1, 4, 1, 5, -9, 2, 6], logn);
        let original = poly.clone();
        let gm = GmTable::new();

        fft(&mut poly, logn, &gm);
        ifft(&mut poly, logn, &gm);

        for (got, want) in poly.iter().zip(original.iter()) {
            assert!(approx_eq(*got, *want), "{got} != {want}");
        }
    }

    #[test]
    fn test_fft_split_merge_roundtrip() {
        let logn = 3usize;
        let gm = GmTable::new();
        let mut poly = smallints_to_fpr(&[2, -1, 3, 0, -4, 1, 5, -2], logn);
        fft(&mut poly, logn, &gm);

        let mut left = vec![0.0; 1 << (logn - 1)];
        let mut right = vec![0.0; 1 << (logn - 1)];
        poly_split_fft(&mut left, &mut right, &poly, logn, &gm);

        let mut merged = vec![0.0; 1 << logn];
        poly_merge_fft(&mut merged, &left, &right, logn, &gm);

        for (got, want) in merged.iter().zip(poly.iter()) {
            assert!(approx_eq(*got, *want), "{got} != {want}");
        }
    }
}
