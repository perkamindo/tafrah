extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::gf::{gf_inverse, gf_mul, gf_square, GF_LOG};

const PARAM_M: usize = 8;
const GF_MUL_ORDER: usize = 255;

fn compute_fft_betas() -> [u16; PARAM_M - 1] {
    let mut betas = [0u16; PARAM_M - 1];
    for (index, slot) in betas.iter_mut().enumerate() {
        *slot = 1u16 << (PARAM_M - 1 - index);
    }
    betas
}

fn compute_subset_sums(set: &[u16]) -> Vec<u16> {
    let mut subset_sums = vec![0u16; 1usize << set.len()];
    for (i, &value) in set.iter().enumerate() {
        for j in 0..(1usize << i) {
            subset_sums[(1usize << i) + j] = value ^ subset_sums[j];
        }
    }
    subset_sums
}

fn radix(f: &[u16], m_f: usize) -> (Vec<u16>, Vec<u16>) {
    let half = 1usize << (m_f - 1);
    let mut f0 = vec![0u16; half];
    let mut f1 = vec![0u16; half];

    match m_f {
        1 => {
            f0[0] = f[0];
            f1[0] = f[1];
        }
        2 => {
            f0[0] = f[0];
            f0[1] = f[2] ^ f[3];
            f1[0] = f[1] ^ f0[1];
            f1[1] = f[3];
        }
        3 => {
            f0[0] = f[0];
            f0[2] = f[4] ^ f[6];
            f0[3] = f[6] ^ f[7];
            f1[1] = f[3] ^ f[5] ^ f[7];
            f1[2] = f[5] ^ f[6];
            f1[3] = f[7];
            f0[1] = f[2] ^ f0[2] ^ f1[1];
            f1[0] = f[1] ^ f0[1];
        }
        4 => {
            f0[4] = f[8] ^ f[12];
            f0[6] = f[12] ^ f[14];
            f0[7] = f[14] ^ f[15];
            f1[5] = f[11] ^ f[13];
            f1[6] = f[13] ^ f[14];
            f1[7] = f[15];
            f0[5] = f[10] ^ f[12] ^ f1[5];
            f1[4] = f[9] ^ f[13] ^ f0[5];

            f0[0] = f[0];
            f1[3] = f[7] ^ f[11] ^ f[15];
            f0[3] = f[6] ^ f[10] ^ f[14] ^ f1[3];
            f0[2] = f[4] ^ f0[4] ^ f0[3] ^ f1[3];
            f1[1] = f[3] ^ f[5] ^ f[9] ^ f[13] ^ f1[3];
            f1[2] = f[3] ^ f1[1] ^ f0[3];
            f0[1] = f[2] ^ f0[2] ^ f1[1];
            f1[0] = f[1] ^ f0[1];
        }
        _ => {
            let n = 1usize << (m_f - 2);
            let mut q = vec![0u16; 2 * n];
            let mut r = vec![0u16; 2 * n];

            q[..n].copy_from_slice(&f[3 * n..4 * n]);
            q[n..2 * n].copy_from_slice(&f[3 * n..4 * n]);
            r.copy_from_slice(&f[..2 * n]);
            for i in 0..n {
                q[i] ^= f[2 * n + i];
                r[n + i] ^= q[i];
            }

            let (q0, q1) = radix(&q, m_f - 1);
            let (r0, r1) = radix(&r, m_f - 1);

            f0[..n].copy_from_slice(&r0[..n]);
            f0[n..2 * n].copy_from_slice(&q0[..n]);
            f1[..n].copy_from_slice(&r1[..n]);
            f1[n..2 * n].copy_from_slice(&q1[..n]);
        }
    }

    (f0, f1)
}

fn fft_rec(w: &mut [u16], f: &mut [u16], f_coeffs: usize, m: usize, m_f: usize, betas: &[u16]) {
    if m_f == 1 {
        let mut tmp = vec![0u16; m];
        for i in 0..m {
            tmp[i] = gf_mul(betas[i], f[1]);
        }

        w[0] = f[0];
        let mut x = 1usize;
        for &value in &tmp {
            for k in 0..x {
                w[x + k] = w[k] ^ value;
            }
            x <<= 1;
        }
        return;
    }

    if betas[m - 1] != 1 {
        let mut beta_m_pow = 1u16;
        let limit = 1usize << m_f;
        for coeff in f.iter_mut().take(limit).skip(1) {
            beta_m_pow = gf_mul(beta_m_pow, betas[m - 1]);
            *coeff = gf_mul(beta_m_pow, *coeff);
        }
    }

    let (f0, f1) = radix(f, m_f);

    let mut gammas = vec![0u16; m - 1];
    let mut deltas = vec![0u16; m - 1];
    let beta_inverse = gf_inverse(betas[m - 1]);
    for i in 0..(m - 1) {
        gammas[i] = gf_mul(betas[i], beta_inverse);
        deltas[i] = gf_square(gammas[i]) ^ gammas[i];
    }
    let gamma_sums = compute_subset_sums(&gammas);

    let k = 1usize << (m - 1);
    let mut u = vec![0u16; k];
    let mut f0 = f0;
    fft_rec(
        &mut u,
        &mut f0,
        f_coeffs.div_ceil(2),
        m - 1,
        m_f - 1,
        &deltas,
    );

    if f_coeffs <= 3 {
        w[0] = u[0];
        w[k] = u[0] ^ f1[0];
        for i in 1..k {
            w[i] = u[i] ^ gf_mul(gamma_sums[i], f1[0]);
            w[k + i] = w[i] ^ f1[0];
        }
        return;
    }

    let mut v = vec![0u16; k];
    let mut f1 = f1;
    fft_rec(&mut v, &mut f1, f_coeffs / 2, m - 1, m_f - 1, &deltas);

    w[k..2 * k].copy_from_slice(&v);
    w[0] = u[0];
    w[k] ^= u[0];
    for i in 1..k {
        w[i] = u[i] ^ gf_mul(gamma_sums[i], v[i]);
        w[k + i] ^= w[i];
    }
}

pub fn fft(f: &[u16], f_coeffs: usize, fft_param: usize) -> Vec<u16> {
    let betas = compute_fft_betas();
    let betas_sums = compute_subset_sums(&betas);

    let (mut f0, mut f1) = radix(f, fft_param);

    let mut deltas = [0u16; PARAM_M - 1];
    for i in 0..(PARAM_M - 1) {
        deltas[i] = gf_square(betas[i]) ^ betas[i];
    }

    let mut u = vec![0u16; 1usize << (PARAM_M - 1)];
    let mut v = vec![0u16; 1usize << (PARAM_M - 1)];
    fft_rec(
        &mut u,
        &mut f0,
        f_coeffs.div_ceil(2),
        PARAM_M - 1,
        fft_param - 1,
        &deltas,
    );
    fft_rec(
        &mut v,
        &mut f1,
        f_coeffs / 2,
        PARAM_M - 1,
        fft_param - 1,
        &deltas,
    );

    let k = 1usize << (PARAM_M - 1);
    let mut w = vec![0u16; 1usize << PARAM_M];
    w[k..2 * k].copy_from_slice(&v);
    w[0] = u[0];
    w[k] ^= u[0];
    for i in 1..k {
        w[i] = u[i] ^ gf_mul(betas_sums[i], v[i]);
        w[k + i] ^= w[i];
    }

    w
}

pub fn fft_retrieve_error_poly(w: &[u16]) -> Vec<u8> {
    let gammas = compute_fft_betas();
    let gamma_sums = compute_subset_sums(&gammas);
    let k = 1usize << (PARAM_M - 1);
    let mut error = vec![0u8; 1usize << PARAM_M];

    error[0] ^= 1 ^ (((w[0].wrapping_neg()) >> 15) as u8);
    error[0] ^= 1 ^ (((w[k].wrapping_neg()) >> 15) as u8);

    for i in 1..k {
        let index = GF_MUL_ORDER - GF_LOG[gamma_sums[i] as usize] as usize;
        error[index] ^= 1 ^ (((w[i].wrapping_neg()) >> 15) as u8);

        let index = GF_MUL_ORDER - GF_LOG[(gamma_sums[i] ^ 1) as usize] as usize;
        error[index] ^= 1 ^ (((w[k + i].wrapping_neg()) >> 15) as u8);
    }

    error
}
