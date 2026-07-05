extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::fft::{fft, fft_retrieve_error_poly};
use crate::gf::{gf_inverse, gf_mul};
use crate::params::Params;

// Constant-time helpers: all operands here are small (degrees/positions/counters
// < 256). All arithmetic is wrapping because the dev profile enables
// `overflow-checks`.

/// Returns 0xFFFF if a != 0, else 0x0000.
#[inline(always)]
fn ct_neq_zero_mask(a: u16) -> u16 {
    (((a | a.wrapping_neg()) >> 15) & 1).wrapping_neg()
}

/// Returns 0xFFFF if a == b, else 0x0000.
#[inline(always)]
fn ct_eq_mask(a: u16, b: u16) -> u16 {
    !ct_neq_zero_mask(a ^ b)
}

/// Returns 0xFFFF if a > b (unsigned, inputs < 2^15), else 0x0000.
#[inline(always)]
fn ct_gt_mask(a: u16, b: u16) -> u16 {
    let diff = (b as u32).wrapping_sub(a as u32); // bit 31 set iff a > b
    (0u32.wrapping_sub(diff >> 31)) as u16
}

/// Returns 0xFFFF if a <= b, else 0x0000.
#[inline(always)]
fn ct_le_mask(a: u16, b: u16) -> u16 {
    !ct_gt_mask(a, b)
}

/// Returns 0xFFFF if a < b, else 0x0000.
#[inline(always)]
fn ct_lt_mask(a: u16, b: u16) -> u16 {
    ct_gt_mask(b, a)
}

/// Constant-time select: returns `a` if mask == 0xFFFF, `b` if mask == 0.
#[inline(always)]
fn select_u16(mask: u16, a: u16, b: u16) -> u16 {
    (mask & a) | (!mask & b)
}

fn exp_at(index: usize) -> u16 {
    crate::gf::GF_EXP[index]
}

fn compute_syndromes(codeword: &[u8], params: &Params) -> Vec<u16> {
    let mut syndromes = vec![0u16; 2 * params.delta];

    for (i, syndrome) in syndromes.iter_mut().enumerate() {
        for j in 1..params.n1 {
            let power = ((i + 1) * j) % 255 ;
            *syndrome ^= gf_mul(u16::from(codeword[j]), exp_at(power));
        }
        *syndrome ^= u16::from(codeword[0]);
    }

    syndromes
}

fn compute_elp(syndromes: &[u16], params: &Params) -> (Vec<u16>, usize) {
    let mut sigma = vec![0u16; 1usize << params.fft];
    let mut deg_sigma = 0usize;
    let mut deg_sigma_p = 0usize;
    let mut sigma_copy = vec![0u16; params.delta + 1];
    let mut x_sigma_p = vec![0u16; params.delta + 1];
    x_sigma_p[1] = 1;
    let mut pp = u16::MAX;
    let mut d_p = 1u16;
    let mut d = syndromes[0];

    sigma[0] = 1;

    for mu in 0..(2 * params.delta) {
        sigma_copy[..=params.delta].copy_from_slice(&sigma[..=params.delta]);
        let deg_sigma_copy = deg_sigma;

        let dd = gf_mul(d, gf_inverse(d_p));
        for i in 1..=(mu + 1).min(params.delta) {
            sigma[i] ^= gf_mul(dd, x_sigma_p[i]);
        }

        let deg_x = (mu as u16).wrapping_sub(pp);
        let deg_x_sigma_p = deg_x as usize + deg_sigma_p;
        let mask1 = ct_neq_zero_mask(d);
        let mask2 = ct_gt_mask(deg_x_sigma_p as u16, deg_sigma as u16);
        let mask12 = mask1 & mask2;
        deg_sigma = select_u16(mask12, deg_x_sigma_p as u16, deg_sigma as u16) as usize;

        if mu == 2 * params.delta - 1 {
            break;
        }

        pp = select_u16(mask12, mu as u16, pp);
        d_p = select_u16(mask12, d, d_p);
        for i in (1..=params.delta).rev() {
            x_sigma_p[i] = select_u16(mask12, sigma_copy[i - 1], x_sigma_p[i]);
        }
        x_sigma_p[0] = select_u16(mask12, 0, x_sigma_p[0]);
        deg_sigma_p = select_u16(mask12, deg_sigma_copy as u16, deg_sigma_p as u16) as usize;

        d = syndromes[mu + 1];
        for i in 1..=(mu + 1).min(params.delta) {
            d ^= gf_mul(sigma[i], syndromes[mu + 1 - i]);
        }
    }

    (sigma, deg_sigma)
}

fn compute_roots(sigma: &[u16], params: &Params) -> Vec<u8> {
    let evaluations = fft(sigma, params.delta + 1, params.fft);
    fft_retrieve_error_poly(&evaluations)
}

fn compute_z_poly(sigma: &[u16], degree: usize, syndromes: &[u16], params: &Params) -> Vec<u16> {
    let mut z = vec![0u16; params.delta + 1];
    z[0] = 1;

    for i in 1..=params.delta {
        z[i] = select_u16(ct_le_mask(i as u16, degree as u16), sigma[i], z[i]);
    }

    z[1] ^= syndromes[0];
    for i in 2..=params.delta {
        z[i] ^= syndromes[i - 1];
        for j in 1..i {
            z[i] ^= gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }

    z
}

fn compute_error_values(z: &[u16], error: &[u8], params: &Params) -> Vec<u16> {
    let mut beta_j = vec![0u16; params.delta];
    let mut e_j = vec![0u16; params.delta];

    let mut delta_counter: u16 = 0;
    for index in 0..params.n1 {
        // valuemask = 0xFFFF at an error position, else 0 (error[] holds 0/1 flags).
        let valuemask = ct_neq_zero_mask(u16::from(error[index]));
        let val = exp_at(index); // PUBLIC index (loop position)
        for j in 0..params.delta {
            // Write beta_j[delta_counter] only, without revealing delta_counter.
            let indexmask = ct_eq_mask(j as u16, delta_counter);
            beta_j[j] ^= indexmask & valuemask & val;
        }
        delta_counter = delta_counter.wrapping_add(valuemask & 1);
    }
    let delta_real_value = delta_counter.min(params.delta as u16) as usize;

    for i in 0..params.delta {
        let inverse = gf_inverse(beta_j[i]);
        let mut inverse_power_j = 1u16;
        let mut tmp1 = 1u16;
        let mut tmp2 = 1u16;

        for &zj in z.iter().take(params.delta + 1).skip(1) {
            inverse_power_j = gf_mul(inverse_power_j, inverse);
            tmp1 ^= gf_mul(inverse_power_j, zj);
        }
        for k in 1..params.delta {
            tmp2 = gf_mul(tmp2, 1 ^ gf_mul(inverse, beta_j[(i + k) % params.delta]));
        }

        // Compute unconditionally (gf_inverse(0)==0 makes unused slots harmless),
        // then store only for i < delta_real_value via a constant-time mask.
        let candidate = gf_mul(tmp1, gf_inverse(tmp2));
        e_j[i] = select_u16(ct_lt_mask(i as u16, delta_real_value as u16), candidate, e_j[i]);
    }

    let mut error_values = vec![0u16; params.n1];
    let mut delta_counter: u16 = 0;
    for index in 0..params.n1 {
        let valuemask = ct_neq_zero_mask(u16::from(error[index]));
        // Constant-time read of e_j[delta_counter] (0 when delta_counter >= delta).
        let mut ev = 0u16;
        for j in 0..params.delta {
            ev ^= ct_eq_mask(j as u16, delta_counter) & e_j[j];
        }
        error_values[index] ^= valuemask & ev;
        delta_counter = delta_counter.wrapping_add(valuemask & 1);
    }

    error_values
}

pub fn encode(message: &[u8], params: &Params) -> Vec<u8> {
    let mut codeword = vec![0u8; params.n1];

    for i in 0..params.k {
        let gate_value = message[params.k - 1 - i] ^ codeword[params.n1 - params.k - 1];
        let mut tmp = vec![0u16; params.g];
        for (slot, coeff) in tmp.iter_mut().zip(params.rs_poly.iter().copied()) {
            *slot = gf_mul(u16::from(gate_value), coeff);
        }
        for k in (1..=(params.n1 - params.k - 1)).rev() {
            codeword[k] = codeword[k - 1] ^ tmp[k] as u8;
        }
        codeword[0] = tmp[0] as u8;
    }

    codeword[params.n1 - params.k..].copy_from_slice(message);
    codeword
}

pub fn decode(codeword: &[u8], params: &Params) -> Vec<u8> {
    let mut corrected = codeword.to_vec();
    let syndromes = compute_syndromes(&corrected, params);
    let (sigma, degree) = compute_elp(&syndromes, params);
    let error = compute_roots(&sigma, params);
    let z = compute_z_poly(&sigma, degree, &syndromes, params);
    let error_values = compute_error_values(&z, &error, params);

    for (slot, &value) in corrected.iter_mut().zip(error_values.iter()) {
        *slot ^= value as u8;
    }

    corrected[params.g - 1..params.g - 1 + params.k].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_mask_helpers_match_reference_exhaustively() {
        for a in 0..256u16 {
            assert_eq!(
                ct_neq_zero_mask(a),
                if a != 0 { 0xFFFF } else { 0 },
                "ct_neq_zero_mask({a})"
            );
            for b in 0..256u16 {
                assert_eq!(ct_eq_mask(a, b), if a == b { 0xFFFF } else { 0 }, "ct_eq_mask({a},{b})");
                assert_eq!(ct_gt_mask(a, b), if a > b { 0xFFFF } else { 0 }, "ct_gt_mask({a},{b})");
                assert_eq!(ct_le_mask(a, b), if a <= b { 0xFFFF } else { 0 }, "ct_le_mask({a},{b})");
                assert_eq!(ct_lt_mask(a, b), if a < b { 0xFFFF } else { 0 }, "ct_lt_mask({a},{b})");
                assert_eq!(select_u16(0xFFFF, a, b), a, "select_u16(all-ones)");
                assert_eq!(select_u16(0, a, b), b, "select_u16(zero)");
            }
        }
    }
}
