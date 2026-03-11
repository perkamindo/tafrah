extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::fft::{fft, fft_retrieve_error_poly};
use crate::gf::{gf_inverse, gf_mul};
use crate::params::Params;

fn exp_at(index: usize) -> u16 {
    crate::gf::GF_EXP[index]
}

fn compute_syndromes(codeword: &[u8], params: &Params) -> Vec<u16> {
    let mut syndromes = vec![0u16; 2 * params.delta];

    for (i, syndrome) in syndromes.iter_mut().enumerate() {
        for j in 1..params.n1 {
            let power = (((i + 1) * j) % 255) as usize;
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
        let mask1 = if d != 0 { u16::MAX } else { 0 };
        let mask2 = if deg_x_sigma_p > deg_sigma {
            u16::MAX
        } else {
            0
        };
        let mask12 = mask1 & mask2;
        if mask12 != 0 {
            deg_sigma = deg_x_sigma_p;
        }

        if mu == 2 * params.delta - 1 {
            break;
        }

        if mask12 != 0 {
            pp = mu as u16;
            d_p = d;
            for i in (1..=params.delta).rev() {
                x_sigma_p[i] = sigma_copy[i - 1];
            }
            x_sigma_p[0] = 0;
            deg_sigma_p = deg_sigma_copy;
        }

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
        if i <= degree {
            z[i] = sigma[i];
        }
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

    let mut delta_counter = 0usize;
    for (index, &error_bit) in error.iter().take(params.n1).enumerate() {
        if error_bit == 0 {
            continue;
        }
        if delta_counter < params.delta {
            beta_j[delta_counter] = exp_at(index);
        }
        delta_counter += 1;
    }
    let delta_real_value = delta_counter.min(params.delta);

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

        if i < delta_real_value {
            e_j[i] = gf_mul(tmp1, gf_inverse(tmp2));
        }
    }

    let mut error_values = vec![0u16; params.n1];
    delta_counter = 0;
    for (index, &error_bit) in error.iter().take(params.n1).enumerate() {
        if error_bit == 0 {
            continue;
        }
        if delta_counter < params.delta {
            error_values[index] = e_j[delta_counter];
        }
        delta_counter += 1;
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
