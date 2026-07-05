extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::params::Params;

pub fn vector_add(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
    lhs.iter().zip(rhs).map(|(a, b)| a ^ b).collect()
}

pub fn vector_compare(lhs: &[u8], rhs: &[u8]) -> u8 {
    let mut acc = 0u64;
    for (&a, &b) in lhs.iter().zip(rhs) {
        acc |= u64::from(a ^ b);
    }

    ((!acc).wrapping_add(1) >> 63) as u8
}

pub fn resize_vector(words: &[u64], out_bits: usize) -> Vec<u64> {
    let out_words = out_bits.div_ceil(64);
    let mut out = vec![0u64; out_words];

    // Data-oblivious zero-extend / truncate: copy the overlapping words directly
    // (no secret-dependent per-bit branch), then mask the final word to out_bits.
    let copy = core::cmp::min(out_words, words.len());
    out[..copy].copy_from_slice(&words[..copy]);

    if let Some(last) = out.last_mut() {
        let rem = out_bits % 64;
        if rem != 0 {
            *last &= (1u64 << rem) - 1;
        }
    }

    out
}

pub fn bit_positions(words: &[u64], bit_len: usize) -> Vec<usize> {
    let mut positions = Vec::new();

    for (word_index, &word) in words.iter().enumerate() {
        let mut cursor = word;
        while cursor != 0 {
            let offset = cursor.trailing_zeros() as usize;
            let bit = word_index * 64 + offset;
            if bit >= bit_len {
                break;
            }
            positions.push(bit);
            cursor &= cursor - 1;
        }
    }

    positions
}

/// Constant-time carryless 64x64 -> 128 multiply (window-4), branchless and with
/// no secret-indexed table (mirrors `gf::gf_carryless_mul`, widened to 64 bits).
/// Returns `(lo, hi)`: bit `t` (0..128) of the 128-bit value is product degree `t`.
fn clmul64(a: u64, b: u64) -> (u64, u64) {
    // u[k] = k (mod 2 poly) * (low 60 bits of b). Masking b to 60 bits keeps each
    // `u[k] << i` within 64 bits; b's top 4 bits are folded back in Step 3.
    let b_low = b & ((1u64 << 60) - 1);
    let mut u = [0u64; 16];
    u[1] = b_low;
    u[2] = u[1] << 1;
    u[3] = u[2] ^ u[1];
    u[4] = u[2] << 1;
    u[5] = u[4] ^ u[1];
    u[6] = u[3] << 1;
    u[7] = u[6] ^ u[1];
    u[8] = u[4] << 1;
    u[9] = u[8] ^ u[1];
    u[10] = u[5] << 1;
    u[11] = u[10] ^ u[1];
    u[12] = u[6] << 1;
    u[13] = u[12] ^ u[1];
    u[14] = u[7] << 1;
    u[15] = u[14] ^ u[1];

    // Branchless select of u[sel], sel in 0..16 (no secret-indexed load).
    let select = |sel: u64| -> u64 {
        let mut acc = 0u64;
        let mut k = 0u64;
        while k < 16 {
            let tmp = sel.wrapping_sub(k);
            let is_eq = 1u64.wrapping_sub((tmp | tmp.wrapping_neg()) >> 63); // 1 iff k == sel
            acc ^= u[k as usize] & 0u64.wrapping_sub(is_eq);
            k += 1;
        }
        acc
    };

    let mut l = select(a & 0x0f);
    let mut h = 0u64;

    // Nibbles 4,8,...,60 of a. Shift amount `64 - i` is in 60..=4 — never 64.
    let mut i = 4u32;
    while i < 64 {
        let g = select((a >> i) & 0x0f);
        l ^= g << i;
        h ^= g >> (64 - i);
        i += 4;
    }

    // Add back a * (top 4 bits of b), gated by branchless masks. Shifts are 60..=63
    // (l) and 1..=4 (h) — never 64.
    let m0 = 0u64.wrapping_sub((b >> 60) & 1);
    let m1 = 0u64.wrapping_sub((b >> 61) & 1);
    let m2 = 0u64.wrapping_sub((b >> 62) & 1);
    let m3 = 0u64.wrapping_sub((b >> 63) & 1);
    l ^= (a << 60) & m0;
    h ^= (a >> 4) & m0;
    l ^= (a << 61) & m1;
    h ^= (a >> 3) & m1;
    l ^= (a << 62) & m2;
    h ^= (a >> 2) & m2;
    l ^= (a << 63) & m3;
    h ^= (a >> 1) & m3;

    (l, h)
}

/// Dense schoolbook carryless product of two W-word polynomials into 2W words.
/// O(W^2) `clmul64` calls, fully data-oblivious (every word pair is multiplied).
fn carryless_mul_dense(a: &[u64], b: &[u64], out: &mut [u64]) {
    let w = a.len();
    debug_assert_eq!(b.len(), w);
    debug_assert_eq!(out.len(), 2 * w);
    for i in 0..w {
        for j in 0..w {
            let (lo, hi) = clmul64(a[i], b[j]);
            out[i + j] ^= lo;
            out[i + j + 1] ^= hi;
        }
    }
}

/// Constant-time cyclic product in GF(2)[x] / (x^n - 1). Data-oblivious: every
/// word of both operands is processed regardless of content, so it has no
/// secret-dependent branch or memory-access pattern. Byte-identical to the
/// previous sparse implementation (kept as the `sparse_product_oracle` test).
pub fn cyclic_product_mod_xn_minus_1(lhs: &[u64], rhs: &[u64], params: &Params) -> Vec<u64> {
    let w = params.vec_n_size_u64();

    // Copy operands into exactly W words and clear bits >= n in the last word,
    // matching the sparse oracle which ignores positions >= params.n.
    let mut a = vec![0u64; w];
    let mut b = vec![0u64; w];
    let na = core::cmp::min(lhs.len(), w);
    let nb = core::cmp::min(rhs.len(), w);
    a[..na].copy_from_slice(&lhs[..na]);
    b[..nb].copy_from_slice(&rhs[..nb]);
    a[w - 1] &= params.red_mask();
    b[w - 1] &= params.red_mask();

    // Full 2W-word carryless product.
    let mut prod = vec![0u64; 2 * w];
    carryless_mul_dense(&a, &b, &mut prod);

    // Reduce mod (x^n - 1): degree k folds to (k mod n). Word-wise fold; product
    // degree <= 2n-2 < 2n so a single fold suffices.
    let s = params.n % 64;
    let mut out = vec![0u64; w];
    if s == 0 {
        for i in 0..w {
            out[i] = prod[i] ^ prod[i + w];
        }
    } else {
        for i in 0..w {
            let r = prod[i + w - 1] >> s;
            let carry = prod[i + w] << (64 - s);
            out[i] = prod[i] ^ r ^ carry;
        }
    }

    if let Some(last) = out.last_mut() {
        *last &= params.red_mask();
    }

    out
}

pub fn bit_is_set(words: &[u64], bit: usize) -> bool {
    let word_index = bit / 64;
    if word_index >= words.len() {
        return false;
    }
    ((words[word_index] >> (bit % 64)) & 1) != 0
}

pub fn toggle_bit(words: &mut [u64], bit: usize) {
    words[bit / 64] ^= 1u64 << (bit % 64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{HQC_128, HQC_192, HQC_256};

    /// Verbatim copy of the previous sparse implementation, retained as the
    /// differential oracle for the constant-time dense multiply.
    fn sparse_product_oracle(lhs: &[u64], rhs: &[u64], params: &Params) -> Vec<u64> {
        let lhs_positions = bit_positions(lhs, params.n);
        let rhs_positions = bit_positions(rhs, params.n);
        let (sparse, dense) = if lhs_positions.len() <= rhs_positions.len() {
            (&lhs_positions, &rhs_positions)
        } else {
            (&rhs_positions, &lhs_positions)
        };
        let mut out = vec![0u64; params.vec_n_size_u64()];
        for &a in sparse {
            for &b in dense {
                let mut bit = a + b;
                if bit >= params.n {
                    bit -= params.n;
                }
                toggle_bit(&mut out, bit);
            }
        }
        if let Some(last) = out.last_mut() {
            *last &= params.red_mask();
        }
        out
    }

    // Small deterministic xorshift so the test needs no rng dependency (no_std).
    fn fill_random(v: &mut [u64], state: &mut u64) {
        for w in v.iter_mut() {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            *w = x;
        }
    }

    // Verbatim copy of the previous bitwise resize, retained as the oracle.
    fn resize_vector_oracle(words: &[u64], out_bits: usize) -> Vec<u64> {
        let out_words = out_bits.div_ceil(64);
        let mut out = vec![0u64; out_words];
        for bit in 0..out_bits {
            if bit_is_set(words, bit) {
                toggle_bit(&mut out, bit);
            }
        }
        if let Some(last) = out.last_mut() {
            let rem = out_bits % 64;
            if rem != 0 {
                *last &= (1u64 << rem) - 1;
            }
        }
        out
    }

    #[test]
    fn resize_vector_matches_bitwise_oracle() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for &in_words in &[1usize, 5, 17] {
            let mut words = vec![0u64; in_words];
            fill_random(&mut words, &mut state);
            for &out_bits in &[
                1usize,
                63,
                64,
                65,
                100,
                64 * in_words,
                64 * in_words + 50,
                64 * in_words - 3,
            ] {
                assert_eq!(
                    resize_vector(&words, out_bits),
                    resize_vector_oracle(&words, out_bits),
                    "resize_vector({in_words} words, {out_bits} bits)"
                );
            }
        }
    }

    #[test]
    fn dense_matches_sparse_for_random_inputs() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for params in [&HQC_128, &HQC_192, &HQC_256] {
            let w = params.vec_n_size_u64();
            for _ in 0..4 {
                let mut a = vec![0u64; w];
                let mut b = vec![0u64; w];
                fill_random(&mut a, &mut state);
                fill_random(&mut b, &mut state);
                let got = cyclic_product_mod_xn_minus_1(&a, &b, params);
                let want = sparse_product_oracle(&a, &b, params);
                assert_eq!(got, want, "dense != sparse at n={}", params.n);
            }
        }
    }
}
