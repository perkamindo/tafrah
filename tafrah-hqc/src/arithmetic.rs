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

pub fn cyclic_product_mod_xn_minus_1(lhs: &[u64], rhs: &[u64], params: &Params) -> Vec<u64> {
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
