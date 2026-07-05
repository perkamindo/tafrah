extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::params::Params;

const SEEDEXPANDER_DOMAIN: u8 = 2;
const SEEDEXPANDER_BLOCK_BYTES: usize = core::mem::size_of::<u64>();

fn round_up_seedexpander_request(out_len: usize) -> usize {
    let remainder = out_len % SEEDEXPANDER_BLOCK_BYTES;
    if remainder == 0 {
        out_len
    } else {
        out_len + (SEEDEXPANDER_BLOCK_BYTES - remainder)
    }
}

fn seedexpander_bytes(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&[SEEDEXPANDER_DOMAIN]);
    let mut reader = shake.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

fn seedexpander_sequence(seed: &[u8], lengths: &[usize]) -> Vec<Vec<u8>> {
    let total_consumed = lengths
        .iter()
        .copied()
        .map(round_up_seedexpander_request)
        .sum();
    let stream = seedexpander_bytes(seed, total_consumed);

    let mut outputs = Vec::with_capacity(lengths.len());
    let mut offset = 0usize;
    for &length in lengths {
        outputs.push(stream[offset..offset + length].to_vec());
        offset += round_up_seedexpander_request(length);
    }

    outputs
}

fn fixed_weight_vector_from_bytes(stream: &[u8], weight: usize, params: &Params) -> Vec<u64> {
    let mut rand_u32 = vec![0u32; weight];
    for (index, chunk) in stream.chunks_exact(4).enumerate() {
        rand_u32[index] = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    fixed_weight_vector_from_u32_stream(&rand_u32, weight, params)
}

fn words_from_bytes_le(bytes: &[u8], word_count: usize) -> Vec<u64> {
    let mut words = vec![0u64; word_count];

    for (index, chunk) in bytes.chunks(8).enumerate() {
        let mut padded = [0u8; 8];
        padded[..chunk.len()].copy_from_slice(chunk);
        words[index] = u64::from_le_bytes(padded);
    }

    words
}

/// Conditional subtraction: returns `r - n` if that did not borrow, else `r`.
/// Branchless port of PQClean `cond_sub`.
fn cond_sub(r: u32, n: u32) -> u32 {
    let r = r.wrapping_sub(n);
    let mask = (r >> 31).wrapping_neg(); // 0xFFFF_FFFF iff the subtraction borrowed
    r.wrapping_add(n & mask)
}

/// Barrett reduction: computes `a % n` in constant time, where `m = floor(2^32 / n)`.
/// Branchless port of PQClean `reduce`. Caller guarantees `n` is the public divisor `params.n - i`.
fn reduce(a: u32, n: u32, m: u32) -> u32 {
    let q = (((a as u64) * (m as u64)) >> 32) as u32;
    let r = a.wrapping_sub(q.wrapping_mul(n));
    cond_sub(r, n)
}

/// Builds `1u64 << pos` (pos in 0..64) without a secret-dependent shift.
/// Branchless port of PQClean `single_bit_mask`.
fn single_bit_mask(pos: u32) -> u64 {
    let mut ret: u64 = 0;
    let mut mask: u64 = 1;
    for i in 0..64u64 {
        let tmp = (pos as u64).wrapping_sub(i);
        let selector = (1u64.wrapping_sub((tmp | tmp.wrapping_neg()) >> 63)).wrapping_neg();
        ret |= mask & selector;
        mask <<= 1;
    }
    ret
}

/// Precomputes Barrett constants `m_val[i] = floor(2^32 / (n - i))` for i in 0..weight.
/// Operates ONLY on public data (params.n, loop index i); the resulting udiv is
/// isolated here, outside the secret-dependent sampler loop. `#[inline(never)]` keeps
/// the divide out of the sampler symbol so the constant-time asm audit greps cleanly.
#[inline(never)]
fn compute_m_val(n: usize, weight: usize) -> Vec<u32> {
    let mut m_val = vec![0u32; weight];
    for i in 0..weight {
        m_val[i] = ((1u64 << 32) / (n as u64 - i as u64)) as u32;
    }
    m_val
}

/// Constant-time equality: returns 1 if v1 == v2, else 0.
/// Branchless port of the PQClean reference (https://gist.github.com/sneves/10845247).
fn compare_u32(v1: u32, v2: u32) -> u32 {
    1 ^ ((v1.wrapping_sub(v2) | v2.wrapping_sub(v1)) >> 31)
}

pub fn random_vector_from_seed(seed: &[u8], params: &Params) -> Vec<u64> {
    let bytes = seedexpander_bytes(seed, params.vec_n_size_bytes());
    let mut words = words_from_bytes_le(&bytes, params.vec_n_size_u64());
    let last = words
        .last_mut()
        .expect("vector representation has at least one word");
    *last &= params.red_mask();
    words
}

pub fn fixed_weight_vector_from_u32_stream(
    rand_u32: &[u32],
    weight: usize,
    params: &Params,
) -> Vec<u64> {
    let mut support = vec![0u32; weight];
    let mut index_tab = vec![0u32; weight];
    let mut bit_tab = vec![0u64; weight];
    let mut vector = vec![0u64; params.vec_n_size_u64()];

    // Barrett constants over PUBLIC data only (n, i) — computed once, outside the
    // secret-dependent loop. Isolated in compute_m_val so no divide enters this fn.
    let m_val = compute_m_val(params.n, weight);

    // Constant-time fixed-weight support sampling (no secret-dependent modulo).
    for i in 0..weight {
        let n_minus_i = (params.n as u32).wrapping_sub(i as u32);
        support[i] = (i as u32).wrapping_add(reduce(rand_u32[i], n_minus_i, m_val[i]));
    }

    // Constant-time deduplication: i runs from weight-2 down to 0.
    for i in (0..weight).rev().skip(1) {
        let mut found = 0u32;
        for j in (i + 1)..weight {
            found |= compare_u32(support[j], support[i]);
        }
        let mask32 = found.wrapping_neg(); // 0xFFFF_FFFF iff a duplicate was found
        support[i] = (mask32 & (i as u32)) ^ ((!mask32) & support[i]);
    }

    // Constant-time bit-position expansion (no secret-dependent shift).
    for i in 0..weight {
        index_tab[i] = support[i] >> 6;
        let pos = support[i] & 0x3f;
        bit_tab[i] = single_bit_mask(pos);
    }

    // Constant-time scatter into the output vector (no branch on secret index).
    for (word_index, slot) in vector.iter_mut().enumerate() {
        let mut value = 0u64;
        for j in 0..weight {
            let mask64 = (compare_u32(word_index as u32, index_tab[j]) as u64).wrapping_neg();
            value |= bit_tab[j] & mask64;
        }
        *slot |= value;
    }

    vector
}

pub fn fixed_weight_vector_from_seed(seed: &[u8], weight: usize, params: &Params) -> Vec<u64> {
    let stream = seedexpander_sequence(seed, &[4 * weight])
        .pop()
        .expect("single seedexpander request");
    fixed_weight_vector_from_bytes(&stream, weight, params)
}

pub fn fixed_weight_vectors_from_seed_sequence(
    seed: &[u8],
    weights: &[usize],
    params: &Params,
) -> Vec<Vec<u64>> {
    let lengths: Vec<usize> = weights.iter().map(|weight| 4 * weight).collect();
    let streams = seedexpander_sequence(seed, &lengths);

    streams
        .into_iter()
        .zip(weights.iter().copied())
        .map(|(stream, weight)| fixed_weight_vector_from_bytes(&stream, weight, params))
        .collect()
}

pub fn secret_vectors_from_seed(seed: &[u8], params: &Params) -> (Vec<u64>, Vec<u64>) {
    let mut vectors =
        fixed_weight_vectors_from_seed_sequence(seed, &[params.omega, params.omega], params);
    let y = vectors.pop().expect("y vector");
    let x = vectors.pop().expect("x vector");
    (x, y)
}

pub fn words_to_bytes_le(words: &[u64], byte_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 8);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(byte_len);
    out
}
