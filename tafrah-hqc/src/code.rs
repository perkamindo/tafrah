extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::arithmetic::resize_vector;
use crate::params::Params;
use crate::reed_muller;
use crate::reed_solomon;

fn words_from_bytes_le(bytes: &[u8], word_count: usize) -> Vec<u64> {
    let mut words = vec![0u64; word_count];
    for (index, chunk) in bytes.chunks(8).enumerate() {
        let mut padded = [0u8; 8];
        padded[..chunk.len()].copy_from_slice(chunk);
        words[index] = u64::from_le_bytes(padded);
    }
    words
}

fn words_to_bytes_le(words: &[u64], byte_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 8);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(byte_len);
    out
}

pub fn encode(message: &[u64], params: &Params) -> Vec<u64> {
    let message_bytes = words_to_bytes_le(message, params.vec_k_size_bytes());
    let rs = reed_solomon::encode(&message_bytes, params);
    let rm = reed_muller::encode(&rs, params);
    words_from_bytes_le(&rm, params.vec_n1n2_size_u64())
}

pub fn decode(codeword: &[u64], params: &Params) -> Vec<u64> {
    let resized = resize_vector(codeword, params.n1n2);
    let codeword_bytes = words_to_bytes_le(&resized, params.vec_n1n2_size_bytes());
    let rs = reed_muller::decode(&codeword_bytes, params);
    let message = reed_solomon::decode(&rs, params);
    words_from_bytes_le(&message, params.vec_k_size_u64())
}
