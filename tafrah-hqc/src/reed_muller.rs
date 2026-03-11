extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::params::Params;

fn bit0mask(value: i32) -> i32 {
    -(value & 1)
}

fn encode_byte(message: u8) -> [u32; 4] {
    let message = i32::from(message);
    let mut first_word = bit0mask(message >> 7);

    first_word ^= bit0mask(message >> 0) & 0xaaaa_aaaa_u32 as i32;
    first_word ^= bit0mask(message >> 1) & 0xcccc_cccc_u32 as i32;
    first_word ^= bit0mask(message >> 2) & 0xf0f0_f0f0_u32 as i32;
    first_word ^= bit0mask(message >> 3) & 0xff00_ff00_u32 as i32;
    first_word ^= bit0mask(message >> 4) & 0xffff_0000_u32 as i32;

    let word0 = first_word as u32;
    first_word ^= bit0mask(message >> 5);
    let word1 = first_word as u32;
    first_word ^= bit0mask(message >> 6);
    let word3 = first_word as u32;
    first_word ^= bit0mask(message >> 5);
    let word2 = first_word as u32;

    [word0, word1, word2, word3]
}

fn hadamard(values: &mut [i16; 128], scratch: &mut [i16; 128]) {
    let mut src_is_values = true;

    for _ in 0..7 {
        let (src, dst) = if src_is_values {
            (&*values, &mut *scratch)
        } else {
            (&*scratch, &mut *values)
        };

        for i in 0..64 {
            dst[i] = src[2 * i] + src[2 * i + 1];
            dst[i + 64] = src[2 * i] - src[2 * i + 1];
        }

        src_is_values = !src_is_values;
    }

    if !src_is_values {
        values.copy_from_slice(scratch);
    }
}

fn find_peak(transform: &[i16; 128]) -> u8 {
    let mut peak_abs_value = 0i32;
    let mut peak_value = 0i32;
    let mut peak_pos = 0i32;

    for (index, &value) in transform.iter().enumerate() {
        let value = i32::from(value);
        let absolute = value.abs();
        if absolute > peak_abs_value {
            peak_abs_value = absolute;
            peak_value = value;
            peak_pos = index as i32;
        }
    }

    if peak_value > 0 {
        peak_pos |= 128;
    }

    peak_pos as u8
}

pub fn encode(message: &[u8], params: &Params) -> Vec<u8> {
    let multiplicity = params.n2.div_ceil(128);
    let mut out = vec![0u8; params.vec_n1n2_size_bytes()];

    for (byte_index, &message_byte) in message.iter().enumerate() {
        let words = encode_byte(message_byte);
        let codeword_bytes: [u8; 16] = [
            words[0].to_le_bytes()[0],
            words[0].to_le_bytes()[1],
            words[0].to_le_bytes()[2],
            words[0].to_le_bytes()[3],
            words[1].to_le_bytes()[0],
            words[1].to_le_bytes()[1],
            words[1].to_le_bytes()[2],
            words[1].to_le_bytes()[3],
            words[2].to_le_bytes()[0],
            words[2].to_le_bytes()[1],
            words[2].to_le_bytes()[2],
            words[2].to_le_bytes()[3],
            words[3].to_le_bytes()[0],
            words[3].to_le_bytes()[1],
            words[3].to_le_bytes()[2],
            words[3].to_le_bytes()[3],
        ];

        let start = byte_index * multiplicity * 16;
        for copy in 0..multiplicity {
            let offset = start + copy * 16;
            out[offset..offset + 16].copy_from_slice(&codeword_bytes);
        }
    }

    out
}

pub fn decode(codeword: &[u8], params: &Params) -> Vec<u8> {
    let multiplicity = params.n2.div_ceil(128);
    let mut message = vec![0u8; params.n1];

    for byte_index in 0..params.n1 {
        let mut expanded = [0i16; 128];

        for copy in 0..multiplicity {
            let start = (byte_index * multiplicity + copy) * 16;
            for part in 0..4 {
                let word = u32::from_le_bytes(
                    codeword[start + part * 4..start + part * 4 + 4]
                        .try_into()
                        .expect("reed-muller codeword word"),
                );
                for bit in 0..32 {
                    expanded[part * 32 + bit] += ((word >> bit) & 1) as i16;
                }
            }
        }

        let mut transform = [0i16; 128];
        hadamard(&mut expanded, &mut transform);
        expanded[0] -= (64 * multiplicity) as i16;
        message[byte_index] = find_peak(&expanded);
    }

    message
}
