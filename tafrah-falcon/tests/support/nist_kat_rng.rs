use rand_core::{CryptoRng, Error as RandError, RngCore};

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
    0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
    0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
    0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
    0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
    0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
    0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
    0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
    0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
    0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
    0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
    0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1,
    0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
    0x16,
];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1B)
}

fn mix_column(column: &mut [u8; 4]) {
    let t = column[0] ^ column[1] ^ column[2] ^ column[3];
    let u = column[0];
    column[0] ^= t ^ xtime(column[0] ^ column[1]);
    column[1] ^= t ^ xtime(column[1] ^ column[2]);
    column[2] ^= t ^ xtime(column[2] ^ column[3]);
    column[3] ^= t ^ xtime(column[3] ^ u);
}

fn sub_word(mut word: [u8; 4]) -> [u8; 4] {
    for byte in &mut word {
        *byte = SBOX[*byte as usize];
    }
    word
}

fn expand_key(key: &[u8; 32]) -> [u8; 240] {
    let mut expanded = [0u8; 240];
    expanded[..32].copy_from_slice(key);

    let mut bytes_generated = 32usize;
    let mut rcon_index = 0usize;
    let mut temp = [0u8; 4];

    while bytes_generated < expanded.len() {
        temp.copy_from_slice(&expanded[bytes_generated - 4..bytes_generated]);
        if bytes_generated % 32 == 0 {
            temp.rotate_left(1);
            temp = sub_word(temp);
            temp[0] ^= RCON[rcon_index];
            rcon_index += 1;
        } else if bytes_generated % 32 == 16 {
            temp = sub_word(temp);
        }

        for value in temp {
            expanded[bytes_generated] = expanded[bytes_generated - 32] ^ value;
            bytes_generated += 1;
        }
    }

    expanded
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
    for (slot, key_byte) in state.iter_mut().zip(round_key.iter()) {
        *slot ^= *key_byte;
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let original = *state;
    state[0] = original[0];
    state[1] = original[5];
    state[2] = original[10];
    state[3] = original[15];
    state[4] = original[4];
    state[5] = original[9];
    state[6] = original[14];
    state[7] = original[3];
    state[8] = original[8];
    state[9] = original[13];
    state[10] = original[2];
    state[11] = original[7];
    state[12] = original[12];
    state[13] = original[1];
    state[14] = original[6];
    state[15] = original[11];
}

fn mix_columns(state: &mut [u8; 16]) {
    for column in state.chunks_exact_mut(4) {
        let mut tmp = [column[0], column[1], column[2], column[3]];
        mix_column(&mut tmp);
        column.copy_from_slice(&tmp);
    }
}

fn aes256_encrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    let expanded = expand_key(key);
    add_round_key(block, &expanded[..16]);

    for round in 1..14 {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &expanded[round * 16..(round + 1) * 16]);
    }

    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &expanded[224..240]);
}

pub struct NistKatDrbg {
    key: [u8; 32],
    v: [u8; 16],
    reseed_counter: u32,
}

impl NistKatDrbg {
    pub fn new(seed: [u8; 48]) -> Self {
        let mut drbg = Self {
            key: [0u8; 32],
            v: [0u8; 16],
            reseed_counter: 0,
        };
        drbg.update(Some(&seed));
        drbg.reseed_counter = 1;
        drbg
    }

    fn increment_v(&mut self) {
        for byte in self.v.iter_mut().rev() {
            if *byte == 0xFF {
                *byte = 0;
            } else {
                *byte = byte.wrapping_add(1);
                break;
            }
        }
    }

    fn update(&mut self, provided_data: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];

        for chunk in temp.chunks_exact_mut(16) {
            self.increment_v();
            let mut block = self.v;
            aes256_encrypt_block(&self.key, &mut block);
            chunk.copy_from_slice(&block);
        }

        if let Some(data) = provided_data {
            for (slot, input) in temp.iter_mut().zip(data.iter()) {
                *slot ^= *input;
            }
        }

        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..48]);
    }

    fn randombytes(&mut self, out: &mut [u8]) {
        let mut offset = 0usize;
        while offset < out.len() {
            self.increment_v();
            let mut block = self.v;
            aes256_encrypt_block(&self.key, &mut block);
            let take = core::cmp::min(16, out.len() - offset);
            out[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }
        self.update(None);
        self.reseed_counter = self.reseed_counter.wrapping_add(1);
    }
}

impl RngCore for NistKatDrbg {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.randombytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.randombytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.randombytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.randombytes(dest);
        Ok(())
    }
}

impl CryptoRng for NistKatDrbg {}
