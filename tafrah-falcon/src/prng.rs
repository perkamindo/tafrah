use core::convert::TryInto;

use sha3::digest::XofReader;

pub(crate) struct Prng {
    buf: [u8; 512],
    ptr: usize,
    state: [u32; 12],
    counter: u64,
}

impl Prng {
    pub(crate) fn new() -> Self {
        Self {
            buf: [0u8; 512],
            ptr: 512,
            state: [0u32; 12],
            counter: 0,
        }
    }

    pub(crate) fn init<R: XofReader>(&mut self, src: &mut R) {
        let mut tmp = [0u8; 56];
        src.read(&mut tmp);

        for (index, slot) in self.state.iter_mut().enumerate() {
            let start = index << 2;
            *slot = u32::from_le_bytes(tmp[start..start + 4].try_into().expect("word"));
        }

        let tl = u32::from_le_bytes(tmp[48..52].try_into().expect("counter low"));
        let th = u32::from_le_bytes(tmp[52..56].try_into().expect("counter high"));
        self.counter = tl as u64 + ((th as u64) << 32);
        self.refill();
    }

    fn refill(&mut self) {
        const CW: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

        fn qround(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
            state[a] = state[a].wrapping_add(state[b]);
            state[d] ^= state[a];
            state[d] = state[d].rotate_left(16);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] ^= state[c];
            state[b] = state[b].rotate_left(12);
            state[a] = state[a].wrapping_add(state[b]);
            state[d] ^= state[a];
            state[d] = state[d].rotate_left(8);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] ^= state[c];
            state[b] = state[b].rotate_left(7);
        }

        let mut cc = self.counter;
        for u in 0..8usize {
            let mut state = [0u32; 16];
            state[..4].copy_from_slice(&CW);
            state[4..16].copy_from_slice(&self.state);
            state[14] ^= cc as u32;
            state[15] ^= (cc >> 32) as u32;

            for _ in 0..10 {
                qround(&mut state, 0, 4, 8, 12);
                qround(&mut state, 1, 5, 9, 13);
                qround(&mut state, 2, 6, 10, 14);
                qround(&mut state, 3, 7, 11, 15);
                qround(&mut state, 0, 5, 10, 15);
                qround(&mut state, 1, 6, 11, 12);
                qround(&mut state, 2, 7, 8, 13);
                qround(&mut state, 3, 4, 9, 14);
            }

            for v in 0..4 {
                state[v] = state[v].wrapping_add(CW[v]);
            }
            for v in 4..14 {
                state[v] = state[v].wrapping_add(self.state[v - 4]);
            }
            state[14] = state[14].wrapping_add(self.state[10] ^ (cc as u32));
            state[15] = state[15].wrapping_add(self.state[11] ^ ((cc >> 32) as u32));
            cc = cc.wrapping_add(1);

            for (v, word) in state.iter().enumerate() {
                let bytes = word.to_le_bytes();
                let base = (u << 2) + (v << 5);
                self.buf[base] = bytes[0];
                self.buf[base + 1] = bytes[1];
                self.buf[base + 2] = bytes[2];
                self.buf[base + 3] = bytes[3];
            }
        }

        self.counter = cc;
        self.ptr = 0;
    }

    pub(crate) fn get_u64(&mut self) -> u64 {
        let mut u = self.ptr;
        if u >= self.buf.len() - 9 {
            self.refill();
            u = 0;
        }
        self.ptr = u + 8;

        u64::from_le_bytes(self.buf[u..u + 8].try_into().expect("u64"))
    }

    pub(crate) fn get_u8(&mut self) -> u8 {
        let value = self.buf[self.ptr];
        self.ptr += 1;
        if self.ptr == self.buf.len() {
            self.refill();
        }
        value
    }
}
