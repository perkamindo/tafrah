extern crate alloc;

use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::mq::L2BOUND;

const Q: u32 = 12289;

pub(crate) fn hash_to_point_vartime(nonce: &[u8], msg: &[u8], logn: usize) -> Vec<u16> {
    let mut hasher = Shake256::default();
    hasher.update(nonce);
    hasher.update(msg);
    let mut reader = hasher.finalize_xof();

    let mut out = Vec::with_capacity(1usize << logn);
    let mut buf = [0u8; 2];
    while out.len() < (1usize << logn) {
        reader.read(&mut buf);
        let mut w = ((buf[0] as u32) << 8) | buf[1] as u32;
        if w < 61_445 {
            while w >= Q {
                w -= Q;
            }
            out.push(w as u16);
        }
    }
    out
}

pub(crate) fn is_short(s1: &[i16], s2: &[i16], logn: usize) -> bool {
    let mut s = 0u32;
    let mut ng = 0u32;

    for (&a, &b) in s1.iter().zip(s2.iter()) {
        let za = a as i32;
        s = s.wrapping_add((za * za) as u32);
        ng |= s;

        let zb = b as i32;
        s = s.wrapping_add((zb * zb) as u32);
        ng |= s;
    }

    s |= 0u32.wrapping_sub(ng >> 31);
    s <= L2BOUND[logn]
}

pub(crate) fn is_short_half(mut sqn: u32, s2: &[i16], logn: usize) -> bool {
    let mut ng = 0u32.wrapping_sub(sqn >> 31);

    for &value in s2 {
        let z = value as i32;
        sqn = sqn.wrapping_add((z as i64 * z as i64) as u32);
        ng |= sqn;
    }

    sqn |= 0u32.wrapping_sub(ng >> 31);
    sqn <= L2BOUND[logn]
}
