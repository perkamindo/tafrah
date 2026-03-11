extern crate alloc;

use alloc::vec::Vec;

const Q: u32 = 12289;

pub(crate) fn modq_encode(values: &[u16], logn: usize) -> Option<Vec<u8>> {
    let n = 1usize << logn;
    if values.len() != n {
        return None;
    }
    for &value in values {
        if value as u32 >= Q {
            return None;
        }
    }

    let out_len = ((n * 14) + 7) >> 3;
    let mut out = Vec::with_capacity(out_len);
    let mut acc = 0u32;
    let mut acc_len = 0usize;

    for &value in values {
        acc = (acc << 14) | value as u32;
        acc_len += 14;
        while acc_len >= 8 {
            acc_len -= 8;
            out.push((acc >> acc_len) as u8);
        }
    }

    if acc_len > 0 {
        out.push((acc << (8 - acc_len)) as u8);
    }

    Some(out)
}

pub(crate) fn modq_decode(out: &mut [u16], logn: usize, input: &[u8]) -> Option<usize> {
    let n = 1usize << logn;
    let in_len = ((n * 14) + 7) >> 3;
    if input.len() < in_len || out.len() != n {
        return None;
    }

    let mut acc = 0u32;
    let mut acc_len = 0usize;
    let mut u = 0usize;

    for &byte in input.iter().take(in_len) {
        acc = (acc << 8) | byte as u32;
        acc_len += 8;
        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            if w >= Q {
                return None;
            }
            out[u] = w as u16;
            u += 1;
        }
    }

    if u != n {
        return None;
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return None;
    }
    Some(in_len)
}

#[allow(dead_code)]
pub(crate) fn trim_i8_encode(values: &[i8], logn: usize, bits: u32) -> Option<Vec<u8>> {
    let n = 1usize << logn;
    if values.len() != n || bits == 0 || bits > 8 {
        return None;
    }

    let maxv = (1i32 << (bits - 1)) - 1;
    let minv = -maxv;
    for &value in values {
        let value = value as i32;
        if value < minv || value > maxv {
            return None;
        }
    }

    let out_len = ((n * bits as usize) + 7) >> 3;
    let mut out = Vec::with_capacity(out_len);
    let mask = (1u32 << bits) - 1;
    let mut acc = 0u32;
    let mut acc_len = 0usize;

    for &value in values {
        acc = (acc << bits) | ((value as u8 as u32) & mask);
        acc_len += bits as usize;
        while acc_len >= 8 {
            acc_len -= 8;
            out.push((acc >> acc_len) as u8);
        }
    }

    if acc_len > 0 {
        out.push((acc << (8 - acc_len)) as u8);
    }

    Some(out)
}

#[allow(dead_code)]
pub(crate) fn trim_i8_decode(
    out: &mut [i8],
    logn: usize,
    bits: u32,
    input: &[u8],
) -> Option<usize> {
    let n = 1usize << logn;
    let in_len = ((n * bits as usize) + 7) >> 3;
    if out.len() != n || bits == 0 || bits > 8 || input.len() < in_len {
        return None;
    }

    let mut u = 0usize;
    let mut acc = 0u32;
    let mut acc_len = 0usize;
    let mask1 = (1u32 << bits) - 1;
    let mask2 = 1u32 << (bits - 1);

    for &byte in input.iter().take(in_len) {
        acc = (acc << 8) | byte as u32;
        acc_len += 8;
        while acc_len >= bits as usize && u < n {
            acc_len -= bits as usize;
            let mut w = (acc >> acc_len) & mask1;
            if (w & mask2) != 0 {
                w |= !mask1;
            }
            let value = w as i32;
            if value == -(mask2 as i32) {
                return None;
            }
            out[u] = value as i8;
            u += 1;
        }
    }

    if u != n {
        return None;
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return None;
    }
    Some(in_len)
}

#[allow(dead_code)]
pub(crate) fn comp_encode(values: &[i16], logn: usize) -> Option<Vec<u8>> {
    let n = 1usize << logn;
    if values.len() != n {
        return None;
    }
    for &value in values {
        if !(-2047..=2047).contains(&value) {
            return None;
        }
    }

    let mut acc = 0u32;
    let mut acc_len = 0usize;
    let mut out = Vec::new();

    for &value in values {
        let mut magnitude = value.unsigned_abs();
        acc <<= 1;
        if value < 0 {
            acc |= 1;
        }

        acc = (acc << 7) | ((magnitude & 127) as u32);
        magnitude >>= 7;
        acc_len += 8;

        acc <<= (magnitude + 1) as usize;
        acc |= 1;
        acc_len += magnitude as usize + 1;

        while acc_len >= 8 {
            acc_len -= 8;
            out.push((acc >> acc_len) as u8);
        }
    }

    if acc_len > 0 {
        out.push((acc << (8 - acc_len)) as u8);
    }

    Some(out)
}

pub(crate) fn comp_decode(out: &mut [i16], logn: usize, input: &[u8]) -> Option<usize> {
    let n = 1usize << logn;
    if out.len() != n {
        return None;
    }

    let mut acc = 0u32;
    let mut acc_len = 0usize;
    let mut v = 0usize;

    for slot in out.iter_mut() {
        if v >= input.len() {
            return None;
        }
        acc = (acc << 8) | input[v] as u32;
        v += 1;
        let b = acc >> acc_len;
        let sign = b & 128;
        let mut magnitude = b & 127;

        loop {
            if acc_len == 0 {
                if v >= input.len() {
                    return None;
                }
                acc = (acc << 8) | input[v] as u32;
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            magnitude += 128;
            if magnitude > 2047 {
                return None;
            }
        }

        if sign != 0 && magnitude == 0 {
            return None;
        }

        *slot = if sign != 0 {
            -(magnitude as i16)
        } else {
            magnitude as i16
        };
    }

    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return None;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::{
        comp_decode, comp_encode, modq_decode, modq_encode, trim_i8_decode, trim_i8_encode,
    };

    #[test]
    fn test_trim_i8_roundtrip() {
        let values = [-3i8, 0, 1, 2, -1, 3, 4, -4];
        let encoded = trim_i8_encode(&values, 3, 4).expect("encode");
        let mut decoded = [0i8; 8];
        let used = trim_i8_decode(&mut decoded, 3, 4, &encoded).expect("decode");
        assert_eq!(used, encoded.len());
        assert_eq!(decoded, values);
    }

    #[test]
    fn test_comp_roundtrip() {
        let values = [-2047i16, -5, 0, 17, 2047, 64, -63, 1];
        let encoded = comp_encode(&values, 3).expect("encode");
        let mut decoded = [0i16; 8];
        let used = comp_decode(&mut decoded, 3, &encoded).expect("decode");
        assert_eq!(used, encoded.len());
        assert_eq!(decoded, values);
    }

    #[test]
    fn test_modq_roundtrip() {
        let values = [0u16, 1, 12288, 511, 8192, 17, 999, 2048];
        let encoded = modq_encode(&values, 3).expect("encode");
        let mut decoded = [0u16; 8];
        let used = modq_decode(&mut decoded, 3, &encoded).expect("decode");
        assert_eq!(used, encoded.len());
        assert_eq!(decoded, values);
    }
}
