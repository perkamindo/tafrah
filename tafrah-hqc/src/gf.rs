#[cfg(test)]
const GF_MUL_ORDER: usize = 255;

pub const GF_EXP: [u16; 258] = [
    1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117,
    234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181,
    119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
    95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253, 231, 211, 187,
    107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136,
    13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197,
    151, 51, 102, 204, 133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168,
    77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198,
    145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149,
    55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167,
    83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36, 72,
    144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125, 250, 233, 207,
    131, 27, 54, 108, 216, 173, 71, 142, 1, 2, 4,
];

pub const GF_LOG: [u16; 256] = [
    0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52, 141, 239,
    129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218,
    240, 18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166, 6,
    191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136, 54, 208, 148, 206, 143,
    150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58,
    40, 84, 250, 133, 186, 61, 202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243,
    167, 87, 7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165,
    153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207,
    205, 144, 135, 151, 178, 220, 252, 190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57,
    83, 71, 109, 65, 162, 31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246,
    108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90, 203, 89, 95, 176, 156,
    169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215, 79, 174, 213, 233, 230, 231, 173, 232, 116,
    214, 244, 234, 168, 80, 88, 175,
];

// Retained only as the differential test oracle for the constant-time GF port.
#[cfg(test)]
fn gf_mod(i: u16) -> u16 {
    let tmp = i.wrapping_sub(GF_MUL_ORDER as u16);
    let mask = -((tmp >> 15) as i16) as u16;
    tmp.wrapping_add(mask & GF_MUL_ORDER as u16)
}

// Constant-time GF(2^8) arithmetic ported from the PQClean HQC reference
// (`gf.c`). These constants describe the field GF(2^PARAM_M) with primitive
// polynomial PARAM_GF_POLY; they are identical across all HQC parameter sets.
const PARAM_M: usize = 8;
const PARAM_GF_POLY: u16 = 0x11D;
const PARAM_GF_POLY_WT: usize = 5;
const PARAM_GF_POLY_M2: usize = 4;

/// Number of trailing zero bits of `a`, computed in constant time
/// (branchless port of PQClean `trailing_zero_bits_count`).
fn trailing_zero_bits_count(a: u16) -> u16 {
    let mut tmp: u16 = 0;
    let mut mask: u16 = 0xFFFF;
    for i in 0..14u16 {
        let bit = (a >> i) & 1;
        tmp = tmp.wrapping_add(1u16.wrapping_sub(bit) & mask);
        mask &= 1u16.wrapping_sub(bit).wrapping_neg();
    }
    tmp
}

/// Reduces polynomial `x` (degree `deg_x`) modulo PARAM_GF_POLY, in constant
/// time (branchless port of PQClean `gf_reduce`).
fn gf_reduce(mut x: u64, deg_x: usize) -> u16 {
    let steps = (deg_x - (PARAM_M - 1)).div_ceil(PARAM_GF_POLY_M2);
    for _ in 0..steps {
        let mut mod_x = x >> PARAM_M;
        x &= (1u64 << PARAM_M) - 1;
        x ^= mod_x;

        let mut z1: u16 = 0;
        let mut rmdr: u16 = PARAM_GF_POLY ^ 1;
        for _ in 0..(PARAM_GF_POLY_WT - 2) {
            let z2 = trailing_zero_bits_count(rmdr);
            let dist = z2 - z1; // z2 >= z1 by construction; cannot underflow
            mod_x <<= dist;
            x ^= mod_x;
            rmdr ^= 1u16 << z2;
            z1 = z2;
        }
    }
    x as u16
}

/// Carryless (polynomial) multiplication of two GF(2^8) elements, returning the
/// 16-bit product. Branchless table-free port of PQClean `gf_carryless_mul`.
fn gf_carryless_mul(a: u8, b: u8) -> u16 {
    let u = {
        let u1 = (b & 0x7F) as u16;
        let u2 = u1 << 1;
        [0u16, u1, u2, u2 ^ u1]
    };

    // Constant-time selection of u[k] where k == sel_idx (k, sel_idx in 0..4).
    let select = |sel_idx: u32| -> u16 {
        let mut acc = 0u16;
        for k in 0..4u32 {
            let tmp = sel_idx.wrapping_sub(k);
            let is_eq = 1u32.wrapping_sub((tmp | tmp.wrapping_neg()) >> 31); // 1 if k == sel_idx
            acc ^= u[k as usize] & (0u32.wrapping_sub(is_eq)) as u16;
        }
        acc
    };

    let mut l: u16 = select((a & 3) as u32);
    let mut h: u16 = 0;

    let mut i = 2u16;
    while i < 8 {
        let g = select(((a >> i) & 3) as u32);
        l ^= g << i;
        h ^= g >> (8 - i);
        i += 2;
    }

    let mask: u16 = 0u16.wrapping_sub(((b >> 7) & 1) as u16);
    l ^= ((a as u16) << 7) & mask;
    h ^= ((a >> 1) as u16) & mask;

    (l & 0xFF) ^ ((h & 0xFF) << 8)
}

/// Multiplies two elements of GF(2^8) in constant time.
pub fn gf_mul(a: u16, b: u16) -> u16 {
    let product = gf_carryless_mul(a as u8, b as u8);
    gf_reduce(product as u64, 2 * (PARAM_M - 1))
}

/// Squares an element of GF(2^8) in constant time.
pub fn gf_square(a: u16) -> u16 {
    gf_mul(a, a)
}

/// Inverts an element of GF(2^8) in constant time using the addition chain
/// 1 2 3 4 7 11 15 30 60 120 127 254 (port of PQClean `gf_inverse`).
/// Returns 0 for input 0 (matching the previous table-based behaviour).
pub fn gf_inverse(a: u16) -> u16 {
    let mut inv = gf_square(a); // a^2
    let mut tmp1 = gf_mul(inv, a); // a^3
    inv = gf_square(inv); // a^4
    let tmp2 = gf_mul(inv, tmp1); // a^7
    tmp1 = gf_mul(inv, tmp2); // a^11
    inv = gf_mul(tmp1, inv); // a^15
    inv = gf_square(inv); // a^30
    inv = gf_square(inv); // a^60
    inv = gf_square(inv); // a^120
    inv = gf_mul(inv, tmp2); // a^127
    inv = gf_square(inv); // a^254
    inv
}

#[cfg(test)]
mod tests {
    use super::*;

    // The previous table-based implementations, kept here as the differential
    // oracle: the constant-time port must reproduce them bit-for-bit.
    fn table_mul(a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            return 0;
        }
        let index = gf_mod(GF_LOG[a as usize] + GF_LOG[b as usize]) as usize;
        GF_EXP[index]
    }
    fn table_inverse(a: u16) -> u16 {
        if a == 0 {
            return 0;
        }
        GF_EXP[GF_MUL_ORDER - GF_LOG[a as usize] as usize]
    }

    #[test]
    fn gf_mul_matches_table_exhaustively() {
        for a in 0..256u16 {
            for b in 0..256u16 {
                assert_eq!(gf_mul(a, b), table_mul(a, b), "gf_mul({a}, {b})");
            }
        }
    }

    #[test]
    fn gf_square_and_inverse_match_table_exhaustively() {
        for a in 0..256u16 {
            assert_eq!(gf_square(a), table_mul(a, a), "gf_square({a})");
            assert_eq!(gf_inverse(a), table_inverse(a), "gf_inverse({a})");
        }
    }
}
