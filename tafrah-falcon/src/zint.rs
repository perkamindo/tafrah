use crate::modp::{
    modp_add, modp_montymul, modp_ninv31, modp_r2, modp_sub, SmallPrime,
};

pub(crate) fn zint_sub(a: &mut [u32], b: &[u32], ctl: u32) -> u32 {
    debug_assert_eq!(a.len(), b.len());
    let mut cc = 0u32;
    let m = 0u32.wrapping_sub(ctl);
    for u in 0..a.len() {
        let aw = a[u];
        let w = aw.wrapping_sub(b[u]).wrapping_sub(cc);
        cc = w >> 31;
        a[u] = aw ^ (((w & 0x7FFF_FFFF) ^ aw) & m);
    }
    cc
}

pub(crate) fn zint_mul_small(m: &mut [u32], x: u32) -> u32 {
    let mut cc = 0u32;
    for word in m.iter_mut() {
        let z = (*word as u64) * (x as u64) + cc as u64;
        *word = z as u32 & 0x7FFF_FFFF;
        cc = (z >> 31) as u32;
    }
    cc
}

pub(crate) fn zint_mod_small_unsigned(
    d: &[u32],
    p: u32,
    p0i: u32,
    r2: u32,
) -> u32 {
    let mut x = 0u32;
    for &word in d.iter().rev() {
        x = modp_montymul(x, r2, p, p0i);
        let mut w = word.wrapping_sub(p);
        w = w.wrapping_add(p & 0u32.wrapping_sub(w >> 31));
        x = modp_add(x, w, p);
    }
    x
}

pub(crate) fn zint_mod_small_signed(
    d: &[u32],
    p: u32,
    p0i: u32,
    r2: u32,
    rx: u32,
) -> u32 {
    if d.is_empty() {
        return 0;
    }
    let z = zint_mod_small_unsigned(d, p, p0i, r2);
    modp_sub(z, rx & 0u32.wrapping_sub(d[d.len() - 1] >> 30), p)
}

pub(crate) fn zint_add_mul_small(x: &mut [u32], y: &[u32], s: u32) {
    debug_assert_eq!(x.len(), y.len() + 1);
    let mut cc = 0u32;
    for u in 0..y.len() {
        let z = (y[u] as u64) * (s as u64) + (x[u] as u64) + (cc as u64);
        x[u] = z as u32 & 0x7FFF_FFFF;
        cc = (z >> 31) as u32;
    }
    x[y.len()] = cc;
}

pub(crate) fn zint_norm_zero(x: &mut [u32], p: &[u32]) {
    debug_assert_eq!(x.len(), p.len());
    let len = x.len();
    let mut r = 0u32;
    let mut bb = 0u32;
    for u in (0..len).rev() {
        let wx = x[u];
        let wp = (p[u] >> 1) | (bb << 30);
        bb = p[u] & 1;
        let cc = wp.wrapping_sub(wx);
        let cc = ((0u32.wrapping_sub(cc)) >> 31) | 0u32.wrapping_sub(cc >> 31);
        r |= cc & ((r & 1).wrapping_sub(1));
    }
    zint_sub(x, p, r >> 31);
}

pub(crate) fn zint_rebuild_crt(
    xx: &mut [u32],
    xlen: usize,
    xstride: usize,
    num: usize,
    primes: &[SmallPrime],
    normalize_signed: bool,
    tmp: &mut [u32],
) {
    debug_assert!(tmp.len() >= xlen);
    tmp[0] = primes[0].p;
    for u in 1..xlen {
        let p = primes[u].p;
        let s = primes[u].s;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        for v in 0..num {
            let base = v * xstride;
            let xp = xx[base + u];
            let xq = zint_mod_small_unsigned(&xx[base..base + u], p, p0i, r2);
            let xr = modp_montymul(s, modp_sub(xp, xq, p), p, p0i);
            zint_add_mul_small(&mut xx[base..base + u + 1], &tmp[..u], xr);
        }
        tmp[u] = zint_mul_small(&mut tmp[..u], p);
    }

    if normalize_signed {
        for v in 0..num {
            let base = v * xstride;
            zint_norm_zero(&mut xx[base..base + xlen], &tmp[..xlen]);
        }
    }
}

pub(crate) fn zint_negate(a: &mut [u32], ctl: u32) {
    let mut cc = ctl;
    let m = 0u32.wrapping_sub(ctl) >> 1;
    for word in a.iter_mut() {
        let aw = (*word ^ m).wrapping_add(cc);
        *word = aw & 0x7FFF_FFFF;
        cc = aw >> 31;
    }
}

pub(crate) fn zint_co_reduce(
    a: &mut [u32],
    b: &mut [u32],
    xa: i64,
    xb: i64,
    ya: i64,
    yb: i64,
) -> u32 {
    debug_assert_eq!(a.len(), b.len());
    let len = a.len();

    let mut cca = 0i64;
    let mut ccb = 0i64;
    for u in 0..len {
        let wa = a[u];
        let wb = b[u];
        let za = (wa as u64)
            .wrapping_mul(xa as u64)
            .wrapping_add((wb as u64).wrapping_mul(xb as u64))
            .wrapping_add(cca as u64);
        let zb = (wa as u64)
            .wrapping_mul(ya as u64)
            .wrapping_add((wb as u64).wrapping_mul(yb as u64))
            .wrapping_add(ccb as u64);
        if u > 0 {
            a[u - 1] = (za as u32) & 0x7FFF_FFFF;
            b[u - 1] = (zb as u32) & 0x7FFF_FFFF;
        }
        cca = (za as i64) >> 31;
        ccb = (zb as i64) >> 31;
    }
    a[len - 1] = cca as u32;
    b[len - 1] = ccb as u32;

    let nega = ((cca as u64) >> 63) as u32;
    let negb = ((ccb as u64) >> 63) as u32;
    zint_negate(a, nega);
    zint_negate(b, negb);
    nega | (negb << 1)
}

pub(crate) fn zint_finish_mod(a: &mut [u32], m: &[u32], neg: u32) {
    debug_assert_eq!(a.len(), m.len());
    let len = a.len();

    let mut cc = 0u32;
    for u in 0..len {
        cc = (a[u].wrapping_sub(m[u]).wrapping_sub(cc)) >> 31;
    }

    let xm = 0u32.wrapping_sub(neg) >> 1;
    let ym = 0u32.wrapping_sub(neg | (1u32.wrapping_sub(cc)));
    cc = neg;
    for u in 0..len {
        let aw = a[u];
        let mw = (m[u] ^ xm) & ym;
        let nw = aw.wrapping_sub(mw).wrapping_sub(cc);
        a[u] = nw & 0x7FFF_FFFF;
        cc = nw >> 31;
    }
}

pub(crate) fn zint_co_reduce_mod(
    a: &mut [u32],
    b: &mut [u32],
    m: &[u32],
    m0i: u32,
    xa: i64,
    xb: i64,
    ya: i64,
    yb: i64,
) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), m.len());
    let len = a.len();

    let mut cca = 0i64;
    let mut ccb = 0i64;
    let fa = ((a[0]
        .wrapping_mul(xa as u32)
        .wrapping_add(b[0].wrapping_mul(xb as u32)))
        .wrapping_mul(m0i))
        & 0x7FFF_FFFF;
    let fb = ((a[0]
        .wrapping_mul(ya as u32)
        .wrapping_add(b[0].wrapping_mul(yb as u32)))
        .wrapping_mul(m0i))
        & 0x7FFF_FFFF;

    for u in 0..len {
        let wa = a[u];
        let wb = b[u];
        let za = (wa as u64)
            .wrapping_mul(xa as u64)
            .wrapping_add((wb as u64).wrapping_mul(xb as u64))
            .wrapping_add((m[u] as u64).wrapping_mul(fa as u64))
            .wrapping_add(cca as u64);
        let zb = (wa as u64)
            .wrapping_mul(ya as u64)
            .wrapping_add((wb as u64).wrapping_mul(yb as u64))
            .wrapping_add((m[u] as u64).wrapping_mul(fb as u64))
            .wrapping_add(ccb as u64);
        if u > 0 {
            a[u - 1] = (za as u32) & 0x7FFF_FFFF;
            b[u - 1] = (zb as u32) & 0x7FFF_FFFF;
        }
        cca = (za as i64) >> 31;
        ccb = (zb as i64) >> 31;
    }
    a[len - 1] = cca as u32;
    b[len - 1] = ccb as u32;

    zint_finish_mod(a, m, ((cca as u64) >> 63) as u32);
    zint_finish_mod(b, m, ((ccb as u64) >> 63) as u32);
}

pub(crate) fn zint_bezout(
    u: &mut [u32],
    v: &mut [u32],
    x: &[u32],
    y: &[u32],
    tmp: &mut [u32],
) -> bool {
    let len = x.len();
    debug_assert_eq!(v.len(), len);
    debug_assert_eq!(y.len(), len);
    debug_assert!(tmp.len() >= len * 4);

    if len == 0 {
        return false;
    }

    let x0i = modp_ninv31(x[0]);
    let y0i = modp_ninv31(y[0]);

    let (u1, rest) = tmp.split_at_mut(len);
    let (v1, rest) = rest.split_at_mut(len);
    let (a, b) = rest.split_at_mut(len);

    a.copy_from_slice(x);
    b.copy_from_slice(y);
    u[0] = 1;
    for word in &mut u[1..] {
        *word = 0;
    }
    v.fill(0);
    u1.copy_from_slice(y);
    v1.copy_from_slice(x);
    v1[0] = v1[0].wrapping_sub(1);

    let mut num = 62u32.wrapping_mul(len as u32).wrapping_add(30);
    while num >= 30 {
        let mut c0 = u32::MAX;
        let mut c1 = u32::MAX;
        let mut a0 = 0u32;
        let mut a1 = 0u32;
        let mut b0 = 0u32;
        let mut b1 = 0u32;
        let mut j = len;
        while j > 0 {
            j -= 1;
            let aw = a[j];
            let bw = b[j];
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw).wrapping_add(0x7FFF_FFFF)) >> 31).wrapping_sub(1);
        }

        a1 |= a0 & c1;
        a0 &= !c1;
        b1 |= b0 & c1;
        b0 &= !c1;
        let mut a_hi = ((a0 as u64) << 31).wrapping_add(a1 as u64);
        let mut b_hi = ((b0 as u64) << 31).wrapping_add(b1 as u64);
        let mut a_lo = a[0];
        let mut b_lo = b[0];

        let mut pa = 1i64;
        let mut pb = 0i64;
        let mut qa = 0i64;
        let mut qb = 1i64;
        for i in 0..31 {
            let rz = b_hi.wrapping_sub(a_hi);
            let rt = ((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63) as u32;

            let oa = (a_lo >> i) & 1;
            let ob = (b_lo >> i) & 1;
            let c_ab = oa & ob & rt;
            let c_ba = oa & ob & !rt;
            let c_a = c_ab | (oa ^ 1);

            let mask_ab_u32 = 0u32.wrapping_sub(c_ab);
            let mask_ba_u32 = 0u32.wrapping_sub(c_ba);
            let mask_ab_u64 = 0u64.wrapping_sub(c_ab as u64);
            let mask_ba_u64 = 0u64.wrapping_sub(c_ba as u64);
            let mask_ab_i64 = 0i64.wrapping_sub(c_ab as i64);
            let mask_ba_i64 = 0i64.wrapping_sub(c_ba as i64);

            a_lo = a_lo.wrapping_sub(b_lo & mask_ab_u32);
            a_hi = a_hi.wrapping_sub(b_hi & mask_ab_u64);
            pa = pa.wrapping_sub(qa & mask_ab_i64);
            pb = pb.wrapping_sub(qb & mask_ab_i64);

            b_lo = b_lo.wrapping_sub(a_lo & mask_ba_u32);
            b_hi = b_hi.wrapping_sub(a_hi & mask_ba_u64);
            qa = qa.wrapping_sub(pa & mask_ba_i64);
            qb = qb.wrapping_sub(pb & mask_ba_i64);

            a_lo = a_lo.wrapping_add(a_lo & c_a.wrapping_sub(1));
            pa = pa.wrapping_add(pa & ((c_a as i64).wrapping_sub(1)));
            pb = pb.wrapping_add(pb & ((c_a as i64).wrapping_sub(1)));
            a_hi ^= (a_hi ^ (a_hi >> 1)) & (0u64.wrapping_sub(c_a as u64));

            b_lo = b_lo.wrapping_add(b_lo & 0u32.wrapping_sub(c_a));
            qa = qa.wrapping_add(qa & 0i64.wrapping_sub(c_a as i64));
            qb = qb.wrapping_add(qb & 0i64.wrapping_sub(c_a as i64));
            b_hi ^= (b_hi ^ (b_hi >> 1)) & ((c_a as u64).wrapping_sub(1));
        }

        let r = zint_co_reduce(a, b, pa, pb, qa, qb);
        pa = pa.wrapping_sub((pa.wrapping_add(pa)) & 0i64.wrapping_sub((r & 1) as i64));
        pb = pb.wrapping_sub((pb.wrapping_add(pb)) & 0i64.wrapping_sub((r & 1) as i64));
        qa = qa.wrapping_sub((qa.wrapping_add(qa)) & 0i64.wrapping_sub((r >> 1) as i64));
        qb = qb.wrapping_sub((qb.wrapping_add(qb)) & 0i64.wrapping_sub((r >> 1) as i64));
        zint_co_reduce_mod(u, u1, y, y0i, pa, pb, qa, qb);
        zint_co_reduce_mod(v, v1, x, x0i, pa, pb, qa, qb);

        num -= 30;
    }

    let mut rc = a[0] ^ 1;
    for &word in &a[1..] {
        rc |= word;
    }
    (((1u32.wrapping_sub((rc | rc.wrapping_neg()) >> 31)) & x[0] & y[0]) & 1) != 0
}

pub(crate) fn zint_add_scaled_mul_small(
    x: &mut [u32],
    y: &[u32],
    k: i32,
    sch: u32,
    scl: u32,
) {
    if y.is_empty() {
        return;
    }

    let xlen = x.len();
    let ylen = y.len();
    let ysign = 0u32.wrapping_sub(y[ylen - 1] >> 30) >> 1;
    let mut tw = 0u32;
    let mut cc = 0i32;
    for u in sch as usize..xlen {
        let v = u - sch as usize;
        let wy = if v < ylen { y[v] } else { ysign };
        let wys = ((wy << scl) & 0x7FFF_FFFF) | tw;
        tw = wy >> (31 - scl);

        let z = ((wys as i64) * (k as i64) + (x[u] as i64) + (cc as i64)) as u64;
        x[u] = (z as u32) & 0x7FFF_FFFF;
        cc = i32::from_ne_bytes(((z >> 31) as u32).to_ne_bytes());
    }
}

pub(crate) fn zint_sub_scaled(x: &mut [u32], y: &[u32], sch: u32, scl: u32) {
    if y.is_empty() {
        return;
    }

    let xlen = x.len();
    let ylen = y.len();
    let ysign = 0u32.wrapping_sub(y[ylen - 1] >> 30) >> 1;
    let mut tw = 0u32;
    let mut cc = 0u32;
    for u in sch as usize..xlen {
        let v = u - sch as usize;
        let wy = if v < ylen { y[v] } else { ysign };
        let wys = ((wy << scl) & 0x7FFF_FFFF) | tw;
        tw = wy >> (31 - scl);

        let w = x[u].wrapping_sub(wys).wrapping_sub(cc);
        x[u] = w & 0x7FFF_FFFF;
        cc = w >> 31;
    }
}

pub(crate) fn zint_one_to_plain(x: &[u32]) -> i32 {
    debug_assert!(!x.is_empty());
    let mut w = x[0];
    w |= (w & 0x4000_0000) << 1;
    i32::from_ne_bytes(w.to_ne_bytes())
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    use super::{
        zint_add_mul_small, zint_add_scaled_mul_small, zint_bezout, zint_co_reduce,
        zint_co_reduce_mod, zint_finish_mod, zint_mod_small_signed, zint_mod_small_unsigned,
        zint_mul_small, zint_negate, zint_norm_zero, zint_one_to_plain, zint_rebuild_crt,
        zint_sub, zint_sub_scaled,
    };
    use crate::modp::{modp_ninv31, modp_r2, modp_rx, SmallPrime};

    const P0: u32 = 2_147_473_409;
    const P1: u32 = 2_147_389_441;

    fn encode_u128(mut x: u128, len: usize) -> Vec<u32> {
        let mut out = vec![0u32; len];
        for slot in out.iter_mut() {
            *slot = (x & 0x7FFF_FFFF) as u32;
            x >>= 31;
        }
        out
    }

    fn decode_u128(words: &[u32]) -> u128 {
        let mut x = 0u128;
        for &word in words.iter().rev() {
            x <<= 31;
            x |= word as u128;
        }
        x
    }

    fn encode_signed_i128(x: i128, len: usize) -> Vec<u32> {
        let bits = 31 * len;
        let modulus = 1i128 << bits;
        let mut y = x;
        if y < 0 {
            y += modulus;
        }
        let mut out = vec![0u32; len];
        let mut v = y as u128;
        for slot in out.iter_mut() {
            *slot = (v & 0x7FFF_FFFF) as u32;
            v >>= 31;
        }
        out
    }

    fn decode_signed_i128(words: &[u32]) -> i128 {
        let bits = 31 * words.len();
        let unsigned = decode_u128(words);
        if bits == 0 {
            return 0;
        }
        if ((unsigned >> (bits - 1)) & 1) != 0 {
            unsigned as i128 - (1i128 << bits)
        } else {
            unsigned as i128
        }
    }

    fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
        while b != 0 {
            let r = a % b;
            a = b;
            b = r;
        }
        a
    }

    #[test]
    fn test_zint_sub_and_mul_small() {
        let mut a = vec![5u32, 7u32];
        let b = vec![2u32, 3u32];
        let cc = zint_sub(&mut a, &b, 1);
        assert_eq!(cc, 0);
        assert_eq!(a, vec![3, 4]);

        let mut c = vec![0x7FFF_FFFF, 1];
        let carry = zint_mul_small(&mut c, 3);
        assert_eq!(carry, 0);
        assert_eq!(decode_u128(&c), ((1u128 << 31) + 0x7FFF_FFFFu128) * 3);
    }

    #[test]
    fn test_zint_mod_small_unsigned_and_signed() {
        let value = encode_u128(123_456_789_012_345u128, 3);
        let p0i = modp_ninv31(P0);
        let r2 = modp_r2(P0, p0i);
        let rx = modp_rx(value.len() as u32, P0, p0i, r2);
        let got = zint_mod_small_unsigned(&value, P0, p0i, r2);
        assert_eq!(got as u128, 123_456_789_012_345u128 % P0 as u128);

        let mut neg = value.clone();
        neg[2] |= 0x4000_0000;
        let got_signed = zint_mod_small_signed(&neg, P0, p0i, r2, rx);
        assert!(got_signed < P0);
    }

    #[test]
    fn test_zint_add_mul_small_and_norm_zero() {
        let y = vec![7u32, 3u32];
        let mut x = vec![5u32, 2u32, 0u32];
        zint_add_mul_small(&mut x, &y, 9);
        assert_eq!(decode_u128(&x), decode_u128(&[5, 2]) + decode_u128(&[7, 3]) * 9);

        let mut v = vec![9u32, 0u32];
        let p = vec![11u32, 0u32];
        zint_norm_zero(&mut v, &p);
        assert_eq!(v[0], 0x7FFF_FFFE);
    }

    #[test]
    fn test_zint_rebuild_crt_two_primes() {
        let value = 1_234_567_890_123u128;
        let residues = vec![(value % P0 as u128) as u32, (value % P1 as u128) as u32];
        let primes = [
            SmallPrime { p: P0, g: 383_167_813, s: 10_239 },
            SmallPrime { p: P1, g: 211_808_905, s: 471_403_745 },
        ];
        let mut xx = residues.clone();
        let mut tmp = vec![0u32; 2];
        zint_rebuild_crt(&mut xx, 2, 2, 1, &primes, false, &mut tmp);
        assert_eq!(decode_u128(&xx), value);
    }

    #[test]
    fn test_zint_negate_and_finish_mod() {
        let mut x = encode_signed_i128(37, 2);
        zint_negate(&mut x, 1);
        assert_eq!(decode_signed_i128(&x), -37);
        zint_negate(&mut x, 1);
        assert_eq!(decode_signed_i128(&x), 37);

        let mut pos = vec![20u32];
        let modulus = vec![13u32];
        zint_finish_mod(&mut pos, &modulus, 0);
        assert_eq!(pos, vec![7u32]);

        let mut neg = vec![0x7FFF_FFFBu32];
        zint_finish_mod(&mut neg, &modulus, 1);
        assert_eq!(neg, vec![8u32]);
    }

    #[test]
    fn test_zint_co_reduce_identity_and_mod() {
        let mut a = vec![0u32, 7u32];
        let mut b = vec![0u32, 11u32];
        let r = zint_co_reduce(&mut a, &mut b, 1, 0, 0, 1);
        assert_eq!(r, 0);
        assert_eq!(decode_signed_i128(&a), 7);
        assert_eq!(decode_signed_i128(&b), 11);

        let modulus = vec![13u32, 0u32];
        let m0i = modp_ninv31(modulus[0]);
        let mut a = vec![0u32, 7u32];
        let mut b = vec![0u32, 11u32];
        zint_co_reduce_mod(&mut a, &mut b, &modulus, m0i, 1, 0, 0, 1);
        assert_eq!(decode_u128(&a), 7);
        assert_eq!(decode_u128(&b), 11);
    }

    #[test]
    fn test_zint_bezout_small_odd_inputs() {
        let x = encode_u128(11, 1);
        let y = encode_u128(9, 1);
        let mut u = vec![0u32; 1];
        let mut v = vec![0u32; 1];
        let mut tmp = vec![0u32; 4];
        assert!(zint_bezout(&mut u, &mut v, &x, &y, &mut tmp));
        let ux = decode_u128(&u) as i128;
        let vx = decode_u128(&v) as i128;
        assert!((0..=9).contains(&(ux as i32)));
        assert!((0..=11).contains(&(vx as i32)));
        assert_eq!(11i128 * ux - 9i128 * vx, 1);
    }

    #[test]
    fn test_zint_bezout_rejects_non_coprime() {
        let x = encode_u128(21, 1);
        let y = encode_u128(9, 1);
        let mut u = vec![0u32; 1];
        let mut v = vec![0u32; 1];
        let mut tmp = vec![0u32; 4];
        assert!(!zint_bezout(&mut u, &mut v, &x, &y, &mut tmp));
    }

    #[test]
    fn test_zint_bezout_random_multiword_u128_cases() {
        let mut rng = StdRng::from_seed([0x5Au8; 32]);

        for len in [2usize] {
            let bits = 31 * len;
            let mask = if bits == 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            };

            for _ in 0..200 {
                let mut xb = [0u8; 16];
                let mut yb = [0u8; 16];
                rng.fill_bytes(&mut xb);
                rng.fill_bytes(&mut yb);
                let mut x = u128::from_le_bytes(xb) & mask;
                let mut y = u128::from_le_bytes(yb) & mask;
                x |= 1;
                y |= 1;
                x |= 1u128 << (bits - 1);
                y |= 1u128 << (bits - 2);
                if gcd_u128(x, y) != 1 {
                    continue;
                }

                let x_words = encode_u128(x, len);
                let y_words = encode_u128(y, len);
                let mut u = vec![0u32; len];
                let mut v = vec![0u32; len];
                let mut tmp = vec![0u32; len * 4];
                assert!(
                    zint_bezout(&mut u, &mut v, &x_words, &y_words, &mut tmp),
                    "bezout failed for len={len}, x={x}, y={y}"
                );

                let ux = decode_u128(&u);
                let vx = decode_u128(&v);
                assert!(ux <= y, "u out of range for len={len}");
                assert!(vx <= x, "v out of range for len={len}");
                assert_eq!(x * ux - y * vx, 1, "identity mismatch for len={len}");
            }
        }
    }

    #[test]
    fn test_zint_scaled_helpers_match_small_signed_arithmetic() {
        let y = encode_signed_i128(-37, 2);
        let mut x = encode_signed_i128(91, 4);
        zint_add_scaled_mul_small(&mut x, &y, -5, 1, 3);
        let expected = 91i128 + (-37i128) * (-5i128) * (1i128 << 34);
        assert_eq!(decode_signed_i128(&x), expected);

        let mut z = x.clone();
        let scaled_y = (-37i128) * (1i128 << 34);
        zint_sub_scaled(&mut z, &y, 1, 3);
        assert_eq!(decode_signed_i128(&z), expected - scaled_y);
    }

    #[test]
    fn test_zint_one_to_plain_sign_extends_31bit_words() {
        assert_eq!(zint_one_to_plain(&[0x0000_0015]), 21);
        assert_eq!(zint_one_to_plain(&[0x7FFF_FFFB]), -5);
    }
}
