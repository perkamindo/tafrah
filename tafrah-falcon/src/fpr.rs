use crate::fpr_tables::{GM_BITS, P2_BITS};

/// IEEE-754 binary64 bit pattern; mirrors the reference `typedef uint64_t fpr`.
///
/// The inner `u64` is the raw bit pattern, never an `f64`. All floating-point
/// arithmetic must go through the constant-time `fpr_*` functions below; the
/// newtype makes a stray `a + b`/`a * b` on two `Fpr` a compile error, so the
/// timing leak cannot silently return.
#[derive(Clone, Copy)]
pub(crate) struct Fpr(u64);

impl Fpr {
    /// Production constructor from a raw IEEE-754 bit pattern.
    pub(crate) const fn from_bits(bits: u64) -> Fpr {
        Fpr(bits)
    }
}

#[cfg(test)]
impl Fpr {
    /// Test-only helper: recover the `f64` this bit pattern encodes.
    pub(crate) fn to_f64(self) -> f64 {
        f64::from_bits(self.0)
    }
}

pub(crate) const fn fpr_from_bits(bits: u64) -> Fpr {
    Fpr(bits)
}

pub(crate) const Q: Fpr = fpr_from_bits(4_667_981_563_525_332_992);
pub(crate) const INVERSE_OF_Q: Fpr = fpr_from_bits(4_545_632_735_260_551_042);
pub(crate) const INV_2SQRSIGMA0: Fpr = fpr_from_bits(4_594_603_506_513_722_306);
pub(crate) const LOG2: Fpr = fpr_from_bits(4_604_418_534_313_441_775);
pub(crate) const INV_LOG2: Fpr = fpr_from_bits(4_609_176_140_021_203_710);
pub(crate) const PTWO63: Fpr = fpr_from_bits(4_890_909_195_324_358_656);
pub(crate) const BNORM_MAX: Fpr = fpr_from_bits(4_670_353_323_383_631_276);

pub(crate) const FPR_ZERO: Fpr = Fpr(0);
pub(crate) const FPR_ONE: Fpr = fpr_from_bits(4_607_182_418_800_017_408);
pub(crate) const FPR_TWO: Fpr = fpr_from_bits(4_611_686_018_427_387_904);
pub(crate) const FPR_ONEHALF: Fpr = fpr_from_bits(4_602_678_819_172_646_912);

pub(crate) const INV_SIGMA: [Fpr; 11] = [
    Fpr(0),
    fpr_from_bits(4_574_611_497_772_390_042),
    fpr_from_bits(4_574_501_679_055_810_265),
    fpr_from_bits(4_574_396_282_908_341_804),
    fpr_from_bits(4_574_245_855_758_572_086),
    fpr_from_bits(4_574_103_865_040_221_165),
    fpr_from_bits(4_573_969_550_563_515_544),
    fpr_from_bits(4_573_842_244_705_920_822),
    fpr_from_bits(4_573_721_358_406_441_454),
    fpr_from_bits(4_573_606_369_665_796_042),
    fpr_from_bits(4_573_496_814_039_276_259),
];

pub(crate) const SIGMA_MIN: [Fpr; 11] = [
    Fpr(0),
    fpr_from_bits(4_607_707_126_469_777_035),
    fpr_from_bits(4_607_777_455_861_499_430),
    fpr_from_bits(4_607_846_828_256_951_418),
    fpr_from_bits(4_607_949_175_006_100_261),
    fpr_from_bits(4_608_049_571_757_433_526),
    fpr_from_bits(4_608_148_125_896_792_003),
    fpr_from_bits(4_608_244_935_301_382_692),
    fpr_from_bits(4_608_340_089_478_362_016),
    fpr_from_bits(4_608_433_670_533_905_013),
    fpr_from_bits(4_608_525_754_002_622_308),
];

// ---------------------------------------------------------------------------
// Constant-time floating-point operations, emulated in integer arithmetic.
//
// Ported op-for-op from the reference Falcon `falcon512int/fpr.{h,c}` (Thomas
// Pornin). Every operation is branchless and data-oblivious: no secret-dependent
// branch, memory access, division, or FP instruction. This replaces native
// `f64` arithmetic, whose div/sqrt latency and subnormal handling are not
// constant-time. Results are bit-identical to IEEE-754 round-to-nearest-even
// (verified by byte-exact Falcon KATs and per-op differential unit tests).
//
// Platform assumption (from the reference's IMPORTANT ASSUMPTIONS note): the
// constant-time property holds on targets where 32x32->64 unsigned multiply and
// shifts are data-independent — x86-64, aarch64, and most ARM cores. It does NOT
// hold on cores with variable-time multiply/shift (e.g. Cortex-M0/M0+/M3, older
// PowerPC G3/G4). tafrah's Falcon feature is non-default and pre-standard.
// ---------------------------------------------------------------------------

// --- fpr_of / fpr_scaled ---
// Ports of the reference `FPR_NORM64` (fpr.c:45-78), `fpr_scaled` (fpr.c:81-135),
// and `FPR` (fpr.h:174-216). All branchless; `wrapping_*` mirrors C modular
// arithmetic (dev profile has overflow-checks=true).

/// Normalize `m` into the 2^63..2^64-1 range by left-shifting, decrementing `e`
/// by the shift count. `m == 0` stays 0. (Reference `FPR_NORM64`.)
fn fpr_norm64(mut m: u64, mut e: i32) -> (u64, i32) {
    e -= 63;

    let mut nt = (m >> 32) as u32;
    nt = (nt | nt.wrapping_neg()) >> 31;
    m ^= (m ^ (m << 32)) & u64::from(nt).wrapping_sub(1);
    e += (nt << 5) as i32;

    nt = (m >> 48) as u32;
    nt = (nt | nt.wrapping_neg()) >> 31;
    m ^= (m ^ (m << 16)) & u64::from(nt).wrapping_sub(1);
    e += (nt << 4) as i32;

    nt = (m >> 56) as u32;
    nt = (nt | nt.wrapping_neg()) >> 31;
    m ^= (m ^ (m << 8)) & u64::from(nt).wrapping_sub(1);
    e += (nt << 3) as i32;

    nt = (m >> 60) as u32;
    nt = (nt | nt.wrapping_neg()) >> 31;
    m ^= (m ^ (m << 4)) & u64::from(nt).wrapping_sub(1);
    e += (nt << 2) as i32;

    nt = (m >> 62) as u32;
    nt = (nt | nt.wrapping_neg()) >> 31;
    m ^= (m ^ (m << 2)) & u64::from(nt).wrapping_sub(1);
    e += (nt << 1) as i32;

    nt = (m >> 63) as u32;
    m ^= (m ^ (m << 1)) & u64::from(nt).wrapping_sub(1);
    e += nt as i32;

    (m, e)
}

/// Assemble sign `s` (0/1), unbiased exponent `e`, and mantissa `m`
/// (2^54..2^55, or 0) into an `Fpr`, with round-to-nearest-ties-even and
/// subnormal-clamp-to-zero. (Reference `FPR`.)
fn fpr_from_parts(s: i32, mut e: i32, mut m: u64) -> Fpr {
    e += 1076;
    let mut t = (e as u32) >> 31;
    m &= u64::from(t).wrapping_sub(1);

    t = (m >> 54) as u32;
    e &= (t as i32).wrapping_neg();

    let mut x = (((s as u64) << 63) | (m >> 2)).wrapping_add(u64::from(e as u32) << 52);

    let f = (m as u32) & 7;
    x = x.wrapping_add(u64::from((0xC8u32 >> f) & 1));
    Fpr(x)
}

pub(crate) fn fpr_scaled(mut i: i64, sc: i32) -> Fpr {
    // Extract sign, take absolute value (-i = 1 + ~i). Assumes i != i64::MIN.
    let s = ((i as u64) >> 63) as i32;
    i ^= i64::from(s).wrapping_neg();
    i = i.wrapping_add(i64::from(s));

    let (mut m, e0) = fpr_norm64(i as u64, 9 + sc);

    // Divide by 512 with a sticky low bit.
    m |= u64::from((m as u32 & 0x1FF).wrapping_add(0x1FF));
    m >>= 9;

    // If i == 0, clamp m and e to zero.
    let t = (((i | i.wrapping_neg()) as u64) >> 63) as u32;
    m &= (t as u64).wrapping_neg();
    let e = e0 & (t as i32).wrapping_neg();

    fpr_from_parts(s, e, m)
}

pub(crate) fn fpr_of(value: i64) -> Fpr {
    fpr_scaled(value, 0)
}

// --- Checkpoint 3: constant-time shift helpers + rint/floor/trunc ---
// Shift helpers (fpr.h:126-157): right/left shift a 64-bit value by a possibly
// secret count in 0..63, without relying on constant-time 64-bit shifts.

fn fpr_ursh(x: u64, n: i32) -> u64 {
    let x = x ^ ((x ^ (x >> 32)) & ((n >> 5) as u64).wrapping_neg());
    x >> (n & 31)
}

fn fpr_irsh(x: i64, n: i32) -> i64 {
    let x = x ^ ((x ^ (x >> 32)) & i64::from(n >> 5).wrapping_neg());
    x >> (n & 31)
}

fn fpr_ulsh(x: u64, n: i32) -> u64 {
    let x = x ^ ((x ^ (x << 32)) & ((n >> 5) as u64).wrapping_neg());
    x << (n & 31)
}

/// Round to nearest integer, ties to even (reference `fpr_rint`, fpr.h:272-319).
/// Assumes the value fits in -(2^63-1)..+(2^63-1).
pub(crate) fn fpr_rint(value: Fpr) -> i64 {
    let x = value.0;
    let mut m = ((x << 10) | (1u64 << 62)) & ((1u64 << 63) - 1);
    let mut e = 1085 - ((x >> 52) as i32 & 0x7FF);
    m &= ((((e - 64) as u32) >> 31) as u64).wrapping_neg();
    e &= 63;
    let d = fpr_ulsh(m, 63 - e);
    let dd = (d as u32) | ((d >> 32) as u32 & 0x1FFF_FFFF);
    let f = (d >> 61) as u32 | ((dd | dd.wrapping_neg()) >> 31);
    m = fpr_ursh(m, e).wrapping_add(u64::from((0xC8u32 >> f) & 1));
    let s = (x >> 63) as u32;
    ((m as i64) ^ (s as i64).wrapping_neg()).wrapping_add(s as i64)
}

/// Round toward minus infinity (reference `fpr_floor`, fpr.h:321-362).
pub(crate) fn fpr_floor(value: Fpr) -> i64 {
    let x = value.0;
    let e = (x >> 52) as i32 & 0x7FF;
    let t = x >> 63;
    let mut xi = (((x << 10) | (1u64 << 62)) & ((1u64 << 63) - 1)) as i64;
    xi = (xi ^ (t as i64).wrapping_neg()).wrapping_add(t as i64);
    let cc = 1085 - e;
    xi = fpr_irsh(xi, cc & 63);
    xi ^= (xi ^ (t as i64).wrapping_neg()) & ((((63 - cc) as u32) >> 31) as i64).wrapping_neg();
    xi
}

/// Round toward zero (reference `fpr_trunc`, fpr.h:364-394).
pub(crate) fn fpr_trunc(value: Fpr) -> i64 {
    let x = value.0;
    let e = (x >> 52) as i32 & 0x7FF;
    let mut xu = ((x << 10) | (1u64 << 62)) & ((1u64 << 63) - 1);
    let cc = 1085 - e;
    xu = fpr_ursh(xu, cc & 63);
    xu &= ((((cc - 64) as u32) >> 31) as u64).wrapping_neg();
    let t = x >> 63;
    xu = (xu ^ t.wrapping_neg()).wrapping_add(t);
    xu as i64
}

// --- Checkpoint 5: fpr_add (reference fpr.c:139-245) ---
pub(crate) fn fpr_add(lhs: Fpr, rhs: Fpr) -> Fpr {
    let mut x = lhs.0;
    let mut y = rhs.0;

    // Conditional swap so |x| >= |y| (and the +0 edge case is handled).
    let msk = (1u64 << 63) - 1;
    let za = (x & msk).wrapping_sub(y & msk);
    let cs = (za >> 63) as u32
        | (1u32.wrapping_sub((za.wrapping_neg() >> 63) as u32) & (x >> 63) as u32);
    let m = (x ^ y) & (cs as u64).wrapping_neg();
    x ^= m;
    y ^= m;

    // Extract sign/exp/mantissa; mantissa scaled to 2^55..2^56-1.
    let mut ex = (x >> 52) as i32;
    let sx = ex >> 11;
    ex &= 0x7FF;
    let m = u64::from(((ex + 0x7FF) >> 11) as u32) << 52;
    let mut xu = ((x & ((1u64 << 52) - 1)) | m) << 3;
    ex -= 1078;

    let mut ey = (y >> 52) as i32;
    let sy = ey >> 11;
    ey &= 0x7FF;
    let m = u64::from(((ey + 0x7FF) >> 11) as u32) << 52;
    let mut yu = ((y & ((1u64 << 52) - 1)) | m) << 3;
    ey -= 1078;

    // Only y needs right-shifting; clamp to zero if the shift exceeds 59.
    let mut cc = ex - ey;
    yu &= ((((cc - 60) as u32) >> 31) as u64).wrapping_neg();
    cc &= 63;

    // Sticky low bit, then align.
    let m = fpr_ulsh(1, cc).wrapping_sub(1);
    yu |= (yu & m).wrapping_add(m);
    yu = fpr_ursh(yu, cc);

    // Same sign -> add mantissas; opposite -> subtract.
    xu = xu.wrapping_add(yu.wrapping_sub((yu << 1) & ((sx ^ sy) as u64).wrapping_neg()));

    // Normalize, then scale down to 2^54..2^55-1 with a sticky low bit.
    let (xu_n, ex_n) = fpr_norm64(xu, ex);
    xu = xu_n;
    ex = ex_n;
    xu |= u64::from((xu as u32 & 0x1FF).wrapping_add(0x1FF));
    xu >>= 9;
    ex += 9;

    fpr_from_parts(sx, ex, xu)
}

// --- Checkpoint 4: neg / sub / half / double / lt (inline ports, fpr.h) ---

pub(crate) fn fpr_sub(lhs: Fpr, rhs: Fpr) -> Fpr {
    fpr_add(lhs, Fpr(rhs.0 ^ (1u64 << 63)))
}

pub(crate) fn fpr_neg(value: Fpr) -> Fpr {
    Fpr(value.0 ^ (1u64 << 63))
}

pub(crate) fn fpr_half(value: Fpr) -> Fpr {
    // Decrement the exponent by one, taking care of zero (fpr.h:413-426).
    let mut x = value.0.wrapping_sub(1u64 << 52);
    let t = ((x >> 52) as u32 & 0x7FF).wrapping_add(1) >> 11;
    x &= u64::from(t).wrapping_sub(1);
    Fpr(x)
}

#[allow(dead_code)]
pub(crate) fn fpr_double(value: Fpr) -> Fpr {
    // Increment the exponent by one; zero is a special case (fpr.h:428-438).
    let x = value.0;
    Fpr(x.wrapping_add(u64::from(((x >> 52) as u32 & 0x7FF).wrapping_add(0x7FF) >> 11) << 52))
}

// --- Checkpoint 6: fpr_mul / fpr_sqr (reference fpr.c:249-343) ---
pub(crate) fn fpr_mul(lhs: Fpr, rhs: Fpr) -> Fpr {
    let x = lhs.0;
    let y = rhs.0;

    let xu = (x & ((1u64 << 52) - 1)) | (1u64 << 52);
    let yu = (y & ((1u64 << 52) - 1)) | (1u64 << 52);

    // Split each 53-bit integer into 25-bit low and upper halves.
    let x0 = xu as u32 & 0x01FF_FFFF;
    let x1 = (xu >> 25) as u32;
    let y0 = yu as u32 & 0x01FF_FFFF;
    let y1 = (yu >> 25) as u32;

    // 32x32->64 partial products (each exact; overflow-check acts as a verifier).
    let mut w = u64::from(x0) * u64::from(y0);
    let z0 = w as u32 & 0x01FF_FFFF;
    let mut z1 = (w >> 25) as u32;
    w = u64::from(x0) * u64::from(y1);
    z1 = z1.wrapping_add(w as u32 & 0x01FF_FFFF);
    let mut z2 = (w >> 25) as u32;
    w = u64::from(x1) * u64::from(y0);
    z1 = z1.wrapping_add(w as u32 & 0x01FF_FFFF);
    z2 = z2.wrapping_add((w >> 25) as u32);
    let mut zu = u64::from(x1) * u64::from(y1);
    z2 = z2.wrapping_add(z1 >> 25);
    z1 &= 0x01FF_FFFF;
    zu = zu.wrapping_add(u64::from(z2));

    // Low limbs contribute only to the sticky bit.
    zu |= u64::from((z0 | z1).wrapping_add(0x01FF_FFFF) >> 25);

    // Conditional right-shift into 2^54..2^55-1 (product may be one bit too large).
    let zv = (zu >> 1) | (zu & 1);
    w = zu >> 55;
    zu ^= (zu ^ zv) & w.wrapping_neg();

    let ex = ((x >> 52) & 0x7FF) as i32;
    let ey = ((y >> 52) & 0x7FF) as i32;
    let e = ex + ey - 2100 + w as i32;

    let s = ((x ^ y) >> 63) as i32;

    // Zero correction: if either operand is zero, force mantissa to zero.
    let d = ((ex + 0x7FF) & (ey + 0x7FF)) >> 11;
    zu &= (d as u64).wrapping_neg();

    fpr_from_parts(s, e, zu)
}

pub(crate) fn fpr_sqr(value: Fpr) -> Fpr {
    fpr_mul(value, value)
}

// --- Checkpoint 7: fpr_div / fpr_inv (reference fpr.c:347-432) ---
pub(crate) fn fpr_div(lhs: Fpr, rhs: Fpr) -> Fpr {
    let x = lhs.0;
    let y = rhs.0;

    let mut xu = (x & ((1u64 << 52) - 1)) | (1u64 << 52);
    let yu = (y & ((1u64 << 52) - 1)) | (1u64 << 52);

    // Bit-by-bit division: exactly 55 iterations (fixed, data-independent).
    let mut q = 0u64;
    for _ in 0..55 {
        let b = (xu.wrapping_sub(yu) >> 63).wrapping_sub(1);
        xu = xu.wrapping_sub(b & yu);
        q |= b & 1;
        xu <<= 1;
        q <<= 1;
    }

    // 56th bit sticky: set iff the remainder is nonzero.
    q |= (xu | xu.wrapping_neg()) >> 63;

    // Conditional shift to normalize q to 2^54..2^55-1.
    let q2 = (q >> 1) | (q & 1);
    let w = q >> 55;
    q ^= (q ^ q2) & w.wrapping_neg();

    let ex = ((x >> 52) & 0x7FF) as i32;
    let ey = ((y >> 52) & 0x7FF) as i32;
    let mut e = ex - ey - 55 + w as i32;

    let mut s = ((x ^ y) >> 63) as i32;

    // Zero correction for x = 0 (division by zero is a caller error, not handled).
    let d = (ex + 0x7FF) >> 11;
    s &= d;
    e &= d.wrapping_neg();
    q &= (d as u64).wrapping_neg();

    fpr_from_parts(s, e, q)
}

pub(crate) fn fpr_inv(value: Fpr) -> Fpr {
    fpr_div(FPR_ONE, value)
}

// --- Checkpoint 8: fpr_sqrt (reference fpr.c:436-511) ---
pub(crate) fn fpr_sqrt(value: Fpr) -> Fpr {
    let x = value.0;

    // Mantissa and true exponent (sign ignored; operand assumed non-negative).
    let mut xu = (x & ((1u64 << 52) - 1)) | (1u64 << 52);
    let ex = ((x >> 52) & 0x7FF) as i32;
    let mut e = ex - 1023;

    // Odd exponent: double the mantissa, decrement e; then halve e.
    xu = xu.wrapping_add(xu & ((e & 1) as u64).wrapping_neg());
    e >>= 1;
    xu <<= 1;

    // Bit-by-bit square root: exactly 54 iterations (fixed, data-independent).
    let mut q = 0u64;
    let mut s = 0u64;
    let mut r = 1u64 << 53;
    for _ in 0..54 {
        let t = s.wrapping_add(r);
        let b = (xu.wrapping_sub(t) >> 63).wrapping_sub(1);
        s = s.wrapping_add((r << 1) & b);
        xu = xu.wrapping_sub(t & b);
        q = q.wrapping_add(r & b);
        xu <<= 1;
        r >>= 1;
    }

    // Extra sticky bit for the remaining operand.
    q <<= 1;
    q |= (xu | xu.wrapping_neg()) >> 63;

    e -= 54;

    // Zero operand -> zero result.
    q &= (((ex + 0x7FF) >> 11) as u64).wrapping_neg();

    fpr_from_parts(0, e, q)
}

pub(crate) fn fpr_lt(lhs: Fpr, rhs: Fpr) -> bool {
    // Signed compare preserves order for non-negative values; when both are
    // negative the order is reversed, corrected via the (x & y) sign bit
    // without mishandling x == y (fpr.h:461-480).
    let x = lhs.0;
    let y = rhs.0;
    let cc0 = i32::from((x as i64) < (y as i64));
    let cc1 = i32::from((x as i64) > (y as i64));
    (cc0 ^ ((cc0 ^ cc1) & (((x & y) >> 63) as i32))) != 0
}

// --- Checkpoint 9: fpr_expm_p63 (reference fpr.c:514-598) ---
// FACCT fixed-point polynomial approximation of exp(-x), coefficients scaled by
// 2^63. Each iteration keeps the top 64 bits of a 128-bit product, computed via
// 32-bit limbs; additive combinations use `wrapping_add` (C unsigned semantics).
pub(crate) fn fpr_expm_p63(x: Fpr, ccs: Fpr) -> u64 {
    const C: [u64; 13] = [
        0x0000_0004_7411_83A3,
        0x0000_0036_548C_FC06,
        0x0000_024F_DCBF_140A,
        0x0000_171D_939D_E045,
        0x0000_D00C_F58F_6F84,
        0x0006_8068_1CF7_96E3,
        0x002D_82D8_305B_0FEA,
        0x0111_1111_0E06_6FD0,
        0x0555_5555_5507_0F00,
        0x1555_5555_5581_FF00,
        0x4000_0000_0002_B400,
        0x7FFF_FFFF_FFFF_4800,
        0x8000_0000_0000_0000,
    ];

    let mut y = C[0];
    let mut z = (fpr_trunc(fpr_mul(x, PTWO63)) as u64) << 1;
    for &c_u in &C[1..] {
        let z0 = z as u32;
        let z1 = (z >> 32) as u32;
        let y0 = y as u32;
        let y1 = (y >> 32) as u32;
        let a =
            (u64::from(z0) * u64::from(y1)).wrapping_add((u64::from(z0) * u64::from(y0)) >> 32);
        let b = u64::from(z1) * u64::from(y0);
        let mut c = (a >> 32).wrapping_add(b >> 32);
        c = c.wrapping_add((u64::from(a as u32).wrapping_add(u64::from(b as u32))) >> 32);
        c = c.wrapping_add(u64::from(z1) * u64::from(y1));
        y = c_u.wrapping_sub(c);
    }

    // Apply the scaling factor ccs (fixed-point) with one final integer multiply.
    z = (fpr_trunc(fpr_mul(ccs, PTWO63)) as u64) << 1;
    let z0 = z as u32;
    let z1 = (z >> 32) as u32;
    let y0 = y as u32;
    let y1 = (y >> 32) as u32;
    let a = (u64::from(z0) * u64::from(y1)).wrapping_add((u64::from(z0) * u64::from(y0)) >> 32);
    let b = u64::from(z1) * u64::from(y0);
    y = (a >> 32).wrapping_add(b >> 32);
    y = y.wrapping_add((u64::from(a as u32).wrapping_add(u64::from(b as u32))) >> 32);
    y = y.wrapping_add(u64::from(z1) * u64::from(y1));

    y
}

pub(crate) struct GmTable;

impl GmTable {
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) fn get(&self, index: usize) -> (Fpr, Fpr) {
        (
            fpr_from_bits(GM_BITS[index << 1]),
            fpr_from_bits(GM_BITS[(index << 1) + 1]),
        )
    }
}

pub(crate) fn p2(logn: usize) -> Fpr {
    fpr_from_bits(P2_BITS[logn])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CP2: emulated `fpr_of` must reproduce `i as f64` bit-for-bit (both
    /// round-to-nearest-ties-even). Spans exact (<2^53) and rounded (>2^53) ranges.
    #[test]
    fn fpr_of_matches_native() {
        let cases: [i64; 24] = [
            0,
            1,
            -1,
            2,
            -2,
            255,
            -255,
            1000,
            -1000,
            i64::from(i32::MAX),
            i64::from(i32::MIN),
            (1 << 52) - 1,
            -((1 << 52) - 1),
            (1 << 53) - 1,
            (1 << 53) + 1, // needs rounding (not exactly representable)
            (1 << 53) + 3,
            -((1 << 53) + 1),
            (1 << 55) + 5,
            (1 << 60),
            -(1 << 60),
            (1 << 62),
            -(1 << 62),
            9_007_199_254_740_993,
            -9_007_199_254_740_993,
        ];
        for i in cases {
            assert_eq!(
                fpr_of(i).0,
                (i as f64).to_bits(),
                "fpr_of({i}) = {:#018x}, native = {:#018x}",
                fpr_of(i).0,
                (i as f64).to_bits()
            );
        }
    }

    /// CP3: emulated rint/floor/trunc must match libm (round-to-nearest-even,
    /// toward -inf, toward zero) over both signs, fractions, and tie cases.
    #[test]
    fn fpr_rint_floor_trunc_match_native() {
        let vals: [f64; 24] = [
            0.0, 1.0, -1.0, 1.4, 1.5, 2.5, 3.5, -1.4, -1.5, -2.5, -3.5, 0.4999, -0.4999, 0.5, -0.5,
            123.456, -123.456, 100.0, -100.0, 1_000_000.5, -1_000_000.5, 1e15, -1e15, 4.5,
        ];
        for v in vals {
            let x = fpr_from_bits(v.to_bits());
            assert_eq!(fpr_rint(x), libm::rint(v) as i64, "rint({v})");
            assert_eq!(fpr_floor(x), libm::floor(v) as i64, "floor({v})");
            assert_eq!(fpr_trunc(x), libm::trunc(v) as i64, "trunc({v})");
        }
    }

    /// CP4: neg/half/double bit-exact vs native; fpr_lt over all sign pairings
    /// (the both-negative reversal is the subtle case).
    #[test]
    fn fpr_neg_half_double_lt_match_native() {
        let vals: [f64; 15] = [
            0.0, 1.0, -1.0, 0.5, -0.5, 2.0, -2.0, 3.141_59, -3.141_59, 1e10, -1e10, 1e-10, -1e-10,
            123.456, -123.456,
        ];
        for a in vals {
            let fa = fpr_from_bits(a.to_bits());
            assert_eq!(fpr_neg(fa).0, (-a).to_bits(), "neg({a})");
            assert_eq!(fpr_half(fa).0, (a * 0.5).to_bits(), "half({a})");
            assert_eq!(fpr_double(fa).0, (a * 2.0).to_bits(), "double({a})");
            for b in vals {
                let fb = fpr_from_bits(b.to_bits());
                assert_eq!(fpr_lt(fa, fb), a < b, "lt({a}, {b})");
            }
        }
    }

    /// CP5: fpr_add bit-exact vs native over all pairs — includes opposite
    /// signs, exact cancellation (-> +0), and wide exponent gaps (shift clamp).
    #[test]
    fn fpr_add_matches_native() {
        let vals: [f64; 19] = [
            0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.141_59, -3.141_59, 1e10, -1e10, 1e-10, -1e-10,
            1234.5, -1234.5, 1e100, -1e100, 7.0, -7.0,
        ];
        for a in vals {
            for b in vals {
                let r = fpr_add(fpr_from_bits(a.to_bits()), fpr_from_bits(b.to_bits()));
                assert_eq!(r.0, (a + b).to_bits(), "add({a}, {b})");
            }
        }
    }

    /// CP6: fpr_mul / fpr_sqr bit-exact vs native, all sign pairs incl. zero.
    #[test]
    fn fpr_mul_matches_native() {
        let vals: [f64; 19] = [
            0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.141_59, -3.141_59, 1e10, -1e10, 1e-10, -1e-10,
            1234.5, -1234.5, 7.0, -7.0, 1e100, 1e-100,
        ];
        for a in vals {
            for b in vals {
                let r = fpr_mul(fpr_from_bits(a.to_bits()), fpr_from_bits(b.to_bits()));
                assert_eq!(r.0, (a * b).to_bits(), "mul({a}, {b})");
            }
            assert_eq!(
                fpr_sqr(fpr_from_bits(a.to_bits())).0,
                (a * a).to_bits(),
                "sqr({a})"
            );
        }
    }

    /// The emulated `fpr` normalizes every zero result to +0 (it does not track
    /// the sign of zero); native division yields -0 for e.g. `0.0 / -1.0`. The
    /// reference `fpr_div` behaves exactly like the emulation here (its zero
    /// correction forces the sign to 0), and Falcon never depends on the sign of
    /// a zero — so treat +0 and -0 as equal in the differential comparison.
    fn same_fpr(got: u64, want: u64) -> bool {
        got == want
            || ((got & 0x7FFF_FFFF_FFFF_FFFF) == 0 && (want & 0x7FFF_FFFF_FFFF_FFFF) == 0)
    }

    /// CP7: fpr_div / fpr_inv bit-exact vs native over non-zero divisors
    /// (modulo the sign of a zero result — see `same_fpr`).
    #[test]
    fn fpr_div_inv_match_native() {
        let divisors: [f64; 18] = [
            1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.141_59, -3.141_59, 1e10, -1e10, 1e-10, -1e-10,
            1234.5, -1234.5, 7.0, -7.0, 1e100, 1e-100,
        ];
        let nums: [f64; 11] = [
            0.0, 1.0, -1.0, 2.0, -2.0, 3.141_59, -3.141_59, 1e10, 1e-10, 1234.5, 7.0,
        ];
        for a in nums {
            for b in divisors {
                let r = fpr_div(fpr_from_bits(a.to_bits()), fpr_from_bits(b.to_bits()));
                assert!(
                    same_fpr(r.0, (a / b).to_bits()),
                    "div({a}, {b}): {:#018x} vs {:#018x}",
                    r.0,
                    (a / b).to_bits()
                );
            }
        }
        for b in divisors {
            assert!(
                same_fpr(fpr_inv(fpr_from_bits(b.to_bits())).0, (1.0 / b).to_bits()),
                "inv({b})"
            );
        }
    }

    /// CP8: fpr_sqrt bit-exact vs libm over non-negative operands.
    #[test]
    fn fpr_sqrt_matches_native() {
        let vals: [f64; 18] = [
            0.0, 1.0, 2.0, 4.0, 0.5, 0.25, 3.141_59, 1e10, 1e-10, 1234.5, 7.0, 9.0, 16.0, 2.25,
            100.0, 1e100, 1e-100, 123_456.789,
        ];
        for a in vals {
            assert_eq!(
                fpr_sqrt(fpr_from_bits(a.to_bits())).0,
                libm::sqrt(a).to_bits(),
                "sqrt({a})"
            );
        }
    }

    /// CP9: fpr_expm_p63 is a different algorithm than the native Horner, so a
    /// bit-exact differential is invalid; the KAT parity is its real gate. This
    /// is only a loose magnitude sanity check that expm(x, ccs) ~= exp(-x)*ccs*2^63.
    /// Domain: x in [0, ln2], ccs strictly < 1 (so ccs*2^63 stays in fpr_trunc range,
    /// as it always is in real Falcon where ccs = isigma * sigma_min < 1).
    #[test]
    fn fpr_expm_p63_sanity() {
        const TWO63: f64 = 9_223_372_036_854_775_808.0;
        for x in [0.0f64, 0.1, 0.25, 0.4, 0.6, 0.69] {
            for ccs in [0.5f64, 0.75, 0.9, 0.99] {
                let got =
                    fpr_expm_p63(fpr_from_bits(x.to_bits()), fpr_from_bits(ccs.to_bits())) as f64;
                let want = libm::exp(-x) * ccs * TWO63;
                let rel = (got - want).abs() / want;
                assert!(rel < 1e-6, "expm({x}, {ccs}): got {got}, want {want}, rel {rel}");
            }
        }
    }
}
