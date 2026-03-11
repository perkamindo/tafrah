use crate::fpr_tables::{GM_BITS, P2_BITS};

pub(crate) type Fpr = f64;

const fn fpr_from_bits(bits: u64) -> Fpr {
    Fpr::from_bits(bits)
}

pub(crate) const Q: Fpr = fpr_from_bits(4_667_981_563_525_332_992);
pub(crate) const INVERSE_OF_Q: Fpr = fpr_from_bits(4_545_632_735_260_551_042);
pub(crate) const INV_2SQRSIGMA0: Fpr = fpr_from_bits(4_594_603_506_513_722_306);
pub(crate) const LOG2: Fpr = fpr_from_bits(4_604_418_534_313_441_775);
pub(crate) const INV_LOG2: Fpr = fpr_from_bits(4_609_176_140_021_203_710);
pub(crate) const PTWO63: Fpr = fpr_from_bits(4_890_909_195_324_358_656);
pub(crate) const BNORM_MAX: Fpr = fpr_from_bits(4_670_353_323_383_631_276);

pub(crate) const INV_SIGMA: [Fpr; 11] = [
    0.0,
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
    0.0,
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

pub(crate) fn fpr_of(value: i64) -> Fpr {
    value as Fpr
}

pub(crate) fn fpr_rint(value: Fpr) -> i64 {
    let sx = (value - 1.0) as i64;
    let mut tx = value as i64;
    let mut rp = (value + 4503599627370496.0) as i64 - 4503599627370496;
    let mut rn = (value - 4503599627370496.0) as i64 + 4503599627370496;

    let mut m = sx >> 63;
    rn &= m;
    rp &= !m;

    let ub = ((tx as u64) >> 52) as u32;
    m = -(((((ub.wrapping_add(1)) & 0x0FFF).wrapping_sub(2)) >> 31) as i64);
    rp &= m;
    rn &= m;
    tx &= !m;

    tx | rn | rp
}

pub(crate) fn fpr_floor(value: Fpr) -> i64 {
    let r = value as i64;
    r - i64::from(value < r as Fpr)
}

pub(crate) fn fpr_trunc(value: Fpr) -> i64 {
    value as i64
}

pub(crate) fn fpr_add(lhs: Fpr, rhs: Fpr) -> Fpr {
    lhs + rhs
}

pub(crate) fn fpr_sub(lhs: Fpr, rhs: Fpr) -> Fpr {
    lhs - rhs
}

pub(crate) fn fpr_neg(value: Fpr) -> Fpr {
    -value
}

pub(crate) fn fpr_half(value: Fpr) -> Fpr {
    value * 0.5
}

pub(crate) fn fpr_mul(lhs: Fpr, rhs: Fpr) -> Fpr {
    lhs * rhs
}

pub(crate) fn fpr_sqr(value: Fpr) -> Fpr {
    value * value
}

pub(crate) fn fpr_inv(value: Fpr) -> Fpr {
    1.0 / value
}

pub(crate) fn fpr_sqrt(value: Fpr) -> Fpr {
    libm::sqrt(value)
}

pub(crate) fn fpr_lt(lhs: Fpr, rhs: Fpr) -> bool {
    lhs < rhs
}

pub(crate) fn fpr_expm_p63(x: Fpr, ccs: Fpr) -> u64 {
    let d = x;
    let mut y = 0.000000002073772366009083061987;
    y = 0.000000025299506379442070029551 - y * d;
    y = 0.000000275607356160477811864927 - y * d;
    y = 0.000002755586350219122514855659 - y * d;
    y = 0.000024801566833585381209939524 - y * d;
    y = 0.000198412739277311890541063977 - y * d;
    y = 0.001388888894063186997887560103 - y * d;
    y = 0.008333333327800835146903501993 - y * d;
    y = 0.041666666666110491190622155955 - y * d;
    y = 0.166666666666984014666397229121 - y * d;
    y = 0.500000000000019206858326015208 - y * d;
    y = 0.999999999999994892974086724280 - y * d;
    y = 1.000000000000000000000000000000 - y * d;
    y *= ccs;
    (y * PTWO63) as u64
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
