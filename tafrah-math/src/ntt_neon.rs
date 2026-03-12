#[cfg(all(feature = "neon", target_arch = "aarch64"))]
pub(crate) mod kem {
    use core::arch::aarch64::{
        vdupq_n_s16, vget_high_s16, vget_low_s16, vld1q_s16, vmull_s16, vst1q_s32,
    };

    use crate::field::kem;
    use crate::ntt::kem::{N, ZETAS};

    #[inline]
    pub(crate) fn is_available() -> bool {
        true
    }

    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn ntt(r: &mut [i16; N]) {
        let mut k: usize = 1;
        let mut len: usize = 128;
        while len >= 2 {
            let mut start: usize = 0;
            while start < N {
                let zeta = ZETAS[k];
                k += 1;
                let mut j = start;
                while j + 8 <= start + len {
                    let t = mul_const_reduce_i16x8(r[j + len..].as_ptr(), zeta);
                    for lane in 0..8 {
                        let lhs = r[j + lane];
                        r[j + len + lane] = lhs - t[lane];
                        r[j + lane] = lhs + t[lane];
                    }
                    j += 8;
                }
                while j < start + len {
                    let t = kem::fqmul(zeta, r[j + len]);
                    r[j + len] = r[j] - t;
                    r[j] = r[j] + t;
                    j += 1;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn inv_ntt(r: &mut [i16; N]) {
        let mut k: usize = 127;
        let mut len: usize = 2;
        while len <= 128 {
            let mut start: usize = 0;
            while start < N {
                let zeta = ZETAS[k];
                k -= 1;
                let mut j = start;
                while j + 8 <= start + len {
                    let mut diff = [0i16; 8];
                    for lane in 0..8 {
                        let lhs = r[j + lane];
                        let rhs = r[j + len + lane];
                        r[j + lane] = kem::barrett_reduce(lhs + rhs);
                        diff[lane] = rhs - lhs;
                    }
                    let reduced = mul_const_reduce_i16x8(diff.as_ptr(), zeta);
                    r[j + len..j + len + 8].copy_from_slice(&reduced);
                    j += 8;
                }
                while j < start + len {
                    let t = r[j];
                    r[j] = kem::barrett_reduce(t + r[j + len]);
                    r[j + len] = r[j + len] - t;
                    r[j + len] = kem::fqmul(zeta, r[j + len]);
                    j += 1;
                }
                start += 2 * len;
            }
            len <<= 1;
        }

        const F: i16 = 1441;
        for coeff in r.iter_mut() {
            *coeff = kem::fqmul(*coeff, F);
        }
    }

    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn poly_basemul_montgomery(out: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
        let mut chunk = 0usize;
        while chunk < N {
            let products = mul_i16x8_to_i32x8(a[chunk..].as_ptr(), b[chunk..].as_ptr());
            let rhs_swapped = [
                b[chunk + 1],
                b[chunk],
                b[chunk + 3],
                b[chunk + 2],
                b[chunk + 5],
                b[chunk + 4],
                b[chunk + 7],
                b[chunk + 6],
            ];
            let crosses = mul_i16x8_to_i32x8(a[chunk..].as_ptr(), rhs_swapped.as_ptr());
            let pair_index = chunk / 4;
            let zeta0 = ZETAS[64 + pair_index];
            let zeta1 = ZETAS[64 + pair_index + 1];

            out[chunk] = kem::fqmul(kem::montgomery_reduce(products[1]), zeta0)
                + kem::montgomery_reduce(products[0]);
            out[chunk + 1] =
                kem::montgomery_reduce(crosses[0]) + kem::montgomery_reduce(crosses[1]);
            out[chunk + 2] = kem::fqmul(kem::montgomery_reduce(products[3]), -zeta0)
                + kem::montgomery_reduce(products[2]);
            out[chunk + 3] =
                kem::montgomery_reduce(crosses[2]) + kem::montgomery_reduce(crosses[3]);
            out[chunk + 4] = kem::fqmul(kem::montgomery_reduce(products[5]), zeta1)
                + kem::montgomery_reduce(products[4]);
            out[chunk + 5] =
                kem::montgomery_reduce(crosses[4]) + kem::montgomery_reduce(crosses[5]);
            out[chunk + 6] = kem::fqmul(kem::montgomery_reduce(products[7]), -zeta1)
                + kem::montgomery_reduce(products[6]);
            out[chunk + 7] =
                kem::montgomery_reduce(crosses[6]) + kem::montgomery_reduce(crosses[7]);
            chunk += 8;
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn mul_const_reduce_i16x8(src: *const i16, zeta: i16) -> [i16; 8] {
        let vec = vld1q_s16(src);
        let zeta_vec = vdupq_n_s16(zeta);
        let lo = vmull_s16(vget_low_s16(vec), vget_low_s16(zeta_vec));
        let hi = vmull_s16(vget_high_s16(vec), vget_high_s16(zeta_vec));

        let mut lo_arr = [0i32; 4];
        let mut hi_arr = [0i32; 4];
        vst1q_s32(lo_arr.as_mut_ptr(), lo);
        vst1q_s32(hi_arr.as_mut_ptr(), hi);

        let mut out = [0i16; 8];
        for lane in 0..4 {
            out[lane] = kem::montgomery_reduce(lo_arr[lane]);
            out[lane + 4] = kem::montgomery_reduce(hi_arr[lane]);
        }
        out
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn mul_i16x8_to_i32x8(lhs: *const i16, rhs: *const i16) -> [i32; 8] {
        let lhs_vec = vld1q_s16(lhs);
        let rhs_vec = vld1q_s16(rhs);
        let lo = vmull_s16(vget_low_s16(lhs_vec), vget_low_s16(rhs_vec));
        let hi = vmull_s16(vget_high_s16(lhs_vec), vget_high_s16(rhs_vec));

        let mut out = [0i32; 8];
        vst1q_s32(out.as_mut_ptr(), lo);
        vst1q_s32(out[4..].as_mut_ptr(), hi);
        out
    }
}

#[cfg(all(feature = "neon", target_arch = "aarch64"))]
pub(crate) mod dsa {
    use core::arch::aarch64::{
        vdup_n_s32, vget_high_s32, vget_low_s32, vld1q_s32, vmull_s32, vst1q_s64,
    };

    use crate::field::dsa;
    use crate::ntt::dsa::{N, ZETAS};

    #[inline]
    pub(crate) fn is_available() -> bool {
        true
    }

    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn pointwise_mul(c: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
        let mut i = 0;
        while i < N {
            let lanes = mul_i32x8_to_i64x8(a[i..].as_ptr(), b[i..].as_ptr());
            for lane in 0..8 {
                c[i + lane] = dsa::montgomery_reduce(lanes[lane]);
            }
            i += 8;
        }
    }

    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn ntt(a: &mut [i32; N]) {
        let mut k: usize = 0;
        let mut len: usize = 128;
        while len > 0 {
            let mut start: usize = 0;
            while start < N {
                k += 1;
                let zeta = ZETAS[k];
                let mut j = start;
                while j + 8 <= start + len {
                    let t = mul_const_reduce_i32x8(a[j + len..].as_ptr(), zeta);
                    for lane in 0..8 {
                        let lhs = a[j + lane];
                        a[j + len + lane] = lhs - t[lane];
                        a[j + lane] = lhs + t[lane];
                    }
                    j += 8;
                }
                while j < start + len {
                    let t = dsa::montgomery_reduce(zeta as i64 * a[j + len] as i64);
                    a[j + len] = a[j] - t;
                    a[j] = a[j] + t;
                    j += 1;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn inv_ntt(a: &mut [i32; N]) {
        let mut k: usize = 256;
        let mut len: usize = 1;
        while len < N {
            let mut start: usize = 0;
            while start < N {
                k -= 1;
                let zeta = -ZETAS[k];
                let mut j = start;
                while j + 8 <= start + len {
                    let mut diff = [0i32; 8];
                    for lane in 0..8 {
                        let lhs = a[j + lane];
                        let rhs = a[j + len + lane];
                        a[j + lane] = lhs + rhs;
                        diff[lane] = lhs - rhs;
                    }
                    let reduced = mul_const_reduce_i32x8(diff.as_ptr(), zeta);
                    a[j + len..j + len + 8].copy_from_slice(&reduced);
                    j += 8;
                }
                while j < start + len {
                    let lhs = a[j];
                    a[j] = lhs + a[j + len];
                    a[j + len] = lhs - a[j + len];
                    a[j + len] = dsa::montgomery_reduce(zeta as i64 * a[j + len] as i64);
                    j += 1;
                }
                start += 2 * len;
            }
            len <<= 1;
        }

        const F: i64 = 41978;
        for coeff in a.iter_mut() {
            *coeff = dsa::montgomery_reduce(F * *coeff as i64);
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn mul_const_reduce_i32x8(src: *const i32, zeta: i32) -> [i32; 8] {
        let zeta_vec = vdup_n_s32(zeta);
        let lo = vmull_s32(vget_low_s32(vld1q_s32(src)), zeta_vec);
        let hi = vmull_s32(vget_high_s32(vld1q_s32(src)), zeta_vec);
        let lo2 = vmull_s32(vget_low_s32(vld1q_s32(src.add(4))), zeta_vec);
        let hi2 = vmull_s32(vget_high_s32(vld1q_s32(src.add(4))), zeta_vec);
        let mut lo_arr = [0i64; 2];
        let mut hi_arr = [0i64; 2];
        let mut lo2_arr = [0i64; 2];
        let mut hi2_arr = [0i64; 2];
        vst1q_s64(lo_arr.as_mut_ptr(), lo);
        vst1q_s64(hi_arr.as_mut_ptr(), hi);
        vst1q_s64(lo2_arr.as_mut_ptr(), lo2);
        vst1q_s64(hi2_arr.as_mut_ptr(), hi2);
        let mut out = [0i32; 8];
        out[0] = dsa::montgomery_reduce(lo_arr[0]);
        out[1] = dsa::montgomery_reduce(lo_arr[1]);
        out[2] = dsa::montgomery_reduce(hi_arr[0]);
        out[3] = dsa::montgomery_reduce(hi_arr[1]);
        out[4] = dsa::montgomery_reduce(lo2_arr[0]);
        out[5] = dsa::montgomery_reduce(lo2_arr[1]);
        out[6] = dsa::montgomery_reduce(hi2_arr[0]);
        out[7] = dsa::montgomery_reduce(hi2_arr[1]);
        out
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn mul_i32x8_to_i64x8(lhs: *const i32, rhs: *const i32) -> [i64; 8] {
        let lhs0 = vld1q_s32(lhs);
        let rhs0 = vld1q_s32(rhs);
        let lhs1 = vld1q_s32(lhs.add(4));
        let rhs1 = vld1q_s32(rhs.add(4));

        let lo0 = vmull_s32(vget_low_s32(lhs0), vget_low_s32(rhs0));
        let hi0 = vmull_s32(vget_high_s32(lhs0), vget_high_s32(rhs0));
        let lo1 = vmull_s32(vget_low_s32(lhs1), vget_low_s32(rhs1));
        let hi1 = vmull_s32(vget_high_s32(lhs1), vget_high_s32(rhs1));

        let mut out = [0i64; 8];
        vst1q_s64(out.as_mut_ptr(), lo0);
        vst1q_s64(out[2..].as_mut_ptr(), hi0);
        vst1q_s64(out[4..].as_mut_ptr(), lo1);
        vst1q_s64(out[6..].as_mut_ptr(), hi1);
        out
    }
}
