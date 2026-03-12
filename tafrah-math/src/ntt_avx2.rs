#[cfg(all(feature = "avx2", any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) mod kem {
    use core::sync::atomic::{AtomicU8, Ordering};

    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __cpuid, __cpuid_count, __m128i, __m256i, _mm256_cvtepi16_epi32, _mm256_mullo_epi32,
        _mm256_set1_epi32, _mm256_storeu_si256, _mm_loadu_si128, _xgetbv,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __cpuid, __cpuid_count, __m128i, __m256i, _mm256_cvtepi16_epi32, _mm256_mullo_epi32,
        _mm256_set1_epi32, _mm256_storeu_si256, _mm_loadu_si128, _xgetbv,
    };

    use crate::field::kem;
    use crate::ntt::kem::{N, ZETAS};

    const DETECT_UNKNOWN: u8 = 0;
    const DETECT_UNAVAILABLE: u8 = 1;
    const DETECT_AVAILABLE: u8 = 2;

    static AVX2_STATE: AtomicU8 = AtomicU8::new(DETECT_UNKNOWN);

    #[inline]
    pub(crate) fn is_available() -> bool {
        match AVX2_STATE.load(Ordering::Relaxed) {
            DETECT_AVAILABLE => true,
            DETECT_UNAVAILABLE => false,
            _ => {
                let available = detect_avx2();
                AVX2_STATE.store(
                    if available {
                        DETECT_AVAILABLE
                    } else {
                        DETECT_UNAVAILABLE
                    },
                    Ordering::Relaxed,
                );
                available
            }
        }
    }

    #[inline]
    fn detect_avx2() -> bool {
        unsafe {
            let leaf1 = __cpuid(1);
            let has_xsave = (leaf1.ecx & (1 << 26)) != 0;
            let has_osxsave = (leaf1.ecx & (1 << 27)) != 0;
            let has_avx = (leaf1.ecx & (1 << 28)) != 0;
            if !(has_xsave && has_osxsave && has_avx) {
                return false;
            }

            let xcr0 = _xgetbv(0);
            if (xcr0 & 0b110) != 0b110 {
                return false;
            }

            let leaf7 = __cpuid_count(7, 0);
            (leaf7.ebx & (1 << 5)) != 0
        }
    }

    #[target_feature(enable = "avx2")]
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

    #[target_feature(enable = "avx2")]
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

    #[target_feature(enable = "avx2")]
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
    #[target_feature(enable = "avx2")]
    unsafe fn mul_const_reduce_i16x8(src: *const i16, zeta: i16) -> [i16; 8] {
        let zeta_vec = _mm256_set1_epi32(zeta as i32);
        let src128 = _mm_loadu_si128(src as *const __m128i);
        let src256 = _mm256_cvtepi16_epi32(src128);
        let products = _mm256_mullo_epi32(src256, zeta_vec);

        let mut lanes = [0i32; 8];
        _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, products);

        let mut out = [0i16; 8];
        for (dst, product) in out.iter_mut().zip(lanes.iter()) {
            *dst = kem::montgomery_reduce(*product);
        }
        out
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn mul_i16x8_to_i32x8(lhs: *const i16, rhs: *const i16) -> [i32; 8] {
        let lhs128 = _mm_loadu_si128(lhs as *const __m128i);
        let rhs128 = _mm_loadu_si128(rhs as *const __m128i);
        let lhs256 = _mm256_cvtepi16_epi32(lhs128);
        let rhs256 = _mm256_cvtepi16_epi32(rhs128);
        let product = _mm256_mullo_epi32(lhs256, rhs256);
        let mut out = [0i32; 8];
        _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, product);
        out
    }
}

#[cfg(all(feature = "avx2", any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) mod dsa {
    use core::sync::atomic::{AtomicU8, Ordering};

    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __cpuid, __cpuid_count, __m256i, _mm256_loadu_si256, _mm256_mul_epi32, _mm256_set1_epi32,
        _mm256_srli_epi64, _mm256_storeu_si256, _xgetbv,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __cpuid, __cpuid_count, __m256i, _mm256_loadu_si256, _mm256_mul_epi32, _mm256_set1_epi32,
        _mm256_srli_epi64, _mm256_storeu_si256, _xgetbv,
    };

    use crate::field::dsa;
    use crate::ntt::dsa::{N, ZETAS};

    const DETECT_UNKNOWN: u8 = 0;
    const DETECT_UNAVAILABLE: u8 = 1;
    const DETECT_AVAILABLE: u8 = 2;

    static AVX2_STATE: AtomicU8 = AtomicU8::new(DETECT_UNKNOWN);

    #[inline]
    pub(crate) fn is_available() -> bool {
        match AVX2_STATE.load(Ordering::Relaxed) {
            DETECT_AVAILABLE => true,
            DETECT_UNAVAILABLE => false,
            _ => {
                let available = detect_avx2();
                AVX2_STATE.store(
                    if available {
                        DETECT_AVAILABLE
                    } else {
                        DETECT_UNAVAILABLE
                    },
                    Ordering::Relaxed,
                );
                available
            }
        }
    }

    #[inline]
    fn detect_avx2() -> bool {
        unsafe {
            let leaf1 = __cpuid(1);
            let has_xsave = (leaf1.ecx & (1 << 26)) != 0;
            let has_osxsave = (leaf1.ecx & (1 << 27)) != 0;
            let has_avx = (leaf1.ecx & (1 << 28)) != 0;
            if !(has_xsave && has_osxsave && has_avx) {
                return false;
            }

            let xcr0 = _xgetbv(0);
            if (xcr0 & 0b110) != 0b110 {
                return false;
            }

            let leaf7 = __cpuid_count(7, 0);
            (leaf7.ebx & (1 << 5)) != 0
        }
    }

    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn pointwise_mul(c: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
        let mut i = 0;
        while i < N {
            let lhs = unsafe { _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i) };
            let rhs = unsafe { _mm256_loadu_si256(b[i..].as_ptr() as *const __m256i) };
            let lanes = mul_reduce_i32x8(lhs, rhs);
            c[i..i + 8].copy_from_slice(&lanes);
            i += 8;
        }
    }

    #[target_feature(enable = "avx2")]
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
                    let rhs =
                        unsafe { _mm256_loadu_si256(a[j + len..].as_ptr() as *const __m256i) };
                    let t = mul_const_reduce_i32x8(rhs, zeta);
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

    #[target_feature(enable = "avx2")]
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
                    let diff_vec = unsafe { _mm256_loadu_si256(diff.as_ptr() as *const __m256i) };
                    let reduced = mul_const_reduce_i32x8(diff_vec, zeta);
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
    #[target_feature(enable = "avx2")]
    unsafe fn mul_const_reduce_i32x8(src: __m256i, zeta: i32) -> [i32; 8] {
        let vzeta = _mm256_set1_epi32(zeta);
        mul_reduce_i32x8(src, vzeta)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn mul_reduce_i32x8(lhs: __m256i, rhs: __m256i) -> [i32; 8] {
        let even_prod = _mm256_mul_epi32(lhs, rhs);
        let lhs_odd = _mm256_srli_epi64(lhs, 32);
        let rhs_odd = _mm256_srli_epi64(rhs, 32);
        let odd_prod = _mm256_mul_epi32(lhs_odd, rhs_odd);

        let mut even = [0i64; 4];
        let mut odd = [0i64; 4];
        unsafe {
            _mm256_storeu_si256(even.as_mut_ptr() as *mut __m256i, even_prod);
            _mm256_storeu_si256(odd.as_mut_ptr() as *mut __m256i, odd_prod);
        }

        let mut out = [0i32; 8];
        for lane in 0..4 {
            out[2 * lane] = dsa::montgomery_reduce(even[lane]);
            out[2 * lane + 1] = dsa::montgomery_reduce(odd[lane]);
        }
        out
    }
}
