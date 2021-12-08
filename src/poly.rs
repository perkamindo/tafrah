/// Polynomial operations for ML-KEM over `Zq\[X]/(X^256+1)`, `q = 3329`.
pub mod kem {
    use crate::field::kem;
    use crate::ntt::kem as ntt;

    pub const N: usize = 256;

    #[derive(Clone)]
    pub struct Poly {
        pub coeffs: [i16; N],
    }

    impl Poly {
        pub fn zero() -> Self {
            Poly { coeffs: [0i16; N] }
        }

        pub fn add(&self, other: &Poly) -> Poly {
            let mut result = Poly::zero();
            for i in 0..N {
                result.coeffs[i] = self.coeffs[i] + other.coeffs[i];
            }
            result
        }

        pub fn sub(&self, other: &Poly) -> Poly {
            let mut result = Poly::zero();
            for i in 0..N {
                result.coeffs[i] = self.coeffs[i] - other.coeffs[i];
            }
            result
        }

        pub fn add_assign(&mut self, other: &Poly) {
            for i in 0..N {
                self.coeffs[i] += other.coeffs[i];
            }
        }

        pub fn ntt(&mut self) {
            ntt::ntt(&mut self.coeffs);
            self.reduce();
        }

        pub fn inv_ntt(&mut self) {
            ntt::inv_ntt(&mut self.coeffs);
        }

        /// Pointwise multiplication in NTT domain (Montgomery)
        pub fn basemul_montgomery(&self, other: &Poly) -> Poly {
            let mut result = Poly::zero();
            ntt::poly_basemul_montgomery(&mut result.coeffs, &self.coeffs, &other.coeffs);
            result
        }

        /// Reduce all coefficients via Barrett
        pub fn reduce(&mut self) {
            for coeff in self.coeffs.iter_mut() {
                *coeff = kem::barrett_reduce(*coeff);
            }
        }

        /// Convert to Montgomery domain: multiply each coefficient by R
        /// Uses f = (2^32) mod q = R^2 mod q = 1353
        /// Since fqmul(a, f) = a * f * R^{-1} = a * R^2 * R^{-1} = a * R
        pub fn tomont(&mut self) {
            const F: i16 = 1353; // (1u64 << 32) % 3329 = R^2 mod q
            for coeff in self.coeffs.iter_mut() {
                *coeff = kem::fqmul(*coeff, F);
            }
        }
    }

    impl Default for Poly {
        fn default() -> Self {
            Self::zero()
        }
    }
}

/// Polynomial operations for ML-DSA over `Zq\[X]/(X^256+1)`, `q = 8380417`.
pub mod dsa {
    use crate::field::dsa;
    use crate::ntt::dsa as ntt;

    pub const N: usize = 256;

    #[derive(Clone)]
    pub struct Poly {
        pub coeffs: [i32; N],
    }

    impl Poly {
        pub fn zero() -> Self {
            Poly { coeffs: [0i32; N] }
        }

        pub fn add(&self, other: &Poly) -> Poly {
            let mut result = Poly::zero();
            for i in 0..N {
                result.coeffs[i] = self.coeffs[i] + other.coeffs[i];
            }
            result
        }

        pub fn sub(&self, other: &Poly) -> Poly {
            let mut result = Poly::zero();
            for i in 0..N {
                result.coeffs[i] = self.coeffs[i] - other.coeffs[i];
            }
            result
        }

        pub fn add_assign(&mut self, other: &Poly) {
            for i in 0..N {
                self.coeffs[i] += other.coeffs[i];
            }
        }

        pub fn ntt(&mut self) {
            ntt::ntt(&mut self.coeffs);
        }

        pub fn inv_ntt(&mut self) {
            ntt::inv_ntt(&mut self.coeffs);
        }

        pub fn pointwise_mul(&self, other: &Poly) -> Poly {
            let mut result = Poly::zero();
            ntt::pointwise_mul(&self.coeffs, &other.coeffs, &mut result.coeffs);
            result
        }

        /// Reduce all coefficients (Barrett-like, centered around 0)
        /// From pq-crystals/dilithium/ref/poly.c: poly_reduce()
        pub fn reduce(&mut self) {
            for coeff in self.coeffs.iter_mut() {
                *coeff = dsa::reduce32(*coeff);
            }
        }

        /// Conditional add q
        pub fn caddq(&mut self) {
            for coeff in self.coeffs.iter_mut() {
                *coeff = dsa::caddq(*coeff);
            }
        }

        /// Check if infinity norm of polynomial is < bound
        pub fn check_norm(&self, bound: i32) -> bool {
            for &c in self.coeffs.iter() {
                let mut t = c;
                // Reduce to centered representation
                t -= (t >> 31) & (2 * t); // abs
                if t >= bound {
                    return false;
                }
            }
            true
        }
    }

    impl Default for Poly {
        fn default() -> Self {
            Self::zero()
        }
    }
}
