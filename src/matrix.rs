extern crate alloc;
use alloc::vec::Vec;

/// Matrix operations for ML-KEM (matrices of polynomials over `Zq\[X]/(X^256+1)`).
pub mod kem {
    use super::Vec;
    use crate::poly::kem::Poly;

    /// Matrix-vector product: result = A * s (all in NTT domain)
    /// A is k×k, s is a vector of k polynomials
    pub fn mat_vec_mul(a: &[Vec<Poly>], s: &[Poly], k: usize) -> Vec<Poly> {
        let mut result = Vec::with_capacity(k);
        for i in 0..k {
            let mut t = Poly::zero();
            for j in 0..k {
                let product = a[i][j].basemul_montgomery(&s[j]);
                t = t.add(&product);
            }
            result.push(t);
        }
        result
    }

    /// Vector addition
    pub fn vec_add(a: &[Poly], b: &[Poly]) -> Vec<Poly> {
        a.iter().zip(b.iter()).map(|(ai, bi)| ai.add(bi)).collect()
    }

    /// Vector subtraction
    pub fn vec_sub(a: &[Poly], b: &[Poly]) -> Vec<Poly> {
        a.iter().zip(b.iter()).map(|(ai, bi)| ai.sub(bi)).collect()
    }
}

/// Matrix operations for ML-DSA
pub mod dsa {
    use super::Vec;
    use crate::poly::dsa::Poly;

    /// Matrix-vector product in NTT domain
    /// A is k×l matrix, s is vector of l polynomials
    pub fn mat_vec_mul(a: &[Vec<Poly>], s: &[Poly], k: usize, l: usize) -> Vec<Poly> {
        let mut result = Vec::with_capacity(k);
        for i in 0..k {
            let mut t = Poly::zero();
            for j in 0..l {
                let product = a[i][j].pointwise_mul(&s[j]);
                t = t.add(&product);
            }
            result.push(t);
        }
        result
    }

    /// Vector addition
    pub fn vec_add(a: &[Poly], b: &[Poly]) -> Vec<Poly> {
        a.iter().zip(b.iter()).map(|(ai, bi)| ai.add(bi)).collect()
    }

    /// Vector subtraction
    pub fn vec_sub(a: &[Poly], b: &[Poly]) -> Vec<Poly> {
        a.iter().zip(b.iter()).map(|(ai, bi)| ai.sub(bi)).collect()
    }
}
