//! HQC parameter bundles aligned with the local pre-standard reference material
//! tracked by this repository.
//!
//! The current constants intentionally match the local `HQC-Round4-FIPS_207`
//! reference bundle. Newer HQC draft/specification snapshots, including the
//! August 2025 publication, advertise different serialized sizes and shared-key
//! lengths. Consumers should treat these values as tied to the bundled
//! reference lineage until NIST finalizes FIPS 207.

use tafrah_traits::Error;

#[derive(Debug, Clone, Copy)]
/// Validated HQC parameter bundle.
pub struct Params {
    /// Claimed NIST security level.
    pub nist_level: usize,
    /// Code length.
    pub n: usize,
    /// Reed-Solomon length.
    pub n1: usize,
    /// Reed-Solomon dimension companion parameter.
    pub n2: usize,
    /// Product `n1 * n2`, rounded as used by the reference implementation.
    pub n1n2: usize,
    /// Hamming weight of the secret vector.
    pub omega: usize,
    /// Hamming weight of the error vector.
    pub omega_e: usize,
    /// Hamming weight of the randomness vector.
    pub omega_r: usize,
    /// Message length in bytes.
    pub k: usize,
    /// Reed-Muller parameter.
    pub delta: usize,
    /// BCH/FFT helper parameter.
    pub g: usize,
    /// FFT depth parameter.
    pub fft: usize,
    /// Reed-Solomon generator polynomial coefficients.
    pub rs_poly: &'static [u16],
    /// Seed length in bytes.
    pub seed_bytes: usize,
    /// Salt length in bytes.
    pub salt_bytes: usize,
    /// Serialized public-key length in bytes.
    pub pk_bytes: usize,
    /// Serialized secret-key length in bytes.
    pub sk_bytes: usize,
    /// Serialized ciphertext length in bytes.
    pub ct_bytes: usize,
    /// Shared-secret length in bytes.
    pub ss_bytes: usize,
    /// Human-readable algorithm name.
    pub alg_name: &'static str,
}

const fn ceil_divide(a: usize, b: usize) -> usize {
    (a / b) + if a % b == 0 { 0 } else { 1 }
}

impl Params {
    /// Returns `true` if this parameter bundle matches one of the supported sets.
    pub const fn is_valid(&self) -> bool {
        matches!(
            (
                self.nist_level,
                self.n,
                self.n1,
                self.n2,
                self.n1n2,
                self.omega,
                self.omega_e,
                self.omega_r,
                self.k,
                self.delta,
                self.g,
                self.fft,
                self.seed_bytes,
                self.salt_bytes,
                self.pk_bytes,
                self.sk_bytes,
                self.ct_bytes,
                self.ss_bytes,
            ),
            (128, 17669, 46, 384, 17664, 66, 75, 75, 16, 15, 31, 4, 40, 16, 2249, 2289, 4497, 64)
                | (
                    192, 35851, 56, 640, 35840, 100, 114, 114, 24, 16, 33, 5, 40, 16, 4522, 4562,
                    9042, 64
                )
                | (
                    256, 57637, 90, 640, 57600, 131, 149, 149, 32, 29, 59, 5, 40, 16, 7245, 7285,
                    14485, 64
                )
        )
    }

    /// Validates the parameter bundle against the supported HQC sets.
    pub fn validate(&self) -> Result<(), Error> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(Error::InvalidParameter)
        }
    }

    pub const fn vec_n_size_bytes(&self) -> usize {
        ceil_divide(self.n, 8)
    }

    pub const fn vec_k_size_bytes(&self) -> usize {
        self.k
    }

    pub const fn vec_n1_size_bytes(&self) -> usize {
        self.n1
    }

    pub const fn vec_n1n2_size_bytes(&self) -> usize {
        ceil_divide(self.n1n2, 8)
    }

    pub const fn vec_n_size_u64(&self) -> usize {
        ceil_divide(self.n, 64)
    }

    pub const fn vec_k_size_u64(&self) -> usize {
        ceil_divide(self.k, 8)
    }

    pub const fn vec_n1_size_u64(&self) -> usize {
        ceil_divide(self.n1, 8)
    }

    pub const fn vec_n1n2_size_u64(&self) -> usize {
        ceil_divide(self.n1n2, 64)
    }

    pub const fn red_mask(&self) -> u64 {
        let remainder = self.n % 64;
        if remainder == 0 {
            u64::MAX
        } else {
            (1u64 << remainder) - 1
        }
    }
}

const HQC_128_RS_POLY: &[u16] = &[
    89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118,
    105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
];

const HQC_192_RS_POLY: &[u16] = &[
    45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
    238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
];

const HQC_256_RS_POLY: &[u16] = &[
    49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201,
    115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191,
    144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
];

/// HQC-128 parameter bundle.
pub const HQC_128: Params = Params {
    nist_level: 128,
    n: 17_669,
    n1: 46,
    n2: 384,
    n1n2: 17_664,
    omega: 66,
    omega_e: 75,
    omega_r: 75,
    k: 16,
    delta: 15,
    g: 31,
    fft: 4,
    rs_poly: HQC_128_RS_POLY,
    seed_bytes: 40,
    salt_bytes: 16,
    pk_bytes: 2249,
    sk_bytes: 2289,
    ct_bytes: 4497,
    ss_bytes: 64,
    alg_name: "HQC-128",
};

/// HQC-192 parameter bundle.
pub const HQC_192: Params = Params {
    nist_level: 192,
    n: 35_851,
    n1: 56,
    n2: 640,
    n1n2: 35_840,
    omega: 100,
    omega_e: 114,
    omega_r: 114,
    k: 24,
    delta: 16,
    g: 33,
    fft: 5,
    rs_poly: HQC_192_RS_POLY,
    seed_bytes: 40,
    salt_bytes: 16,
    pk_bytes: 4522,
    sk_bytes: 4562,
    ct_bytes: 9042,
    ss_bytes: 64,
    alg_name: "HQC-192",
};

/// HQC-256 parameter bundle.
pub const HQC_256: Params = Params {
    nist_level: 256,
    n: 57_637,
    n1: 90,
    n2: 640,
    n1n2: 57_600,
    omega: 131,
    omega_e: 149,
    omega_r: 149,
    k: 32,
    delta: 29,
    g: 59,
    fft: 5,
    rs_poly: HQC_256_RS_POLY,
    seed_bytes: 40,
    salt_bytes: 16,
    pk_bytes: 7245,
    sk_bytes: 7285,
    ct_bytes: 14485,
    ss_bytes: 64,
    alg_name: "HQC-256",
};
