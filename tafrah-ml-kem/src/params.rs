use tafrah_traits::Error;

/// ML-KEM parameter sets (FIPS 203, Table 1)
#[derive(Debug, Clone, Copy)]
/// Validated ML-KEM parameter bundle.
pub struct Params {
    /// Rank parameter.
    pub k: usize,
    /// Noise parameter for key generation.
    pub eta1: usize,
    /// Noise parameter for encapsulation.
    pub eta2: usize,
    /// Compression width for `u`.
    pub du: u32,
    /// Compression width for `v`.
    pub dv: u32,
    /// Byte length of eta1 CBD input: 64 * eta1
    pub eta1_bytes: usize,
    /// Byte length of eta2 CBD input: 64 * eta2
    pub eta2_bytes: usize,
}

/// FIPS 203 ML-KEM-512 parameter bundle.
pub const ML_KEM_512: Params = Params {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    eta1_bytes: 192, // 64 * 3
    eta2_bytes: 128, // 64 * 2
};

/// FIPS 203 ML-KEM-768 parameter bundle.
pub const ML_KEM_768: Params = Params {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    eta1_bytes: 128,
    eta2_bytes: 128,
};

/// FIPS 203 ML-KEM-1024 parameter bundle.
pub const ML_KEM_1024: Params = Params {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    eta1_bytes: 128,
    eta2_bytes: 128,
};

impl Params {
    /// Returns `true` if this parameter bundle matches one of the supported sets.
    pub const fn is_valid(&self) -> bool {
        matches!(
            (
                self.k,
                self.eta1,
                self.eta2,
                self.du,
                self.dv,
                self.eta1_bytes,
                self.eta2_bytes,
            ),
            (2, 3, 2, 10, 4, 192, 128)
                | (3, 2, 2, 10, 4, 128, 128)
                | (4, 2, 2, 11, 5, 128, 128)
        )
    }

    /// Validates the parameter bundle against the supported ML-KEM sets.
    pub fn validate(&self) -> Result<(), Error> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(Error::InvalidParameter)
        }
    }

    /// Size of encapsulation key in bytes
    pub const fn ek_size(&self) -> usize {
        384 * self.k + 32
    }

    /// Size of decapsulation key in bytes
    pub const fn dk_size(&self) -> usize {
        768 * self.k + 96
    }

    /// Size of ciphertext in bytes
    pub const fn ct_size(&self) -> usize {
        32 * (self.du as usize * self.k + self.dv as usize)
    }
}
