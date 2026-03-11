use tafrah_traits::Error;

/// ML-DSA parameter sets (FIPS 204, Table 1)
#[derive(Debug, Clone, Copy)]
/// Validated ML-DSA parameter bundle.
pub struct Params {
    /// Number of rows in the public matrix.
    pub k: usize,
    /// Number of columns in the public matrix.
    pub l: usize,
    /// Small-noise parameter.
    pub eta: usize,
    /// Challenge weight.
    pub tau: usize,
    /// Norm bound for `z`.
    pub gamma1: i32,
    /// Bit width used by `gamma1`.
    pub gamma1_bits: u32,
    /// Rounding parameter.
    pub gamma2: i32,
    /// Rejection bound.
    pub beta: i32,
    /// Maximum number of hint bits.
    pub omega: usize,
    pub d: u32, // dropped bits in t
    /// Challenge hash output length in bytes
    pub c_tilde_bytes: usize,
}

impl Params {
    /// Returns `true` if this parameter bundle matches one of the supported sets.
    pub const fn is_valid(&self) -> bool {
        matches!(
            (
                self.k,
                self.l,
                self.eta,
                self.tau,
                self.gamma1,
                self.gamma1_bits,
                self.gamma2,
                self.beta,
                self.omega,
                self.d,
                self.c_tilde_bytes,
            ),
            (4, 4, 2, 39, 131072, 17, 95232, 78, 80, 13, 32)
                | (6, 5, 4, 49, 524288, 19, 261888, 196, 55, 13, 48)
                | (8, 7, 2, 60, 524288, 19, 261888, 120, 75, 13, 64)
        )
    }

    /// Validates the parameter bundle against the supported ML-DSA sets.
    pub fn validate(&self) -> Result<(), Error> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(Error::InvalidParameter)
        }
    }

    pub const fn eta_bytes(&self) -> usize {
        match self.eta {
            2 => 96,
            4 => 128,
            _ => 0,
        }
    }

    pub const fn z_bytes(&self) -> usize {
        match self.gamma1_bits {
            17 => 576,
            19 => 640,
            _ => 0,
        }
    }

    pub const fn sk_size(&self) -> usize {
        128 + (self.l + self.k) * self.eta_bytes() + self.k * 416
    }

    pub const fn vk_size(&self) -> usize {
        32 + 320 * self.k
    }

    pub const fn sig_size(&self) -> usize {
        self.c_tilde_bytes + self.l * self.z_bytes() + self.omega + self.k
    }
}

/// ML-DSA modulus.
pub const Q: i32 = 8380417;

/// FIPS 204 ML-DSA-44 parameter bundle.
pub const ML_DSA_44: Params = Params {
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    gamma1: 1 << 17, // 2^17 = 131072
    gamma1_bits: 17,
    gamma2: (Q - 1) / 88, // 95232
    beta: 78,             // tau * eta = 39 * 2
    omega: 80,
    d: 13,
    c_tilde_bytes: 32,
};

/// FIPS 204 ML-DSA-65 parameter bundle.
pub const ML_DSA_65: Params = Params {
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    gamma1: 1 << 19, // 2^19 = 524288
    gamma1_bits: 19,
    gamma2: (Q - 1) / 32, // 261888
    beta: 196,            // tau * eta = 49 * 4
    omega: 55,
    d: 13,
    c_tilde_bytes: 48,
};

/// FIPS 204 ML-DSA-87 parameter bundle.
pub const ML_DSA_87: Params = Params {
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    gamma1: 1 << 19, // 2^19
    gamma1_bits: 19,
    gamma2: (Q - 1) / 32, // 261888
    beta: 120,            // tau * eta = 60 * 2
    omega: 75,
    d: 13,
    c_tilde_bytes: 64,
};
