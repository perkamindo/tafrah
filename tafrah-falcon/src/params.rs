use tafrah_traits::Error;

const MAX_FG_BITS: [u8; 11] = [0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5];
const MAX_CAPITAL_FG_BITS: [u8; 11] = [0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];

#[derive(Debug, Clone, Copy)]
/// Validated Falcon parameter bundle.
pub struct Params {
    /// Base-2 logarithm of the Falcon lattice dimension.
    pub log_n: usize,
    /// Falcon lattice dimension.
    pub n: usize,
    /// Serialized public-key length in bytes.
    pub pk_bytes: usize,
    /// Serialized secret-key length in bytes.
    pub sk_bytes: usize,
    /// Maximum detached NIST-style signature size:
    /// 2-byte encoded signature length || 40-byte nonce || compressed signature.
    pub sig_max_bytes: usize,
    pub alg_name: &'static str,
}

impl Params {
    /// Returns `true` if this parameter bundle matches one of the supported sets.
    pub const fn is_valid(&self) -> bool {
        matches!(
            (
                self.log_n,
                self.n,
                self.pk_bytes,
                self.sk_bytes,
                self.sig_max_bytes,
            ),
            (9, 512, 897, 1281, 690) | (10, 1024, 1793, 2305, 1330)
        )
    }

    /// Validates the parameter bundle against the supported Falcon sets.
    pub fn validate(&self) -> Result<(), Error> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(Error::InvalidParameter)
        }
    }

    pub(crate) fn pk_tag(&self) -> u8 {
        self.log_n as u8
    }

    pub(crate) fn sk_tag(&self) -> u8 {
        0x50 + self.log_n as u8
    }

    pub(crate) fn sig_tag(&self) -> u8 {
        0x20 + self.log_n as u8
    }

    pub(crate) fn fg_bits(&self) -> u32 {
        MAX_FG_BITS[self.log_n] as u32
    }

    pub(crate) fn capital_fg_bits(&self) -> u32 {
        MAX_CAPITAL_FG_BITS[self.log_n] as u32
    }
}

/// Falcon-512 parameter bundle.
pub const FALCON_512: Params = Params {
    log_n: 9,
    n: 512,
    pk_bytes: 897,
    sk_bytes: 1281,
    sig_max_bytes: 690,
    alg_name: "Falcon-512",
};

/// Falcon-1024 parameter bundle.
pub const FALCON_1024: Params = Params {
    log_n: 10,
    n: 1024,
    pk_bytes: 1793,
    sk_bytes: 2305,
    sig_max_bytes: 1330,
    alg_name: "Falcon-1024",
};
