use tafrah_traits::Error;

/// SLH-DSA parameter sets (FIPS 205)
/// 12 parameter sets: {SHA2, SHAKE} × {128, 192, 256} × {s, f}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Hash family used by a SLH-DSA parameter set.
pub enum HashType {
    Sha2,
    Shake,
}

#[derive(Debug, Clone, Copy)]
/// Validated SLH-DSA parameter bundle.
pub struct Params {
    pub n: usize,    // Security parameter (hash output length in bytes)
    pub h: usize,    // Total tree height
    pub d: usize,    // Number of hypertree layers
    pub hp: usize,   // Height of each layer: h/d
    pub a: usize,    // FORS tree height
    pub k: usize,    // Number of FORS trees
    pub w: usize,    // Winternitz parameter (always 16)
    pub lg_w: usize, // log2(w) = 4
    pub len1: usize, // WOTS+ chain count part 1
    pub len2: usize, // WOTS+ chain count part 2
    pub len: usize,  // Total WOTS+ chains: len1 + len2
    pub hash_type: HashType,
    /// Signature size in bytes
    pub sig_bytes: usize,
    /// Public key size in bytes
    pub pk_bytes: usize,
    /// Secret key size in bytes
    pub sk_bytes: usize,
}

impl Params {
    /// Returns `true` if this parameter bundle matches one of the supported sets.
    pub const fn is_valid(&self) -> bool {
        matches!(
            (
                self.n,
                self.h,
                self.d,
                self.a,
                self.k,
                self.w,
                self.lg_w,
                self.hash_type,
                self.sig_bytes,
                self.pk_bytes,
                self.sk_bytes,
            ),
            (16, 63, 7, 12, 14, 16, 4, HashType::Sha2, 7856, 32, 64)
                | (16, 66, 22, 6, 33, 16, 4, HashType::Sha2, 17088, 32, 64)
                | (24, 63, 7, 14, 17, 16, 4, HashType::Sha2, 16224, 48, 96)
                | (24, 66, 22, 8, 33, 16, 4, HashType::Sha2, 35664, 48, 96)
                | (32, 64, 8, 14, 22, 16, 4, HashType::Sha2, 29792, 64, 128)
                | (32, 68, 17, 9, 35, 16, 4, HashType::Sha2, 49856, 64, 128)
                | (16, 63, 7, 12, 14, 16, 4, HashType::Shake, 7856, 32, 64)
                | (16, 66, 22, 6, 33, 16, 4, HashType::Shake, 17088, 32, 64)
                | (24, 63, 7, 14, 17, 16, 4, HashType::Shake, 16224, 48, 96)
                | (24, 66, 22, 8, 33, 16, 4, HashType::Shake, 35664, 48, 96)
                | (32, 64, 8, 14, 22, 16, 4, HashType::Shake, 29792, 64, 128)
                | (32, 68, 17, 9, 35, 16, 4, HashType::Shake, 49856, 64, 128)
        )
    }

    /// Validates the parameter bundle against the supported SLH-DSA sets.
    pub fn validate(&self) -> Result<(), Error> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(Error::InvalidParameter)
        }
    }

    const fn compute_len1(n: usize) -> usize {
        // len1 = ceil(8n / lg_w) = ceil(8n / 4) = 2n
        2 * n
    }

    const fn compute_len2(_n: usize) -> usize {
        // len2 = floor(log2(len1 * (w-1)) / lg_w) + 1
        // For n=16: len1=32, len1*(w-1)=480, floor(log2(480)/4)+1 = floor(8.9/4)+1 = 3
        // For n=24: len1=48, len1*(w-1)=720, floor(log2(720)/4)+1 = floor(9.49/4)+1 = 3
        // For n=32: len1=64, len1*(w-1)=960, floor(log2(960)/4)+1 = floor(9.9/4)+1 = 3
        3
    }

    #[allow(dead_code)]
    const fn compute_len(n: usize) -> usize {
        Self::compute_len1(n) + Self::compute_len2(n)
    }
}

macro_rules! slh_params {
    ($name:ident, $n:expr, $h:expr, $d:expr, $a:expr, $k:expr, $hash:expr) => {
        pub const $name: Params = {
            let hp = $h / $d;
            let len1 = Params::compute_len1($n);
            let len2 = Params::compute_len2($n);
            let len = len1 + len2;
            // sig_bytes = (1 + k*(1+a) + h + d*len) * n
            let sig_bytes = (1 + $k * (1 + $a) + $h + $d * len) * $n;
            Params {
                n: $n,
                h: $h,
                d: $d,
                hp,
                a: $a,
                k: $k,
                w: 16,
                lg_w: 4,
                len1,
                len2,
                len,
                hash_type: $hash,
                sig_bytes,
                pk_bytes: 2 * $n,
                sk_bytes: 4 * $n,
            }
        };
    };
}

// SHA2 variants
slh_params!(SLH_DSA_SHA2_128S, 16, 63, 7, 12, 14, HashType::Sha2);
slh_params!(SLH_DSA_SHA2_128F, 16, 66, 22, 6, 33, HashType::Sha2);
slh_params!(SLH_DSA_SHA2_192S, 24, 63, 7, 14, 17, HashType::Sha2);
slh_params!(SLH_DSA_SHA2_192F, 24, 66, 22, 8, 33, HashType::Sha2);
slh_params!(SLH_DSA_SHA2_256S, 32, 64, 8, 14, 22, HashType::Sha2);
slh_params!(SLH_DSA_SHA2_256F, 32, 68, 17, 9, 35, HashType::Sha2);

// SHAKE variants
slh_params!(SLH_DSA_SHAKE_128S, 16, 63, 7, 12, 14, HashType::Shake);
slh_params!(SLH_DSA_SHAKE_128F, 16, 66, 22, 6, 33, HashType::Shake);
slh_params!(SLH_DSA_SHAKE_192S, 24, 63, 7, 14, 17, HashType::Shake);
slh_params!(SLH_DSA_SHAKE_192F, 24, 66, 22, 8, 33, HashType::Shake);
slh_params!(SLH_DSA_SHAKE_256S, 32, 64, 8, 14, 22, HashType::Shake);
slh_params!(SLH_DSA_SHAKE_256F, 32, 68, 17, 9, 35, HashType::Shake);
