//! Generic Falcon key generation entry point.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::fft::{
    fft, ifft, poly_adj_fft, poly_invnorm2_fft, poly_mul_autoadj_fft, poly_mulconst,
    smallints_to_fpr,
};
use crate::fpr::{fpr_add, fpr_lt, fpr_sqr, Fpr, GmTable, BNORM_MAX, Q};
use crate::key_material::{encode_signing_key, encode_verifying_key};
use crate::mq::compute_public_from_small;
use crate::ntru::solve_ntru;
use crate::params::Params;
use crate::types::{SigningKey, VerifyingKey};
use tafrah_traits::Error;

const GAUSS_1024_12289: [u64; 27] = [
    1283868770400643928,
    6416574995475331444,
    4078260278032692663,
    2353523259288686585,
    1227179971273316331,
    575931623374121527,
    242543240509105209,
    91437049221049666,
    30799446349977173,
    9255276791179340,
    2478152334826140,
    590642893610164,
    125206034929641,
    23590435911403,
    3948334035941,
    586753615614,
    77391054539,
    9056793210,
    940121950,
    86539696,
    7062824,
    510971,
    32764,
    1862,
    94,
    4,
    0,
];

#[derive(Clone)]
struct PreNtruCandidate {
    f: Vec<i8>,
    g: Vec<i8>,
    h: Vec<u16>,
}

fn get_rng_u64<R: XofReader>(rng: &mut R) -> u64 {
    let mut tmp = [0u8; 8];
    rng.read(&mut tmp);
    u64::from_le_bytes(tmp)
}

fn mkgauss<R: XofReader>(rng: &mut R, logn: usize) -> i32 {
    let g = 1usize << (10 - logn);
    let mut val = 0i32;

    for _ in 0..g {
        let mut r = get_rng_u64(rng);
        let neg = (r >> 63) as u32;
        r &= !(1u64 << 63);
        let mut f = ((r.wrapping_sub(GAUSS_1024_12289[0])) >> 63) as u32;

        let mut v = 0u32;
        r = get_rng_u64(rng);
        r &= !(1u64 << 63);
        for (k, &entry) in GAUSS_1024_12289.iter().enumerate().skip(1) {
            let t = (((r.wrapping_sub(entry)) >> 63) as u32) ^ 1;
            v |= (k as u32) & 0u32.wrapping_sub(t & (f ^ 1));
            f |= t;
        }

        v = (v ^ neg.wrapping_neg()).wrapping_add(neg);
        val += i32::from_ne_bytes(v.to_ne_bytes());
    }

    val
}

fn poly_small_mkgauss<R: XofReader>(rng: &mut R, logn: usize) -> Vec<i8> {
    let n = 1usize << logn;
    let mut f = vec![0i8; n];
    let mut mod2 = 0u32;

    for u in 0..n {
        loop {
            let s = mkgauss(rng, logn);
            if !(-127..=127).contains(&s) {
                continue;
            }
            if u == n - 1 {
                if (mod2 ^ ((s as u32) & 1)) == 0 {
                    continue;
                }
            } else {
                mod2 ^= (s as u32) & 1;
            }
            f[u] = s as i8;
            break;
        }
    }

    f
}

fn coeffs_fit_fg_bounds(poly: &[i8], params: &Params) -> bool {
    let lim = 1i32 << (params.fg_bits() - 1);
    poly.iter()
        .all(|&value| (value as i32) < lim && (value as i32) > -lim)
}

fn poly_small_sqnorm(poly: &[i8]) -> u32 {
    let mut s = 0u32;
    let mut ng = 0u32;
    for &value in poly {
        let z = value as i32;
        s = s.wrapping_add((z as i64 * z as i64) as u32);
        ng |= s;
    }
    s | 0u32.wrapping_sub(ng >> 31)
}

fn orthogonalized_norm_ok(f: &[i8], g: &[i8], logn: usize) -> bool {
    let n = 1usize << logn;
    let gm = GmTable::new();
    let mut rt1 = smallints_to_fpr(f, logn);
    let mut rt2 = smallints_to_fpr(g, logn);
    let mut rt3 = vec![0.0; n];

    fft(&mut rt1, logn, &gm);
    fft(&mut rt2, logn, &gm);
    poly_invnorm2_fft(&mut rt3, &rt1, &rt2, logn);
    poly_adj_fft(&mut rt1, logn);
    poly_adj_fft(&mut rt2, logn);
    poly_mulconst(&mut rt1, Q);
    poly_mulconst(&mut rt2, Q);
    poly_mul_autoadj_fft(&mut rt1, &rt3, logn);
    poly_mul_autoadj_fft(&mut rt2, &rt3, logn);
    ifft(&mut rt1, logn, &gm);
    ifft(&mut rt2, logn, &gm);

    let mut bnorm: Fpr = 0.0;
    for u in 0..n {
        bnorm = fpr_add(bnorm, fpr_sqr(rt1[u]));
        bnorm = fpr_add(bnorm, fpr_sqr(rt2[u]));
    }
    fpr_lt(bnorm, BNORM_MAX)
}

fn sample_pre_ntru_candidate_from_xof<R: XofReader>(
    reader: &mut R,
    params: &Params,
) -> PreNtruCandidate {
    loop {
        let f = poly_small_mkgauss(reader, params.log_n);
        let g = poly_small_mkgauss(reader, params.log_n);
        if !coeffs_fit_fg_bounds(&f, params) || !coeffs_fit_fg_bounds(&g, params) {
            continue;
        }

        let normf = poly_small_sqnorm(&f);
        let normg = poly_small_sqnorm(&g);
        let norm = normf.wrapping_add(normg) | 0u32.wrapping_sub((normf | normg) >> 31);
        if norm >= 16_823 {
            continue;
        }
        if !orthogonalized_norm_ok(&f, &g, params.log_n) {
            continue;
        }

        let Some(h) = compute_public_from_small(&f, &g, params.log_n) else {
            continue;
        };
        return PreNtruCandidate { f, g, h };
    }
}

#[cfg(test)]
fn sample_pre_ntru_candidate(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<PreNtruCandidate, Error> {
    let mut seed = [0u8; 48];
    rng.fill_bytes(&mut seed);
    let mut hasher = Shake256::default();
    hasher.update(&seed);
    let mut reader = hasher.finalize_xof();
    Ok(sample_pre_ntru_candidate_from_xof(&mut reader, params))
}

/// Generates a Falcon verifying key and signing key pair.
pub fn falcon_keygen(
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<(VerifyingKey, SigningKey), Error> {
    params.validate()?;
    let lim = (1i32 << (params.capital_fg_bits() - 1)) - 1;
    let mut seed = [0u8; 48];

    loop {
        rng.fill_bytes(&mut seed);
        let mut hasher = Shake256::default();
        hasher.update(&seed);
        let mut reader = hasher.finalize_xof();

        loop {
            let candidate = sample_pre_ntru_candidate_from_xof(&mut reader, params);
            let Some((capital_f, _capital_g)) =
                solve_ntru(params.log_n, &candidate.f, &candidate.g, lim)
            else {
                continue;
            };

            let sk = encode_signing_key(&candidate.f, &candidate.g, &capital_f, params)?;
            let vk = encode_verifying_key(&candidate.h, params)?;
            return Ok((vk, sk));
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::borrow::ToOwned;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::string::String;
    use std::vec::Vec;

    use core::convert::Infallible;

    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand_core::{TryCryptoRng, TryRng};

    use crate::derive::falcon_derive_verifying_key;
    use crate::key_material::decode_signing_key;
    use crate::params::{FALCON_1024, FALCON_512};
    use crate::sign::falcon_sign;
    use crate::verify::falcon_verify;

    use super::{
        coeffs_fit_fg_bounds, falcon_keygen, orthogonalized_norm_ok, poly_small_sqnorm,
        sample_pre_ntru_candidate,
    };

    struct FixedBytesRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl FixedBytesRng {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl TryRng for FixedBytesRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut tmp = [0u8; 4];
            self.try_fill_bytes(&mut tmp)?;
            Ok(u32::from_le_bytes(tmp))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut tmp = [0u8; 8];
            self.try_fill_bytes(&mut tmp)?;
            Ok(u64::from_le_bytes(tmp))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            let end = self.offset + dest.len();
            assert!(
                end <= self.bytes.len(),
                "fixed rng exhausted: need {}, have {}",
                dest.len(),
                self.bytes.len().saturating_sub(self.offset)
            );
            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
            Ok(())
        }
    }

    impl TryCryptoRng for FixedBytesRng {}

    fn ref_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("workspace root")
            .join("ref")
    }

    fn ensure_reference_paths(label: &str, paths: &[PathBuf]) -> bool {
        if let Some(missing) = paths.iter().find(|path| !path.exists()) {
            std::eprintln!("skipping {label}: missing {}", missing.display());
            return false;
        }
        true
    }

    fn parse_rsp_entries(path: &Path) -> Vec<BTreeMap<String, String>> {
        let content = fs::read_to_string(path).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", path.display());
        });

        let mut entries = Vec::new();
        let mut current = BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                if current.contains_key("count") {
                    entries.push(core::mem::take(&mut current));
                }
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(" = ") {
                current.insert(key.to_owned(), value.to_owned());
            }
        }
        if current.contains_key("count") {
            entries.push(current);
        }
        entries
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex string has odd length");
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            let text = std::str::from_utf8(pair).unwrap();
            bytes.push(u8::from_str_radix(text, 16).unwrap());
        }
        bytes
    }

    #[test]
    fn test_pre_ntru_candidates_meet_reference_rejection_gates() {
        for params in [&FALCON_512, &FALCON_1024] {
            let mut seed = [0u8; 32];
            seed[0] = params.log_n as u8;
            let mut rng = StdRng::from_seed(seed);
            let candidate = sample_pre_ntru_candidate(&mut rng, params).expect("candidate");

            assert_eq!(candidate.f.len(), params.n);
            assert_eq!(candidate.g.len(), params.n);
            assert_eq!(candidate.h.len(), params.n);
            assert!(coeffs_fit_fg_bounds(&candidate.f, params));
            assert!(coeffs_fit_fg_bounds(&candidate.g, params));
            let norm =
                poly_small_sqnorm(&candidate.f).wrapping_add(poly_small_sqnorm(&candidate.g));
            assert!(norm < 16_823);
            assert!(orthogonalized_norm_ok(
                &candidate.f,
                &candidate.g,
                params.log_n
            ));
            assert_eq!(
                candidate
                    .f
                    .iter()
                    .fold(0i32, |acc, &value| acc + value as i32)
                    & 1,
                1
            );
            assert_eq!(
                candidate
                    .g
                    .iter()
                    .fold(0i32, |acc, &value| acc + value as i32)
                    & 1,
                1
            );
        }
    }

    #[test]
    fn test_falcon_keygen_sign_verify_roundtrip() {
        for params in [&FALCON_512, &FALCON_1024] {
            let mut seed = [0u8; 32];
            seed[0] = 0xA5;
            seed[1] = params.log_n as u8;
            let mut rng = StdRng::from_seed(seed);
            let (vk, sk) = falcon_keygen(&mut rng, params).expect("keygen");
            let derived = falcon_derive_verifying_key(&sk, params).expect("derive vk");
            assert_eq!(derived.bytes, vk.bytes);

            let sig =
                falcon_sign(&sk, b"tafrah falcon keygen proof", &mut rng, params).expect("sign");
            falcon_verify(&vk, b"tafrah falcon keygen proof", &sig, params).expect("verify");
        }
    }

    #[test]
    fn test_falcon1024_keygen_matches_reference_count1_from_single_internal_seed() {
        let path = ref_root()
            .join("Falcon-FIPS_206")
            .join("falcon-round3")
            .join("KAT")
            .join("falcon1024-KAT.rsp");
        if !ensure_reference_paths(
            "Falcon-1024 deterministic keygen reference check",
            std::slice::from_ref(&path),
        ) {
            return;
        }
        let entries = parse_rsp_entries(&path);
        let entry = entries
            .iter()
            .find(|entry| entry.get("count").map(String::as_str) == Some("1"))
            .expect("count=1 entry");
        let expected_pk = hex_decode(entry.get("pk").expect("missing pk"));
        let expected_sk = hex_decode(entry.get("sk").expect("missing sk"));
        let keygen_seed = hex_decode(
            "4B622DE1350119C45A9F2E2EF3DC5DF50A759D138CDFBD64C81CC7CC2F513345D5A45A4CED06403C5557E87113CB30EA",
        );
        let mut rng = FixedBytesRng::new(keygen_seed);
        let (vk, sk) = falcon_keygen(&mut rng, &FALCON_1024).expect("keygen");

        assert_eq!(vk.bytes, expected_pk);
        assert_eq!(sk.bytes, expected_sk);
        let decoded = decode_signing_key(&sk.bytes, &FALCON_1024).expect("decode generated sk");
        let expected = decode_signing_key(&expected_sk, &FALCON_1024).expect("decode reference sk");
        assert_eq!(decoded.f, expected.f);
        assert_eq!(decoded.g, expected.g);
    }
}
