use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

use tafrah_slh_dsa::keygen::{slh_dsa_keygen, slh_keygen_internal};
use tafrah_slh_dsa::params::{Params, SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_128F};
use tafrah_slh_dsa::prehash::{hash_slh_sign, hash_slh_verify, PrehashAlgorithm};
use tafrah_slh_dsa::sign::{slh_sign, slh_sign_internal};
use tafrah_slh_dsa::verify::{slh_verify, slh_verify_internal};
use tafrah_traits::Error;

struct SliceRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl SliceRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl TryRng for SliceRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.offset + dest.len();
        dest.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for SliceRng {}

fn fixed_keypair(
    params: &Params,
) -> (
    tafrah_slh_dsa::types::VerifyingKey,
    tafrah_slh_dsa::types::SigningKey,
) {
    let n = params.n;
    let seed_material: Vec<u8> = (0..(3 * n)).map(|i| (i as u8).wrapping_mul(17)).collect();
    slh_keygen_internal(
        &seed_material[..n],
        &seed_material[n..2 * n],
        &seed_material[2 * n..3 * n],
        params,
    )
    .unwrap()
}

#[test]
fn test_slh_keygen_internal_matches_rng_wrapper() {
    let params = SLH_DSA_SHAKE_128F;
    let n = params.n;
    let seed_material: Vec<u8> = (0..(3 * n)).map(|i| (255 - i) as u8).collect();

    let mut rng = SliceRng::new(seed_material.clone());
    let (vk_rng, sk_rng) = slh_dsa_keygen(&mut rng, &params).unwrap();
    let (vk_det, sk_det) = slh_keygen_internal(
        &seed_material[..n],
        &seed_material[n..2 * n],
        &seed_material[2 * n..3 * n],
        &params,
    )
    .unwrap();

    assert_eq!(vk_rng.as_bytes(), vk_det.as_bytes());
    assert_eq!(sk_rng.as_bytes(), sk_det.as_bytes());
}

#[test]
fn test_slh_internal_deterministic_and_randomized_modes() {
    let params = SLH_DSA_SHAKE_128F;
    let (vk, sk) = fixed_keypair(&params);
    let msg = b"SLH-DSA internal deterministic mode";
    let pk_seed = &sk.as_bytes()[2 * params.n..3 * params.n];
    let addrnd = vec![0xA5; params.n];

    let sig_deterministic_a = slh_sign_internal(&sk, msg, None, &params).unwrap();
    let sig_deterministic_b = slh_sign_internal(&sk, msg, None, &params).unwrap();
    let sig_with_pk_seed = slh_sign_internal(&sk, msg, Some(pk_seed), &params).unwrap();
    let sig_randomized = slh_sign_internal(&sk, msg, Some(&addrnd), &params).unwrap();

    assert_eq!(
        sig_deterministic_a.as_bytes(),
        sig_deterministic_b.as_bytes()
    );
    assert_eq!(sig_deterministic_a.as_bytes(), sig_with_pk_seed.as_bytes());
    assert_ne!(sig_deterministic_a.as_bytes(), sig_randomized.as_bytes());

    slh_verify_internal(&vk, msg, &sig_deterministic_a, &params).unwrap();
    slh_verify_internal(&vk, msg, &sig_randomized, &params).unwrap();
}

#[test]
fn test_slh_pure_context_roundtrip_and_domain_separation() {
    let params = SLH_DSA_SHA2_128F;
    let (vk, sk) = fixed_keypair(&params);
    let msg = b"SLH-DSA pure mode with context";
    let ctx = b"tafrah-ctx";

    let pure_sig = slh_sign(&sk, msg, ctx, None, &params).unwrap();
    let pure_sig_again = slh_sign(&sk, msg, ctx, None, &params).unwrap();
    let internal_sig = slh_sign_internal(&sk, msg, None, &params).unwrap();

    assert_eq!(pure_sig.as_bytes(), pure_sig_again.as_bytes());
    assert_ne!(pure_sig.as_bytes(), internal_sig.as_bytes());

    slh_verify(&vk, msg, &pure_sig, ctx, &params).unwrap();
    assert_eq!(
        slh_verify(&vk, msg, &pure_sig, b"wrong-ctx", &params),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        slh_verify_internal(&vk, msg, &pure_sig, &params),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn test_hash_slh_supports_all_prehash_algorithms() {
    let algorithms = [
        PrehashAlgorithm::Sha2_224,
        PrehashAlgorithm::Sha2_256,
        PrehashAlgorithm::Sha2_384,
        PrehashAlgorithm::Sha2_512,
        PrehashAlgorithm::Sha2_512_224,
        PrehashAlgorithm::Sha2_512_256,
        PrehashAlgorithm::Sha3_224,
        PrehashAlgorithm::Sha3_256,
        PrehashAlgorithm::Sha3_384,
        PrehashAlgorithm::Sha3_512,
        PrehashAlgorithm::Shake128,
        PrehashAlgorithm::Shake256,
    ];
    let params_sets = [SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_128F];

    for params in params_sets {
        let (vk, sk) = fixed_keypair(&params);
        for algorithm in algorithms {
            let msg = format!("HashSLH proof {}", algorithm.identifier());
            let sig = hash_slh_sign(
                &sk,
                msg.as_bytes(),
                b"prehash-ctx",
                algorithm,
                None,
                &params,
            )
            .unwrap();
            hash_slh_verify(
                &vk,
                msg.as_bytes(),
                &sig,
                b"prehash-ctx",
                algorithm,
                &params,
            )
            .unwrap();
            assert_eq!(
                hash_slh_verify(&vk, b"tampered", &sig, b"prehash-ctx", algorithm, &params),
                Err(Error::VerificationFailed)
            );
        }
    }
}

#[test]
fn test_slh_new_apis_reject_invalid_context_and_randomness_lengths() {
    let params = SLH_DSA_SHAKE_128F;
    let (vk, sk) = fixed_keypair(&params);
    let msg = b"rejection path";
    let sig = slh_sign_internal(&sk, msg, None, &params).unwrap();
    let long_ctx = vec![0u8; 256];
    let short_addrnd = vec![0u8; params.n - 1];

    assert!(matches!(
        slh_sign(&sk, msg, &long_ctx, None, &params),
        Err(Error::InvalidParameter)
    ));
    assert_eq!(
        slh_verify(&vk, msg, &sig, &long_ctx, &params),
        Err(Error::InvalidParameter)
    );
    assert!(matches!(
        hash_slh_sign(
            &sk,
            msg,
            &long_ctx,
            PrehashAlgorithm::Sha2_256,
            None,
            &params
        ),
        Err(Error::InvalidParameter)
    ));
    assert!(matches!(
        slh_sign_internal(&sk, msg, Some(&short_addrnd), &params),
        Err(Error::InvalidParameter)
    ));
}
