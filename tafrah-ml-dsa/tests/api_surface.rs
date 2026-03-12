use tafrah_ml_dsa::keygen::ml_dsa_keygen_internal;
use tafrah_ml_dsa::params::ML_DSA_44;
use tafrah_ml_dsa::prehash::{build_prehash_prefix, shake256_prehash, PreHashAlgorithm};
use tafrah_ml_dsa::sign::{
    ml_dsa_sign_deterministic_with_context, ml_dsa_sign_extmu_deterministic, ml_dsa_sign_internal,
    ml_dsa_sign_message_deterministic_with_context, ml_dsa_sign_prehash_deterministic,
    ml_dsa_sign_prehash_internal, ml_dsa_sign_prehash_shake256_deterministic, ML_DSA_RNDBYTES,
};
use tafrah_ml_dsa::verify::{
    ml_dsa_open_signed_message_with_context, ml_dsa_verify_extmu, ml_dsa_verify_internal,
    ml_dsa_verify_prehash, ml_dsa_verify_prehash_shake256, ml_dsa_verify_with_context,
};

fn fixed_seed() -> [u8; 32] {
    [0x42; 32]
}

fn zero_rnd() -> [u8; ML_DSA_RNDBYTES] {
    [0u8; ML_DSA_RNDBYTES]
}

fn pure_prefix(ctx: &[u8]) -> Vec<u8> {
    let mut prefix = vec![0u8; 2 + ctx.len()];
    prefix[1] = ctx.len() as u8;
    prefix[2..].copy_from_slice(ctx);
    prefix
}

fn digest_for(alg: PreHashAlgorithm) -> Vec<u8> {
    vec![0xA5; alg.digest_len()]
}

#[test]
fn test_keygen_internal_is_deterministic() {
    let (vk1, sk1) = ml_dsa_keygen_internal(&fixed_seed(), &ML_DSA_44).unwrap();
    let (vk2, sk2) = ml_dsa_keygen_internal(&fixed_seed(), &ML_DSA_44).unwrap();
    assert_eq!(vk1.as_bytes(), vk2.as_bytes());
    assert_eq!(sk1.as_bytes(), sk2.as_bytes());
}

#[test]
fn test_deterministic_sign_matches_internal_pure_path() {
    let (vk, sk) = ml_dsa_keygen_internal(&fixed_seed(), &ML_DSA_44).unwrap();
    let msg = b"tafrah-mldsa-deterministic";
    let ctx = b"ctx";

    let detached = ml_dsa_sign_deterministic_with_context(&sk, msg, ctx, &ML_DSA_44).unwrap();
    let pre = pure_prefix(ctx);
    let internal = ml_dsa_sign_internal(&sk, msg, &pre, &zero_rnd(), false, &ML_DSA_44).unwrap();

    assert_eq!(detached.as_bytes(), internal.as_bytes());
    ml_dsa_verify_with_context(&vk, msg, &detached, ctx, &ML_DSA_44).unwrap();
    ml_dsa_verify_internal(&vk, msg, &internal, &pre, false, &ML_DSA_44).unwrap();
}

#[test]
fn test_extmu_deterministic_roundtrip_matches_internal_path() {
    let (vk, sk) = ml_dsa_keygen_internal(&fixed_seed(), &ML_DSA_44).unwrap();
    let mu = [0x5Au8; 64];

    let detached = ml_dsa_sign_extmu_deterministic(&sk, &mu, &ML_DSA_44).unwrap();
    let internal = ml_dsa_sign_internal(&sk, &mu, &[], &zero_rnd(), true, &ML_DSA_44).unwrap();

    assert_eq!(detached.as_bytes(), internal.as_bytes());
    ml_dsa_verify_extmu(&vk, &mu, &detached, &ML_DSA_44).unwrap();
}

#[test]
fn test_prehash_all_algorithms_roundtrip() {
    let (vk, sk) = ml_dsa_keygen_internal(&fixed_seed(), &ML_DSA_44).unwrap();
    let ctx = b"hash-ctx";
    let algorithms = [
        PreHashAlgorithm::Sha2_224,
        PreHashAlgorithm::Sha2_256,
        PreHashAlgorithm::Sha2_384,
        PreHashAlgorithm::Sha2_512,
        PreHashAlgorithm::Sha2_512_224,
        PreHashAlgorithm::Sha2_512_256,
        PreHashAlgorithm::Sha3_224,
        PreHashAlgorithm::Sha3_256,
        PreHashAlgorithm::Sha3_384,
        PreHashAlgorithm::Sha3_512,
        PreHashAlgorithm::Shake128,
        PreHashAlgorithm::Shake256,
    ];

    for alg in algorithms {
        let digest = digest_for(alg);
        let sig = ml_dsa_sign_prehash_deterministic(&sk, &digest, ctx, alg, &ML_DSA_44).unwrap();
        ml_dsa_verify_prehash(&vk, &digest, &sig, ctx, alg, &ML_DSA_44).unwrap();

        let (pre, prelen) = build_prehash_prefix(&digest, ctx, alg).unwrap();
        let internal =
            ml_dsa_sign_prehash_internal(&sk, &digest, ctx, &zero_rnd(), alg, &ML_DSA_44).unwrap();
        assert_eq!(sig.as_bytes(), internal.as_bytes());
        ml_dsa_verify_internal(&vk, &pre[..prelen], &sig, &[], false, &ML_DSA_44).unwrap();
    }
}

#[test]
fn test_shake256_prehash_convenience_matches_internal_digest_path() {
    let (vk, sk) = ml_dsa_keygen_internal(&fixed_seed(), &ML_DSA_44).unwrap();
    let msg = b"hashml-dsa::shake256";
    let ctx = b"shake-ctx";
    let digest = shake256_prehash(msg);

    let sig = ml_dsa_sign_prehash_shake256_deterministic(&sk, msg, ctx, &ML_DSA_44).unwrap();
    let expected = ml_dsa_sign_prehash_deterministic(
        &sk,
        &digest,
        ctx,
        PreHashAlgorithm::Shake256,
        &ML_DSA_44,
    )
    .unwrap();

    assert_eq!(sig.as_bytes(), expected.as_bytes());
    ml_dsa_verify_prehash_shake256(&vk, msg, &sig, ctx, &ML_DSA_44).unwrap();
}

#[test]
fn test_signed_message_open_roundtrip() {
    let (vk, sk) = ml_dsa_keygen_internal(&fixed_seed(), &ML_DSA_44).unwrap();
    let msg = b"tafrah::signed-message";
    let ctx = b"sm-ctx";

    let signed = ml_dsa_sign_message_deterministic_with_context(&sk, msg, ctx, &ML_DSA_44).unwrap();
    let opened = ml_dsa_open_signed_message_with_context(&vk, &signed, ctx, &ML_DSA_44).unwrap();

    assert_eq!(opened.as_slice(), msg);
}
