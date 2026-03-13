use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tafrah::Error;
use tafrah::falcon::falcon_512;
use tafrah::falcon::types::Signature as FalconSignature;
use tafrah::hqc::hqc_128;
use tafrah::hqc::types::Ciphertext as HqcCiphertext;
use tafrah::ml_dsa::params::ML_DSA_65;
use tafrah::ml_dsa::{keygen as ml_dsa_keygen, sign as ml_dsa_sign, verify as ml_dsa_verify};
use tafrah::ml_kem::ml_kem_768;
use tafrah::ml_kem::types::Ciphertext as MlKemCiphertext;
use tafrah::slh_dsa::params::SLH_DSA_SHAKE_128F;
use tafrah::slh_dsa::{keygen, prehash, sign, verify};
use tafrah::{ml_dsa, slh_dsa};

fn json_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn encode_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = [0x5cu8; 64];
    let mut i_key_pad = [0x36u8; 64];
    for i in 0..64 {
        o_key_pad[i] ^= key_block[i];
        i_key_pad[i] ^= key_block[i];
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&i_key_pad);
    inner.extend_from_slice(data);
    let inner_hash = Sha256::digest(&inner);

    let mut outer = Vec::with_capacity(64 + inner_hash.len());
    outer.extend_from_slice(&o_key_pad);
    outer.extend_from_slice(&inner_hash);
    Sha256::digest(&outer).to_vec()
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hmac_sha256(salt, ikm);
    let mut okm = Vec::with_capacity(length);
    let mut block = Vec::new();
    let mut counter = 1u8;
    while okm.len() < length {
        let mut data = block.clone();
        data.extend_from_slice(info);
        data.push(counter);
        block = hmac_sha256(&prk, &data);
        let take = core::cmp::min(block.len(), length - okm.len());
        okm.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    okm
}

fn stream_xor(key: &[u8], nonce: &[u8], label: &[u8], data: &[u8]) -> Vec<u8> {
    let stream = hkdf_sha256(
        key,
        b"tafrah-auth-demo::stream-salt",
        &encode_parts(&[b"tafrah-auth-demo::stream", label, nonce]),
        data.len(),
    );
    data.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect()
}

fn main() {
    let mut rng = rand::rng();

    let (kem_ek, kem_dk) = ml_kem_768::keygen(&mut rng);
    let (kem_ct, kem_client_ss) = ml_kem_768::encapsulate(&kem_ek, &mut rng).expect("ml-kem encaps");
    let kem_server_ss = ml_kem_768::decapsulate(&kem_dk, &kem_ct).expect("ml-kem decaps");
    let mut kem_truncated_ct_bytes = kem_ct.clone().into_bytes();
    kem_truncated_ct_bytes.pop();
    let kem_truncated_ct = MlKemCiphertext::from_bytes(kem_truncated_ct_bytes);
    let kem_truncated_ct_rejected = ml_kem_768::decapsulate(&kem_dk, &kem_truncated_ct)
        .map(|replacement_ss| !bool::from(kem_client_ss.as_bytes().ct_eq(replacement_ss.as_bytes())))
        .unwrap_or(false);
    let transport_material = hkdf_sha256(
        kem_client_ss.as_bytes(),
        b"tafrah-auth-demo::transport-salt",
        &encode_parts(&[b"tafrah-auth-demo::transport"]),
        64,
    );
    let nonce_seed = Sha256::digest([kem_client_ss.as_bytes(), b"tafrah-auth-demo::nonce"].concat());
    let nonce = &nonce_seed[..16];
    let plaintext = b"tafrah-auth-demo::symmetric-roundtrip";
    let ciphertext = stream_xor(&transport_material[..32], nonce, b"client->server", plaintext);
    let recovered = stream_xor(&transport_material[..32], nonce, b"client->server", &ciphertext);
    let symmetric_roundtrip_ok = plaintext == recovered.as_slice();
    let hash_sha256_ok =
        format!("{:x}", Sha256::digest(b"tafrah-auth-demo::hash::sha256"))
            == "5f36ca6b07d4d4a0162b71332eddefb1b79719d4719e09e2e880c059881ef00b";

    let (hqc_ek, hqc_dk) = hqc_128::keygen(&mut rng).expect("hqc keygen");
    let (hqc_ct, hqc_client_ss) = hqc_128::encapsulate(&hqc_ek, &mut rng).expect("hqc encaps");
    let hqc_server_ss = hqc_128::decapsulate(&hqc_dk, &hqc_ct).expect("hqc decaps");
    let mut hqc_truncated_ct_bytes = hqc_ct.clone().into_bytes();
    hqc_truncated_ct_bytes.pop();
    let hqc_truncated_ct = HqcCiphertext::from_bytes(hqc_truncated_ct_bytes);
    let hqc_truncated_ct_rejected =
        matches!(hqc_128::decapsulate(&hqc_dk, &hqc_truncated_ct), Err(Error::InvalidCiphertextLength));

    let (ml_vk, ml_sk) = ml_dsa_keygen::ml_dsa_keygen(&mut rng, &ML_DSA_65).expect("ml-dsa keygen");
    let ml_message = b"tafrah-auth-demo::ml-dsa-65".to_vec();
    let ml_sig = ml_dsa_sign::ml_dsa_sign_with_context(&ml_sk, &ml_message, &[], &mut rng, &ML_DSA_65)
        .expect("ml-dsa sign");
    let ml_verify_ok =
        ml_dsa_verify::ml_dsa_verify_with_context(&ml_vk, &ml_message, &ml_sig, &[], &ML_DSA_65).is_ok();
    let ml_tamper_rejected =
        ml_dsa_verify::ml_dsa_verify_with_context(
            &ml_vk,
            b"tafrah-auth-demo::ml-dsa-65\x01",
            &ml_sig,
            &[],
            &ML_DSA_65,
        )
        .is_err();
    let mut ml_truncated_sig_bytes = ml_sig.clone().into_bytes();
    ml_truncated_sig_bytes.pop();
    let ml_truncated_sig = ml_dsa::types::Signature::from_bytes(ml_truncated_sig_bytes);
    let ml_truncated_sig_rejected = matches!(
        ml_dsa_verify::ml_dsa_verify_with_context(&ml_vk, &ml_message, &ml_truncated_sig, &[], &ML_DSA_65),
        Err(Error::InvalidSignatureLength)
    );
    let ml_mu = [0x5Au8; 64];
    let ml_extmu_sig =
        ml_dsa_sign::ml_dsa_sign_extmu_deterministic(&ml_sk, &ml_mu, &ML_DSA_65).expect("ml-dsa extmu sign");
    let ml_extmu_ok = ml_dsa_verify::ml_dsa_verify_extmu(&ml_vk, &ml_mu, &ml_extmu_sig, &ML_DSA_65).is_ok();
    let ml_prehash_sig = ml_dsa_sign::ml_dsa_sign_prehash_shake256_deterministic(
        &ml_sk,
        &ml_message,
        b"hashml",
        &ML_DSA_65,
    )
    .expect("ml-dsa prehash sign");
    let ml_prehash_ok = ml_dsa_verify::ml_dsa_verify_prehash_shake256(
        &ml_vk,
        &ml_message,
        &ml_prehash_sig,
        b"hashml",
        &ML_DSA_65,
    )
    .is_ok();
    let ml_signed = ml_dsa_sign::ml_dsa_sign_message_deterministic_with_context(
        &ml_sk,
        &ml_message,
        b"openml",
        &ML_DSA_65,
    )
    .expect("ml-dsa sign message");
    let ml_open_ok = ml_dsa_verify::ml_dsa_open_signed_message_with_context(
        &ml_vk,
        &ml_signed,
        b"openml",
        &ML_DSA_65,
    )
    .map(|opened| opened == ml_message)
    .unwrap_or(false);

    let (slh_vk, slh_sk) = keygen::slh_dsa_keygen(&mut rng, &SLH_DSA_SHAKE_128F).expect("slh keygen");
    let slh_message = b"tafrah-auth-demo::slh-dsa-shake-128f".to_vec();
    let slh_sig = sign::slh_dsa_sign(&slh_sk, &slh_message, &mut rng, &SLH_DSA_SHAKE_128F)
        .expect("slh sign");
    let slh_prehash_sig = prehash::hash_slh_sign(
        &slh_sk,
        &slh_message,
        &[],
        prehash::PrehashAlgorithm::Sha2_256,
        None,
        &SLH_DSA_SHAKE_128F,
    )
    .expect("slh prehash sign");
    let slh_verify_ok = verify::slh_dsa_verify(&slh_vk, &slh_message, &slh_sig, &SLH_DSA_SHAKE_128F).is_ok();
    let slh_prehash_verify_ok = prehash::hash_slh_verify(
        &slh_vk,
        &slh_message,
        &slh_prehash_sig,
        &[],
        prehash::PrehashAlgorithm::Sha2_256,
        &SLH_DSA_SHAKE_128F,
    )
    .is_ok();
    let slh_tamper_rejected =
        verify::slh_dsa_verify(&slh_vk, b"tafrah-auth-demo::slh-dsa-shake-128f\x02", &slh_sig, &SLH_DSA_SHAKE_128F)
            .is_err();
    let slh_prehash_tamper_rejected = prehash::hash_slh_verify(
        &slh_vk,
        b"tafrah-auth-demo::slh-dsa-shake-128f\x04",
        &slh_prehash_sig,
        &[],
        prehash::PrehashAlgorithm::Sha2_256,
        &SLH_DSA_SHAKE_128F,
    )
    .is_err();
    let mut slh_truncated_sig_bytes = slh_sig.clone().into_bytes();
    slh_truncated_sig_bytes.pop();
    let slh_truncated_sig = slh_dsa::types::Signature::from_bytes(slh_truncated_sig_bytes);
    let slh_truncated_sig_rejected = matches!(
        verify::slh_dsa_verify(&slh_vk, &slh_message, &slh_truncated_sig, &SLH_DSA_SHAKE_128F),
        Err(Error::InvalidSignatureLength)
    );

    let (falcon_vk, falcon_sk) = falcon_512::keygen(&mut rng).expect("falcon keygen");
    let falcon_message = b"tafrah-auth-demo::falcon-512".to_vec();
    let falcon_sig = falcon_512::sign(&falcon_sk, &falcon_message, &mut rng).expect("falcon sign");
    let falcon_verify_ok = falcon_512::verify(&falcon_vk, &falcon_message, &falcon_sig).is_ok();
    let falcon_tamper_rejected =
        falcon_512::verify(&falcon_vk, b"tafrah-auth-demo::falcon-512\x03", &falcon_sig).is_err();
    let mut falcon_truncated_sig_bytes = falcon_sig.clone().into_bytes();
    falcon_truncated_sig_bytes.pop();
    let falcon_truncated_sig = FalconSignature::from_bytes(falcon_truncated_sig_bytes);
    let falcon_truncated_sig_rejected = matches!(
        falcon_512::verify(&falcon_vk, &falcon_message, &falcon_truncated_sig),
        Err(Error::InvalidSignatureLength)
    );

    let kem_match = bool::from(kem_client_ss.as_bytes().ct_eq(kem_server_ss.as_bytes()));
    let hqc_match = bool::from(hqc_client_ss.as_bytes().ct_eq(hqc_server_ss.as_bytes()));
    let overall_ok = kem_match
        && kem_truncated_ct_rejected
        && symmetric_roundtrip_ok
        && hash_sha256_ok
        && hqc_match
        && hqc_truncated_ct_rejected
        && ml_verify_ok
        && ml_tamper_rejected
        && ml_truncated_sig_rejected
        && ml_extmu_ok
        && ml_prehash_ok
        && ml_open_ok
        && slh_verify_ok
        && slh_prehash_verify_ok
        && slh_prehash_tamper_rejected
        && slh_tamper_rejected
        && slh_truncated_sig_rejected
        && falcon_verify_ok
        && falcon_tamper_rejected
        && falcon_truncated_sig_rejected;

    println!(
        "{{\"language\":\"rust\",\"ml_kem_768_shared_secret_match\":{},\"ml_kem_768_truncated_ct_rejected\":{},\"symmetric_roundtrip_ok\":{},\"hash_sha256_ok\":{},\"hqc_128_shared_secret_match\":{},\"hqc_128_truncated_ct_rejected\":{},\"ml_dsa_65_verify_ok\":{},\"ml_dsa_65_tamper_rejected\":{},\"ml_dsa_65_truncated_sig_rejected\":{},\"ml_dsa_65_extmu_ok\":{},\"ml_dsa_65_prehash_ok\":{},\"ml_dsa_65_open_ok\":{},\"slh_dsa_shake_128f_verify_ok\":{},\"slh_dsa_shake_128f_prehash_verify_ok\":{},\"slh_dsa_shake_128f_prehash_tamper_rejected\":{},\"slh_dsa_shake_128f_tamper_rejected\":{},\"slh_dsa_shake_128f_truncated_sig_rejected\":{},\"falcon_512_verify_ok\":{},\"falcon_512_tamper_rejected\":{},\"falcon_512_truncated_sig_rejected\":{},\"overall_ok\":{}}}",
        json_bool(kem_match),
        json_bool(kem_truncated_ct_rejected),
        json_bool(symmetric_roundtrip_ok),
        json_bool(hash_sha256_ok),
        json_bool(hqc_match),
        json_bool(hqc_truncated_ct_rejected),
        json_bool(ml_verify_ok),
        json_bool(ml_tamper_rejected),
        json_bool(ml_truncated_sig_rejected),
        json_bool(ml_extmu_ok),
        json_bool(ml_prehash_ok),
        json_bool(ml_open_ok),
        json_bool(slh_verify_ok),
        json_bool(slh_prehash_verify_ok),
        json_bool(slh_prehash_tamper_rejected),
        json_bool(slh_tamper_rejected),
        json_bool(slh_truncated_sig_rejected),
        json_bool(falcon_verify_ok),
        json_bool(falcon_tamper_rejected),
        json_bool(falcon_truncated_sig_rejected),
        json_bool(overall_ok)
    );

    if !overall_ok {
        std::process::exit(1);
    }
}
