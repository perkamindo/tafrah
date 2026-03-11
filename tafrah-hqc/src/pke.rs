extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::arithmetic::{cyclic_product_mod_xn_minus_1, resize_vector, vector_add};
use crate::code;
use crate::hash::{shake256_512_ds, G_FCT_DOMAIN, H_FCT_DOMAIN, K_FCT_DOMAIN};
use crate::params::Params;
use crate::parse::{CiphertextParts, PublicKeyParts, SecretKeyParts, HQC_D_BYTES};
use crate::sampling::{fixed_weight_vectors_from_seed_sequence, words_to_bytes_le};
use crate::types::SharedSecret;

fn words_from_bytes_le(bytes: &[u8], word_count: usize) -> Vec<u64> {
    let mut words = vec![0u64; word_count];
    for (index, chunk) in bytes.chunks(8).enumerate() {
        let mut padded = [0u8; 8];
        padded[..chunk.len()].copy_from_slice(chunk);
        words[index] = u64::from_le_bytes(padded);
    }
    words
}

pub fn random_message_from_rng(
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    params: &Params,
) -> Vec<u64> {
    let mut message = vec![0u8; params.vec_k_size_bytes()];
    rng.fill_bytes(&mut message);
    words_from_bytes_le(&message, params.vec_k_size_u64())
}

pub fn random_salt_from_rng(
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    params: &Params,
) -> Vec<u8> {
    let mut salt = vec![0u8; params.salt_bytes];
    rng.fill_bytes(&mut salt);
    salt
}

fn theta_from_message(
    message: &[u64],
    pk: &PublicKeyParts,
    salt: &[u8],
    params: &Params,
) -> [u8; 64] {
    let mut input =
        Vec::with_capacity(params.vec_k_size_bytes() + params.seed_bytes + params.salt_bytes);
    input.extend_from_slice(&words_to_bytes_le(message, params.vec_k_size_bytes()));
    input.extend_from_slice(&pk.seed);
    input.extend_from_slice(salt);
    shake256_512_ds(&input, G_FCT_DOMAIN)
}

fn d_from_message(message: &[u64], params: &Params) -> [u8; HQC_D_BYTES] {
    let message_bytes = words_to_bytes_le(message, params.vec_k_size_bytes());
    shake256_512_ds(&message_bytes, H_FCT_DOMAIN)
}

pub fn shared_secret_from_message_and_ciphertext(
    message: &[u64],
    u: &[u64],
    v: &[u64],
    params: &Params,
) -> SharedSecret {
    let mut input = Vec::with_capacity(
        params.vec_k_size_bytes() + params.vec_n_size_bytes() + params.vec_n1n2_size_bytes(),
    );
    input.extend_from_slice(&words_to_bytes_le(message, params.vec_k_size_bytes()));
    input.extend_from_slice(&words_to_bytes_le(u, params.vec_n_size_bytes()));
    input.extend_from_slice(&words_to_bytes_le(v, params.vec_n1n2_size_bytes()));
    SharedSecret {
        bytes: shake256_512_ds(&input, K_FCT_DOMAIN).to_vec(),
    }
}

pub fn pke_encrypt(
    pk: &PublicKeyParts,
    message: &[u64],
    theta: &[u8],
    params: &Params,
) -> (Vec<u64>, Vec<u64>) {
    let mut samples = fixed_weight_vectors_from_seed_sequence(
        theta,
        &[params.omega_r, params.omega_r, params.omega_e],
        params,
    );
    let e = samples.pop().expect("e");
    let r2 = samples.pop().expect("r2");
    let r1 = samples.pop().expect("r1");

    let u = vector_add(&r1, &cyclic_product_mod_xn_minus_1(&r2, &pk.h, params));

    let mut tmp1 = resize_vector(&code::encode(message, params), params.n);
    let tmp2 = vector_add(
        &tmp1,
        &vector_add(&e, &cyclic_product_mod_xn_minus_1(&r2, &pk.s, params)),
    );
    tmp1.clear();
    let v = resize_vector(&tmp2, params.n1n2);

    (u, v)
}

pub fn pke_decrypt(sk: &SecretKeyParts, ciphertext: &CiphertextParts, params: &Params) -> Vec<u64> {
    let tmp1 = resize_vector(&ciphertext.v, params.n);
    let tmp2 = vector_add(
        &tmp1,
        &cyclic_product_mod_xn_minus_1(&sk.y, &ciphertext.u, params),
    );
    code::decode(&tmp2, params)
}

pub fn encapsulate_with_message_and_salt(
    pk: &PublicKeyParts,
    message: &[u64],
    salt: &[u8],
    params: &Params,
) -> (CiphertextParts, SharedSecret) {
    let theta = theta_from_message(message, pk, salt, params);
    let (u, v) = pke_encrypt(pk, message, &theta[..params.seed_bytes], params);
    let d = d_from_message(message, params);
    let ss = shared_secret_from_message_and_ciphertext(message, &u, &v, params);

    let mut salt_array = [0u8; 16];
    salt_array.copy_from_slice(&salt[..params.salt_bytes]);
    (
        CiphertextParts {
            u,
            v,
            d,
            salt: salt_array,
        },
        ss,
    )
}

pub fn decapsulate_ciphertext(
    sk: &SecretKeyParts,
    pk: &PublicKeyParts,
    ciphertext: &CiphertextParts,
    params: &Params,
) -> SharedSecret {
    let message = pke_decrypt(sk, ciphertext, params);
    let theta = theta_from_message(&message, pk, &ciphertext.salt, params);
    let (u2, v2) = pke_encrypt(pk, &message, &theta[..params.seed_bytes], params);
    let d2 = d_from_message(&message, params);

    let mut ss =
        shared_secret_from_message_and_ciphertext(&message, &ciphertext.u, &ciphertext.v, params);
    let mismatch = crate::arithmetic::vector_compare(
        &words_to_bytes_le(&ciphertext.u, params.vec_n_size_bytes()),
        &words_to_bytes_le(&u2, params.vec_n_size_bytes()),
    ) | crate::arithmetic::vector_compare(
        &words_to_bytes_le(&ciphertext.v, params.vec_n1n2_size_bytes()),
        &words_to_bytes_le(&v2, params.vec_n1n2_size_bytes()),
    ) | crate::arithmetic::vector_compare(&ciphertext.d, &d2);

    if mismatch != 0 {
        for byte in &mut ss.bytes {
            *byte = 0;
        }
    }

    ss
}
