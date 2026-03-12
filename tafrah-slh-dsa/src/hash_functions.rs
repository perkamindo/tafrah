/// Tweakable hash functions for SLH-DSA (FIPS 205)
/// Supports both SHA2 and SHAKE variants
extern crate alloc;
use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;

use crate::address::Adrs;
use crate::params::{HashType, Params};

use sha2::Digest;
use sha3::digest::{ExtendableOutput, XofReader};

fn contextual_message<'a>(msg: &'a [u8], ctx: Option<&'a [u8]>) -> Cow<'a, [u8]> {
    match ctx {
        Some(ctx) => {
            let mut prefixed = Vec::with_capacity(2 + ctx.len() + msg.len());
            prefixed.push(0);
            prefixed.push(ctx.len() as u8);
            prefixed.extend_from_slice(ctx);
            prefixed.extend_from_slice(msg);
            Cow::Owned(prefixed)
        }
        None => Cow::Borrowed(msg),
    }
}

/// PRF: pseudorandom function
/// SHAKE variant: SHAKE256(pk.seed || adrs || sk.seed)
/// SHA2 variant: SHA-256(pad64(pk.seed) || ADRS^c || sk.seed)
pub fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs, params: &Params) -> Vec<u8> {
    match params.hash_type {
        HashType::Shake => {
            use sha3::Shake256;
            let mut hasher = Shake256::default();
            let adrs_bytes = adrs.to_hash_bytes(params);
            sha3::digest::Update::update(&mut hasher, pk_seed);
            sha3::digest::Update::update(&mut hasher, &adrs_bytes);
            sha3::digest::Update::update(&mut hasher, sk_seed);
            let mut reader = hasher.finalize_xof();
            let mut out = vec![0u8; params.n];
            reader.read(&mut out);
            out
        }
        HashType::Sha2 => {
            let adrs_bytes = adrs.to_sha2_compressed_bytes();
            use sha2::Sha256;
            let mut padded = vec![0u8; 64];
            padded[..pk_seed.len()].copy_from_slice(pk_seed);
            let mut h = Sha256::new();
            sha2::Digest::update(&mut h, &padded);
            sha2::Digest::update(&mut h, &adrs_bytes);
            sha2::Digest::update(&mut h, sk_seed);
            let result = h.finalize();
            result[..params.n].to_vec()
        }
    }
}

/// PRF_msg: PRF for message randomizer
pub fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], params: &Params) -> Vec<u8> {
    prf_msg_with_context(sk_prf, opt_rand, msg, None, params)
}

/// PRF_msg with the pure-API context prefix from FIPS 205 Algorithms 22-25.
pub fn prf_msg_with_context(
    sk_prf: &[u8],
    opt_rand: &[u8],
    msg: &[u8],
    ctx: Option<&[u8]>,
    params: &Params,
) -> Vec<u8> {
    let message = contextual_message(msg, ctx);
    match params.hash_type {
        HashType::Shake => {
            use sha3::Shake256;
            let mut hasher = Shake256::default();
            sha3::digest::Update::update(&mut hasher, sk_prf);
            sha3::digest::Update::update(&mut hasher, opt_rand);
            sha3::digest::Update::update(&mut hasher, message.as_ref());
            let mut reader = hasher.finalize_xof();
            let mut out = vec![0u8; params.n];
            reader.read(&mut out);
            out
        }
        HashType::Sha2 => {
            use hmac::{Hmac, Mac};

            if params.n >= 24 {
                use sha2::Sha512;
                type HmacSha512 = Hmac<Sha512>;
                let mut mac = HmacSha512::new_from_slice(sk_prf).expect("HMAC key length");
                hmac::Mac::update(&mut mac, opt_rand);
                hmac::Mac::update(&mut mac, message.as_ref());
                let result = mac.finalize().into_bytes();
                result[..params.n].to_vec()
            } else {
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(sk_prf).expect("HMAC key length");
                hmac::Mac::update(&mut mac, opt_rand);
                hmac::Mac::update(&mut mac, message.as_ref());
                let result = mac.finalize().into_bytes();
                result[..params.n].to_vec()
            }
        }
    }
}

/// F: keyed hash function (single n-byte block)
pub fn hash_f(pk_seed: &[u8], adrs: &Adrs, m: &[u8], params: &Params) -> Vec<u8> {
    hash_t(pk_seed, adrs, m, params)
}

/// H: keyed hash function (two n-byte blocks)
pub fn hash_h(pk_seed: &[u8], adrs: &Adrs, m: &[u8], params: &Params) -> Vec<u8> {
    hash_t(pk_seed, adrs, m, params)
}

/// T_l: keyed hash function for l n-byte blocks
pub fn hash_t(pk_seed: &[u8], adrs: &Adrs, m: &[u8], params: &Params) -> Vec<u8> {
    match params.hash_type {
        HashType::Shake => {
            use sha3::Shake256;
            let mut hasher = Shake256::default();
            sha3::digest::Update::update(&mut hasher, pk_seed);
            let adrs_bytes = adrs.to_hash_bytes(params);
            sha3::digest::Update::update(&mut hasher, &adrs_bytes);
            sha3::digest::Update::update(&mut hasher, m);
            let mut reader = hasher.finalize_xof();
            let mut out = vec![0u8; params.n];
            reader.read(&mut out);
            out
        }
        HashType::Sha2 => {
            let adrs_bytes = adrs.to_sha2_compressed_bytes();
            // The currently tracked FIPS 205 / SPHINCS+ SHA2 reference lineage
            // uses SHA-256 for single-block F and SHA-512 for multi-block H/T_l
            // when n >= 24.
            if params.n >= 24 && m.len() > params.n {
                use sha2::Sha512;
                let mut padded = vec![0u8; 128];
                padded[..pk_seed.len()].copy_from_slice(pk_seed);
                let mut h = Sha512::new();
                sha2::Digest::update(&mut h, &padded);
                sha2::Digest::update(&mut h, &adrs_bytes);
                sha2::Digest::update(&mut h, m);
                let result = h.finalize();
                result[..params.n].to_vec()
            } else {
                use sha2::Sha256;
                let mut padded = vec![0u8; 64];
                padded[..pk_seed.len()].copy_from_slice(pk_seed);
                let mut h = Sha256::new();
                sha2::Digest::update(&mut h, &padded);
                sha2::Digest::update(&mut h, &adrs_bytes);
                sha2::Digest::update(&mut h, m);
                let result = h.finalize();
                result[..params.n].to_vec()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{hash_f, hash_h, hash_t};
    use crate::address::Adrs;
    use crate::params::{SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256S};
    use alloc::vec;
    use alloc::vec::Vec;
    use sha2::{Digest, Sha256, Sha512};

    fn expected_sha256_hash(pk_seed: &[u8], adrs: &Adrs, m: &[u8], n: usize) -> Vec<u8> {
        let adrs_bytes = adrs.to_sha2_compressed_bytes();
        let mut padded = vec![0u8; 64];
        padded[..pk_seed.len()].copy_from_slice(pk_seed);
        let mut h = Sha256::new();
        sha2::Digest::update(&mut h, &padded);
        sha2::Digest::update(&mut h, &adrs_bytes);
        sha2::Digest::update(&mut h, m);
        let result = h.finalize();
        result[..n].to_vec()
    }

    fn expected_sha512_hash(pk_seed: &[u8], adrs: &Adrs, m: &[u8], n: usize) -> Vec<u8> {
        let adrs_bytes = adrs.to_sha2_compressed_bytes();
        let mut padded = vec![0u8; 128];
        padded[..pk_seed.len()].copy_from_slice(pk_seed);
        let mut h = Sha512::new();
        sha2::Digest::update(&mut h, &padded);
        sha2::Digest::update(&mut h, &adrs_bytes);
        sha2::Digest::update(&mut h, m);
        let result = h.finalize();
        result[..n].to_vec()
    }

    #[test]
    fn sha2_192_f_uses_sha256_for_single_block() {
        let params = SLH_DSA_SHA2_192S;
        let pk_seed = [0x11u8; 24];
        let m = [0x22u8; 24];
        let mut adrs = Adrs::new();
        adrs.set_layer_address(3);
        adrs.set_tree_address(0x0102_0304_0506_0708);
        adrs.set_type_and_clear(crate::address::WOTS_HASH);
        adrs.set_keypair_address(0x1234);
        adrs.set_chain_address(9);
        adrs.set_hash_address(17);

        let actual = hash_f(&pk_seed, &adrs, &m, &params);
        let expected = expected_sha256_hash(&pk_seed, &adrs, &m, params.n);
        assert_eq!(actual, expected);
    }

    #[test]
    fn sha2_256_f_uses_sha256_for_single_block() {
        let params = SLH_DSA_SHA2_256S;
        let pk_seed = [0x33u8; 32];
        let m = [0x44u8; 32];
        let mut adrs = Adrs::new();
        adrs.set_layer_address(4);
        adrs.set_tree_address(0x1112_1314_1516_1718);
        adrs.set_type_and_clear(crate::address::FORS_TREE);
        adrs.set_keypair_address(0x5678);
        adrs.set_tree_height(12);
        adrs.set_tree_index(34);

        let actual = hash_f(&pk_seed, &adrs, &m, &params);
        let expected = expected_sha256_hash(&pk_seed, &adrs, &m, params.n);
        assert_eq!(actual, expected);
    }

    #[test]
    fn sha2_192_h_and_t_use_sha512_for_multi_block_inputs() {
        let params = SLH_DSA_SHA2_192S;
        let pk_seed = [0x55u8; 24];
        let mut adrs = Adrs::new();
        adrs.set_layer_address(1);
        adrs.set_tree_address(0x2223_2425_2627_2829);
        adrs.set_type_and_clear(crate::address::TREE);
        adrs.set_tree_height(3);
        adrs.set_tree_index(7);

        let mut two_blocks = vec![0x66u8; 2 * params.n];
        let actual_h = hash_h(&pk_seed, &adrs, &two_blocks, &params);
        let expected_h = expected_sha512_hash(&pk_seed, &adrs, &two_blocks, params.n);
        assert_eq!(actual_h, expected_h);

        two_blocks.extend_from_slice(&[0x77u8; 24]);
        let actual_t = hash_t(&pk_seed, &adrs, &two_blocks, &params);
        let expected_t = expected_sha512_hash(&pk_seed, &adrs, &two_blocks, params.n);
        assert_eq!(actual_t, expected_t);
    }

    #[test]
    fn sha2_256_h_and_t_use_sha512_for_multi_block_inputs() {
        let params = SLH_DSA_SHA2_256S;
        let pk_seed = [0x88u8; 32];
        let mut adrs = Adrs::new();
        adrs.set_layer_address(2);
        adrs.set_tree_address(0x3132_3334_3536_3738);
        adrs.set_type_and_clear(crate::address::FORS_ROOTS);
        adrs.set_tree_height(5);
        adrs.set_tree_index(11);

        let mut two_blocks = vec![0x99u8; 2 * params.n];
        let actual_h = hash_h(&pk_seed, &adrs, &two_blocks, &params);
        let expected_h = expected_sha512_hash(&pk_seed, &adrs, &two_blocks, params.n);
        assert_eq!(actual_h, expected_h);

        two_blocks.extend_from_slice(&[0xAAu8; 32]);
        let actual_t = hash_t(&pk_seed, &adrs, &two_blocks, &params);
        let expected_t = expected_sha512_hash(&pk_seed, &adrs, &two_blocks, params.n);
        assert_eq!(actual_t, expected_t);
    }
}

/// H_msg: hash message to m bytes
pub fn hash_msg(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    m_bytes: usize,
    params: &Params,
) -> Vec<u8> {
    hash_msg_with_context(r, pk_seed, pk_root, msg, None, m_bytes, params)
}

/// H_msg with the pure-API context prefix from FIPS 205 Algorithms 22-25.
pub fn hash_msg_with_context(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    ctx: Option<&[u8]>,
    m_bytes: usize,
    params: &Params,
) -> Vec<u8> {
    let message = contextual_message(msg, ctx);
    match params.hash_type {
        HashType::Shake => {
            use sha3::Shake256;
            let mut hasher = Shake256::default();
            sha3::digest::Update::update(&mut hasher, r);
            sha3::digest::Update::update(&mut hasher, pk_seed);
            sha3::digest::Update::update(&mut hasher, pk_root);
            sha3::digest::Update::update(&mut hasher, message.as_ref());
            let mut reader = hasher.finalize_xof();
            let mut out = vec![0u8; m_bytes];
            reader.read(&mut out);
            out
        }
        HashType::Sha2 => {
            if params.n >= 24 {
                mgf1_sha512_prefixed(r, pk_seed, pk_root, message.as_ref(), m_bytes)
            } else {
                mgf1_sha256_prefixed(r, pk_seed, pk_root, message.as_ref(), m_bytes)
            }
        }
    }
}

fn mgf1_sha256_prefixed(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    out_len: usize,
) -> Vec<u8> {
    use sha2::Sha256;

    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, r);
    sha2::Digest::update(&mut h, pk_seed);
    sha2::Digest::update(&mut h, pk_root);
    sha2::Digest::update(&mut h, msg);
    let seed = h.finalize();

    let mut mgf_input = Vec::with_capacity(r.len() + pk_seed.len() + seed.len());
    mgf_input.extend_from_slice(r);
    mgf_input.extend_from_slice(pk_seed);
    mgf_input.extend_from_slice(&seed);
    mgf1_sha256(&mgf_input, out_len)
}

fn mgf1_sha512_prefixed(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    out_len: usize,
) -> Vec<u8> {
    use sha2::Sha512;

    let mut h = Sha512::new();
    sha2::Digest::update(&mut h, r);
    sha2::Digest::update(&mut h, pk_seed);
    sha2::Digest::update(&mut h, pk_root);
    sha2::Digest::update(&mut h, msg);
    let seed = h.finalize();

    let mut mgf_input = Vec::with_capacity(r.len() + pk_seed.len() + seed.len());
    mgf_input.extend_from_slice(r);
    mgf_input.extend_from_slice(pk_seed);
    mgf_input.extend_from_slice(&seed);
    mgf1_sha512(&mgf_input, out_len)
}

fn mgf1_sha256(seed: &[u8], out_len: usize) -> Vec<u8> {
    use sha2::Sha256;

    let mut output = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while output.len() < out_len {
        let mut h = Sha256::new();
        sha2::Digest::update(&mut h, seed);
        sha2::Digest::update(&mut h, &counter.to_be_bytes());
        output.extend_from_slice(&h.finalize());
        counter += 1;
    }
    output.truncate(out_len);
    output
}

fn mgf1_sha512(seed: &[u8], out_len: usize) -> Vec<u8> {
    use sha2::Sha512;

    let mut output = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while output.len() < out_len {
        let mut h = Sha512::new();
        sha2::Digest::update(&mut h, seed);
        sha2::Digest::update(&mut h, &counter.to_be_bytes());
        output.extend_from_slice(&h.finalize());
        counter += 1;
    }
    output.truncate(out_len);
    output
}
