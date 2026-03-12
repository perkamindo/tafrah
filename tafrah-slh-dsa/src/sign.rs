/// Generic SLH-DSA signing entry point.
///
/// Implements FIPS 205 Algorithm 19.
extern crate alloc;
use alloc::vec::Vec;

use crate::address::{Adrs, FORS_TREE};
use crate::fors;
use crate::hash_functions;
use crate::hypertree;
use crate::params::Params;
use crate::types::{Signature, SigningKey};
use tafrah_traits::Error;

fn parse_signing_key<'a>(
    sk: &'a SigningKey,
    params: &Params,
) -> Result<(&'a [u8], &'a [u8], &'a [u8], &'a [u8]), Error> {
    let n = params.n;
    if sk.bytes.len() != params.sk_bytes {
        return Err(Error::InvalidKeyLength);
    }

    Ok((
        &sk.bytes[..n],
        &sk.bytes[n..2 * n],
        &sk.bytes[2 * n..3 * n],
        &sk.bytes[3 * n..4 * n],
    ))
}

fn parse_digest_indices<'a>(digest: &'a [u8], params: &Params) -> (&'a [u8], u64, u32) {
    let md_len = (params.k * params.a + 7) / 8;
    let tree_bits = params.h - params.hp;
    let tree_bytes = (tree_bits + 7) / 8;
    let leaf_bytes = (params.hp + 7) / 8;
    let md = &digest[..md_len];

    let mut idx_tree: u64 = 0;
    for i in 0..tree_bytes {
        idx_tree = (idx_tree << 8) | digest[md_len + i] as u64;
    }
    let tree_mask = if tree_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << tree_bits) - 1
    };
    idx_tree &= tree_mask;

    let mut idx_leaf: u32 = 0;
    for i in 0..leaf_bytes {
        idx_leaf = (idx_leaf << 8) | digest[md_len + tree_bytes + i] as u32;
    }
    let leaf_mask = if params.hp >= 32 {
        u32::MAX
    } else {
        (1u32 << params.hp) - 1
    };
    idx_leaf &= leaf_mask;

    (md, idx_tree, idx_leaf)
}

fn sign_with_context_and_randomness(
    sk: &SigningKey,
    msg: &[u8],
    ctx: Option<&[u8]>,
    addrnd: Option<&[u8]>,
    params: &Params,
) -> Result<Signature, Error> {
    params.validate()?;
    let n = params.n;
    if let Some(ctx) = ctx {
        if ctx.len() > 255 {
            return Err(Error::InvalidParameter);
        }
    }
    let (sk_seed, sk_prf, pk_seed, pk_root) = parse_signing_key(sk, params)?;

    let opt_rand = match addrnd {
        Some(addrnd) => {
            if addrnd.len() != n {
                return Err(Error::InvalidParameter);
            }
            addrnd
        }
        None => pk_seed,
    };

    let r = hash_functions::prf_msg_with_context(sk_prf, opt_rand, msg, ctx, params);

    let m_bytes = params.message_digest_bytes();
    let digest =
        hash_functions::hash_msg_with_context(&r, pk_seed, pk_root, msg, ctx, m_bytes, params);
    let (md, idx_tree, idx_leaf) = parse_digest_indices(&digest, params);

    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear_not_keypair(FORS_TREE);
    adrs.set_keypair_address(idx_leaf);
    let sig_fors = fors::fors_sign(md, sk_seed, pk_seed, &mut adrs, params);

    let pk_fors = fors::fors_pk_from_sig(&sig_fors, md, pk_seed, &mut adrs, params);
    let sig_ht = hypertree::ht_sign(&pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf, params);

    let mut sig_bytes = Vec::with_capacity(n + sig_fors.len() + sig_ht.len());
    sig_bytes.extend_from_slice(&r);
    sig_bytes.extend_from_slice(&sig_fors);
    sig_bytes.extend_from_slice(&sig_ht);

    Ok(Signature { bytes: sig_bytes })
}

/// Signs a message using the deterministic or caller-randomized internal API
/// from FIPS 205 Algorithm 19.
pub fn slh_sign_internal(
    sk: &SigningKey,
    msg: &[u8],
    addrnd: Option<&[u8]>,
    params: &Params,
) -> Result<Signature, Error> {
    sign_with_context_and_randomness(sk, msg, None, addrnd, params)
}

/// Signs a message using the pure FIPS 205 API with an explicit context.
///
/// This matches FIPS 205 Algorithm 22 for the pure SPHINCS+ / SLH-DSA API.
pub fn slh_sign(
    sk: &SigningKey,
    msg: &[u8],
    ctx: &[u8],
    addrnd: Option<&[u8]>,
    params: &Params,
) -> Result<Signature, Error> {
    sign_with_context_and_randomness(sk, msg, Some(ctx), addrnd, params)
}

/// Compatibility wrapper that keeps the previous randomized signing surface.
pub fn slh_dsa_sign(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::Rng),
    params: &Params,
) -> Result<Signature, Error> {
    let mut opt_rand = alloc::vec![0u8; params.n];
    rng.fill_bytes(&mut opt_rand);
    slh_sign_internal(sk, msg, Some(&opt_rand), params)
}
