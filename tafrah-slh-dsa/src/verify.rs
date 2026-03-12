/// Generic SLH-DSA verification entry point.
///
/// Implements FIPS 205 Algorithm 20.
extern crate alloc;

use crate::address::{Adrs, FORS_TREE};
use crate::fors;
use crate::hash_functions;
use crate::hypertree;
use crate::params::Params;
use crate::types::{Signature, VerifyingKey};
use tafrah_traits::Error;

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

fn verify_with_context(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    ctx: Option<&[u8]>,
    params: &Params,
) -> Result<(), Error> {
    params.validate()?;
    let n = params.n;
    if let Some(ctx) = ctx {
        if ctx.len() > 255 {
            return Err(Error::InvalidParameter);
        }
    }

    if vk.bytes.len() != params.pk_bytes {
        return Err(Error::InvalidKeyLength);
    }

    if sig.bytes.len() != params.sig_bytes {
        return Err(Error::InvalidSignatureLength);
    }

    let pk_seed = &vk.bytes[..n];
    let pk_root = &vk.bytes[n..2 * n];
    let r = &sig.bytes[..n];

    let fors_sig_len = params.k * (1 + params.a) * n;
    let fors_sig = &sig.bytes[n..n + fors_sig_len];
    let ht_sig = &sig.bytes[n + fors_sig_len..];

    let m_bytes = params.message_digest_bytes();
    let digest =
        hash_functions::hash_msg_with_context(r, pk_seed, pk_root, msg, ctx, m_bytes, params);
    let (md, idx_tree, idx_leaf) = parse_digest_indices(&digest, params);

    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear_not_keypair(FORS_TREE);
    adrs.set_keypair_address(idx_leaf);
    let pk_fors = fors::fors_pk_from_sig(fors_sig, md, pk_seed, &mut adrs, params);

    let valid = hypertree::ht_verify(
        &pk_fors, ht_sig, pk_seed, pk_root, idx_tree, idx_leaf, params,
    );

    if valid {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

/// Verifies a signature with the internal FIPS 205 Algorithm 20 semantics.
pub fn slh_verify_internal(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    params: &Params,
) -> Result<(), Error> {
    verify_with_context(vk, msg, sig, None, params)
}

/// Verifies a signature with the pure FIPS 205 Algorithm 24 semantics.
pub fn slh_verify(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    ctx: &[u8],
    params: &Params,
) -> Result<(), Error> {
    verify_with_context(vk, msg, sig, Some(ctx), params)
}

/// Compatibility wrapper that preserves the previous internal verification
/// surface.
pub fn slh_dsa_verify(
    vk: &VerifyingKey,
    msg: &[u8],
    sig: &Signature,
    params: &Params,
) -> Result<(), Error> {
    slh_verify_internal(vk, msg, sig, params)
}
