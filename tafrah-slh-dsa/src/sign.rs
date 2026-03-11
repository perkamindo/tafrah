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

/// Signs a message with SLH-DSA using the supplied parameter set.
pub fn slh_dsa_sign(
    sk: &SigningKey,
    msg: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    params: &Params,
) -> Result<Signature, Error> {
    params.validate()?;
    let n = params.n;

    if sk.bytes.len() != params.sk_bytes {
        return Err(Error::InvalidKeyLength);
    }

    // Parse SK
    let sk_seed = &sk.bytes[..n];
    let sk_prf = &sk.bytes[n..2 * n];
    let pk_seed = &sk.bytes[2 * n..3 * n];
    let pk_root = &sk.bytes[3 * n..4 * n];

    // Generate randomizer
    let mut opt_rand = alloc::vec![0u8; n];
    rng.fill_bytes(&mut opt_rand);

    // R = PRF_msg(SK.prf, opt_rand, M)
    let r = hash_functions::prf_msg(sk_prf, &opt_rand, msg, params);

    // Hash message to get (md, idx_tree, idx_leaf)
    let md_len = (params.k * params.a + 7) / 8;
    let tree_bits = params.h - params.hp;
    let tree_bytes = (tree_bits + 7) / 8;
    let leaf_bytes = (params.hp + 7) / 8;
    let m_bytes = md_len + tree_bytes + leaf_bytes;

    let digest = hash_functions::hash_msg(&r, pk_seed, pk_root, msg, m_bytes, params);

    let md = &digest[..md_len];

    // Extract idx_tree
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

    // Extract idx_leaf
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

    // FORS sign
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type(FORS_TREE);
    adrs.set_keypair_address(idx_leaf);
    let sig_fors = fors::fors_sign(md, sk_seed, pk_seed, &mut adrs, params);

    // FORS public key
    let pk_fors = fors::fors_pk_from_sig(&sig_fors, md, pk_seed, &mut adrs, params);

    // HT sign
    let sig_ht = hypertree::ht_sign(&pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf, params);

    // Signature = R || SIG_FORS || SIG_HT
    let mut sig_bytes = Vec::with_capacity(n + sig_fors.len() + sig_ht.len());
    sig_bytes.extend_from_slice(&r);
    sig_bytes.extend_from_slice(&sig_fors);
    sig_bytes.extend_from_slice(&sig_ht);

    Ok(Signature { bytes: sig_bytes })
}
