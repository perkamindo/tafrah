/// Hypertree multi-layer construction (FIPS 205, Section 7)
extern crate alloc;
use alloc::vec::Vec;

use crate::address::Adrs;
use crate::params::Params;
use crate::xmss;

/// HT sign: sign a message using the hypertree
/// Algorithm 12 from FIPS 205
pub fn ht_sign(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    params: &Params,
) -> Vec<u8> {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);

    // Sign at layer 0
    let mut sig_tmp = xmss::xmss_sign(msg, sk_seed, pk_seed, idx_leaf, &mut adrs, params);

    // Compute root at layer 0
    let mut root = xmss::xmss_pk_from_sig(idx_leaf, &sig_tmp, msg, pk_seed, &mut adrs, params);

    let mut current_tree = idx_tree;
    let mut current_leaf;

    // Sign through remaining layers
    for j in 1..params.d {
        current_leaf = (current_tree & ((1 << params.hp) - 1)) as u32;
        current_tree >>= params.hp;

        adrs.set_layer_address(j as u32);
        adrs.set_tree_address(current_tree);

        let sig_layer = xmss::xmss_sign(&root, sk_seed, pk_seed, current_leaf, &mut adrs, params);
        root = xmss::xmss_pk_from_sig(current_leaf, &sig_layer, &root, pk_seed, &mut adrs, params);

        sig_tmp.extend_from_slice(&sig_layer);
    }

    sig_tmp
}

/// HT verify: verify a hypertree signature
/// Algorithm 13 from FIPS 205
pub fn ht_verify(
    msg: &[u8],
    sig: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    params: &Params,
) -> bool {
    let xmss_sig_len = (params.len + params.hp) * params.n;

    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);

    // Verify layer 0
    let sig_layer = &sig[..xmss_sig_len];
    let mut node = xmss::xmss_pk_from_sig(idx_leaf, sig_layer, msg, pk_seed, &mut adrs, params);

    let mut current_tree = idx_tree;
    let mut current_leaf;

    // Verify remaining layers
    for j in 1..params.d {
        current_leaf = (current_tree & ((1 << params.hp) - 1)) as u32;
        current_tree >>= params.hp;

        adrs.set_layer_address(j as u32);
        adrs.set_tree_address(current_tree);

        let offset = j * xmss_sig_len;
        let sig_layer = &sig[offset..offset + xmss_sig_len];
        node = xmss::xmss_pk_from_sig(current_leaf, sig_layer, &node, pk_seed, &mut adrs, params);
    }

    // Check if computed root matches
    node == pk_root
}
