/// XMSS tree operations (FIPS 205, Section 6)
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::address::{Adrs, TREE, WOTS_HASH};
use crate::hash_functions;
use crate::params::Params;
use crate::wots;

fn wots_gen_leaf(
    sk_seed: &[u8],
    pk_seed: &[u8],
    addr_idx: u32,
    tree_adrs: &Adrs,
    params: &Params,
) -> Vec<u8> {
    let mut wots_adrs = Adrs::new();
    wots_adrs.set_layer_address(tree_adrs.get_layer_address());
    wots_adrs.set_tree_address(tree_adrs.get_tree_address());
    wots_adrs.set_type(WOTS_HASH);
    wots_adrs.set_keypair_address(addr_idx);
    wots::wots_pkgen(sk_seed, pk_seed, &mut wots_adrs, params)
}

fn treehash_with_auth(
    sk_seed: &[u8],
    pk_seed: &[u8],
    leaf_idx: u32,
    idx_offset: u32,
    tree_height: u32,
    tree_adrs: &mut Adrs,
    params: &Params,
) -> (Vec<u8>, Vec<u8>) {
    let n = params.n;
    let mut stack = Vec::with_capacity((tree_height as usize) + 1);
    let mut heights = Vec::with_capacity((tree_height as usize) + 1);
    let mut auth_path = vec![0u8; tree_height as usize * n];

    tree_adrs.set_type(TREE);

    for idx in 0..(1u32 << tree_height) {
        let leaf = wots_gen_leaf(sk_seed, pk_seed, idx + idx_offset, tree_adrs, params);
        stack.push(leaf);
        heights.push(0u32);

        if (leaf_idx ^ 0x1) == idx {
            auth_path[..n].copy_from_slice(stack.last().expect("leaf present"));
        }

        while stack.len() >= 2 && heights[heights.len() - 1] == heights[heights.len() - 2] {
            let node_height = heights[heights.len() - 1];
            let tree_idx = idx >> (node_height + 1);

            tree_adrs.set_tree_height(node_height + 1);
            tree_adrs.set_tree_index(tree_idx + (idx_offset >> (node_height + 1)));

            let right = stack.pop().expect("right node");
            let left = stack.pop().expect("left node");
            heights.pop();
            heights.pop();

            let mut combined = left;
            combined.extend_from_slice(&right);
            let parent = hash_functions::hash_h(pk_seed, tree_adrs, &combined, params);

            stack.push(parent);
            heights.push(node_height + 1);

            if (((leaf_idx >> (node_height + 1)) ^ 0x1) == tree_idx)
                && (node_height as usize + 1) < tree_height as usize
            {
                let offset = (node_height as usize + 1) * n;
                auth_path[offset..offset + n]
                    .copy_from_slice(stack.last().expect("parent node present"));
            }
        }
    }

    (
        stack.pop().unwrap_or_else(|| vec![0u8; n]),
        auth_path,
    )
}

/// Compute a subtree root with the reference treehash flow.
pub fn xmss_treehash(
    sk_seed: &[u8],
    pk_seed: &[u8],
    start: u32,
    height: u32,
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    treehash_with_auth(sk_seed, pk_seed, 0, start, height, adrs, params).0
}

/// XMSS sign: sign a message with XMSS
/// Algorithm 10 from FIPS 205
pub fn xmss_sign(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx: u32,
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    let mut wots_adrs = adrs.clone();
    wots_adrs.set_type(WOTS_HASH);
    wots_adrs.set_keypair_address(idx);
    let sig_wots = wots::wots_sign(msg, sk_seed, pk_seed, &mut wots_adrs, params);

    let mut tree_adrs = adrs.clone();
    tree_adrs.set_type(TREE);
    let (_root, auth) =
        treehash_with_auth(sk_seed, pk_seed, idx, 0, params.hp as u32, &mut tree_adrs, params);

    let mut sig = sig_wots;
    sig.extend_from_slice(&auth);
    sig
}

/// XMSS pkFromSig: compute root from XMSS signature
/// Algorithm 11 from FIPS 205
pub fn xmss_pk_from_sig(
    idx: u32,
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    let hp = params.hp;
    let wots_sig_len = params.len * params.n;

    let sig_wots = &sig[..wots_sig_len];
    let auth = &sig[wots_sig_len..];

    let mut wots_adrs = adrs.clone();
    wots_adrs.set_type(WOTS_HASH);
    wots_adrs.set_keypair_address(idx);
    let mut node = wots::wots_pk_from_sig(sig_wots, msg, pk_seed, &mut wots_adrs, params);

    adrs.set_type(TREE);
    for j in 0..hp {
        adrs.set_tree_height((j + 1) as u32);
        let auth_node = &auth[j * params.n..(j + 1) * params.n];

        let mut combined = if (idx >> j) & 1 == 0 {
            let mut pair = node;
            pair.extend_from_slice(auth_node);
            pair
        } else {
            let mut pair = auth_node.to_vec();
            pair.extend_from_slice(&node);
            pair
        };
        adrs.set_tree_index((idx >> (j + 1)) as u32);
        node = hash_functions::hash_h(pk_seed, adrs, &combined, params);
        combined.clear();
    }

    node
}
