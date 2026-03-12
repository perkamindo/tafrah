/// FORS few-time signatures (FIPS 205, Section 8)
extern crate alloc;
use alloc::vec::Vec;

use crate::address::{Adrs, FORS_PRF, FORS_ROOTS};
use crate::hash_functions;
use crate::params::Params;

/// FORS treehash: compute root of one FORS subtree
fn fors_treehash(
    sk_seed: &[u8],
    pk_seed: &[u8],
    start: u32,
    height: u32,
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    if height == 0 {
        // Leaf: PRF then F
        let mut sk_adrs = adrs.clone();
        sk_adrs.set_type_and_clear(FORS_PRF);
        sk_adrs.set_keypair_address(adrs.get_keypair_address());
        sk_adrs.set_tree_height(0);
        sk_adrs.set_tree_index(start);

        let sk = hash_functions::prf(pk_seed, sk_seed, &sk_adrs, params);

        adrs.set_tree_height(0);
        adrs.set_tree_index(start);
        return hash_functions::hash_f(pk_seed, adrs, &sk, params);
    }

    let mid = 1u32 << (height - 1);
    let left = fors_treehash(sk_seed, pk_seed, start, height - 1, adrs, params);
    let right = fors_treehash(sk_seed, pk_seed, start + mid, height - 1, adrs, params);

    adrs.set_tree_height(height);
    adrs.set_tree_index(start >> height);

    let mut combined = left;
    combined.extend_from_slice(&right);
    hash_functions::hash_h(pk_seed, adrs, &combined, params)
}

/// FORS sign: sign a message using FORS
/// Algorithm 16 from FIPS 205
pub fn fors_sign(
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    let k = params.k;
    let a = params.a;

    // Split md into k a-bit indices
    let indices = message_to_indices(md, k, a);

    let mut sig = Vec::new();

    for i in 0..k {
        let idx = indices[i];

        // Secret key value
        let mut sk_adrs = adrs.clone();
        sk_adrs.set_type_and_clear(FORS_PRF);
        sk_adrs.set_keypair_address(adrs.get_keypair_address());
        sk_adrs.set_tree_height(0);
        sk_adrs.set_tree_index((i * (1 << a) + idx) as u32);

        let sk = hash_functions::prf(pk_seed, sk_seed, &sk_adrs, params);
        sig.extend_from_slice(&sk);

        // Authentication path
        let mut auth = Vec::with_capacity(a * params.n);
        for j in 0..a {
            let s = (idx >> j) ^ 1;
            let subtree_start = (i * (1 << a) + (s << j)) as u32;
            let node = fors_treehash(sk_seed, pk_seed, subtree_start, j as u32, adrs, params);
            auth.extend_from_slice(&node);
        }
        sig.extend_from_slice(&auth);
    }

    sig
}

/// FORS pkFromSig: compute FORS public key from signature
/// Algorithm 17 from FIPS 205
pub fn fors_pk_from_sig(
    sig: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    let k = params.k;
    let a = params.a;

    let indices = message_to_indices(md, k, a);

    let node_size = params.n;
    let per_tree = node_size * (1 + a); // sk + a auth nodes

    let mut roots = Vec::with_capacity(k * node_size);

    for i in 0..k {
        let tree_sig = &sig[i * per_tree..];
        let sk_val = &tree_sig[..node_size];
        let auth = &tree_sig[node_size..per_tree];

        let idx = indices[i];

        // Compute leaf from sk
        adrs.set_tree_height(0);
        adrs.set_tree_index((i * (1 << a) + idx) as u32);
        let mut node = hash_functions::hash_f(pk_seed, adrs, sk_val, params);

        // Walk up the tree
        for j in 0..a {
            let auth_node = &auth[j * node_size..(j + 1) * node_size];
            adrs.set_tree_height((j + 1) as u32);
            let tree_idx = ((i * (1 << a) + idx) >> (j + 1)) as u32;
            adrs.set_tree_index(tree_idx);

            if (idx >> j) & 1 == 0 {
                let mut combined = node;
                combined.extend_from_slice(auth_node);
                node = hash_functions::hash_h(pk_seed, adrs, &combined, params);
            } else {
                let mut combined = auth_node.to_vec();
                combined.extend_from_slice(&node);
                node = hash_functions::hash_h(pk_seed, adrs, &combined, params);
            }
        }
        roots.extend_from_slice(&node);
    }

    // Compress roots into FORS public key
    let mut fors_pk_adrs = adrs.clone();
    fors_pk_adrs.set_type_and_clear_not_keypair(FORS_ROOTS);
    fors_pk_adrs.set_keypair_address(adrs.get_keypair_address());

    hash_functions::hash_t(pk_seed, &fors_pk_adrs, &roots, params)
}

/// Split message digest into k a-bit indices
fn message_to_indices(md: &[u8], k: usize, a: usize) -> Vec<usize> {
    let mut indices = Vec::with_capacity(k);
    let mut byte_idx = 0usize;
    let mut bits_available = 0usize;
    let mut accumulator = 0usize;
    let mask = (1usize << a) - 1;

    for _ in 0..k {
        while bits_available < a {
            accumulator = (accumulator << 8) | md.get(byte_idx).copied().unwrap_or(0) as usize;
            byte_idx += 1;
            bits_available += 8;
        }
        bits_available -= a;
        indices.push((accumulator >> bits_available) & mask);
    }
    indices
}
