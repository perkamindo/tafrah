/// WOTS+ one-time signatures (FIPS 205, Section 5)
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::address::{Adrs, WOTS_PK, WOTS_PRF};
use crate::hash_functions;
use crate::params::Params;

/// WOTS+ chain function: iterate hash F `steps` times
/// chain(X, i, s, PK.seed, ADRS) = F^s(...F(X)...)
fn chain(
    x: &[u8],
    start: u32,
    steps: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    let mut tmp = x.to_vec();
    for j in start..start + steps {
        adrs.set_hash_address(j);
        tmp = hash_functions::hash_f(pk_seed, adrs, &tmp, params);
    }
    tmp
}

/// WOTS+ key generation: generate WOTS+ public key
/// Algorithm 6 from FIPS 205
pub fn wots_pkgen(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs, params: &Params) -> Vec<u8> {
    let mut wots_pk_adrs = adrs.clone();
    wots_pk_adrs.set_type_and_clear_not_keypair(WOTS_PK);
    wots_pk_adrs.set_keypair_address(adrs.get_keypair_address());

    let mut tmp = Vec::with_capacity(params.len * params.n);

    for i in 0..params.len {
        let mut sk_adrs = adrs.clone();
        sk_adrs.set_type_and_clear(WOTS_PRF);
        sk_adrs.set_keypair_address(adrs.get_keypair_address());
        sk_adrs.set_chain_address(i as u32);
        sk_adrs.set_hash_address(0);

        let sk = hash_functions::prf(pk_seed, sk_seed, &sk_adrs, params);

        adrs.set_chain_address(i as u32);
        let pk_i = chain(&sk, 0, (params.w - 1) as u32, pk_seed, adrs, params);
        tmp.extend_from_slice(&pk_i);
    }

    // Compress: T_len(PK.seed, wotspkADRS, tmp)
    hash_functions::hash_t(pk_seed, &wots_pk_adrs, &tmp, params)
}

/// WOTS+ sign: sign an n-byte message digest
/// Algorithm 7 from FIPS 205
pub fn wots_sign(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    // Convert message to base w
    let msg_base_w = base_w(msg, params.lg_w, params.len1);

    // Compute checksum
    let mut csum: u32 = 0;
    for &val in &msg_base_w {
        csum += (params.w - 1 - val as usize) as u32;
    }
    csum <<= (8 - ((params.len2 * params.lg_w) % 8)) % 8;

    // Convert checksum to base w
    let csum_bytes = csum.to_be_bytes();
    let csum_len = (params.len2 * params.lg_w + 7) / 8;
    let csum_base_w = base_w(&csum_bytes[4 - csum_len..], params.lg_w, params.len2);

    let mut sig = Vec::with_capacity(params.len * params.n);

    for i in 0..params.len {
        let val = if i < params.len1 {
            msg_base_w[i]
        } else {
            csum_base_w[i - params.len1]
        };

        let mut sk_adrs = adrs.clone();
        sk_adrs.set_type_and_clear(WOTS_PRF);
        sk_adrs.set_keypair_address(adrs.get_keypair_address());
        sk_adrs.set_chain_address(i as u32);
        sk_adrs.set_hash_address(0);

        let sk = hash_functions::prf(pk_seed, sk_seed, &sk_adrs, params);

        adrs.set_chain_address(i as u32);
        let sig_i = chain(&sk, 0, val as u32, pk_seed, adrs, params);
        sig.extend_from_slice(&sig_i);
    }

    sig
}

/// WOTS+ pkFromSig: compute public key from signature
/// Algorithm 8 from FIPS 205
pub fn wots_pk_from_sig(
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    params: &Params,
) -> Vec<u8> {
    let msg_base_w = base_w(msg, params.lg_w, params.len1);

    let mut csum: u32 = 0;
    for &val in &msg_base_w {
        csum += (params.w - 1 - val as usize) as u32;
    }
    csum <<= (8 - ((params.len2 * params.lg_w) % 8)) % 8;
    let csum_bytes = csum.to_be_bytes();
    let csum_len = (params.len2 * params.lg_w + 7) / 8;
    let csum_base_w = base_w(&csum_bytes[4 - csum_len..], params.lg_w, params.len2);

    let mut wots_pk_adrs = adrs.clone();
    wots_pk_adrs.set_type_and_clear_not_keypair(WOTS_PK);
    wots_pk_adrs.set_keypair_address(adrs.get_keypair_address());

    let mut tmp = Vec::with_capacity(params.len * params.n);

    for i in 0..params.len {
        let val = if i < params.len1 {
            msg_base_w[i]
        } else {
            csum_base_w[i - params.len1]
        };

        adrs.set_chain_address(i as u32);
        let sig_i = &sig[i * params.n..(i + 1) * params.n];
        let pk_i = chain(
            sig_i,
            val as u32,
            (params.w - 1) as u32 - val as u32,
            pk_seed,
            adrs,
            params,
        );
        tmp.extend_from_slice(&pk_i);
    }

    hash_functions::hash_t(pk_seed, &wots_pk_adrs, &tmp, params)
}

/// Convert byte string to base-w representation
fn base_w(input: &[u8], lg_w: usize, out_len: usize) -> Vec<u8> {
    let mut output = vec![0u8; out_len];
    let mut in_idx = 0;
    let mut bits = 0u32;
    let mut total = 0u32;

    for out_idx in 0..out_len {
        if bits == 0 {
            if in_idx < input.len() {
                total = input[in_idx] as u32;
                in_idx += 1;
            }
            bits = 8;
        }
        bits -= lg_w as u32;
        output[out_idx] = ((total >> bits) & ((1 << lg_w) - 1)) as u8;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::WOTS_HASH;
    use crate::params::SLH_DSA_SHA2_128F;

    fn hex_decode(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.as_bytes().chunks_exact(2) {
            let text = core::str::from_utf8(chunk).expect("valid hex utf8");
            out.push(u8::from_str_radix(text, 16).expect("valid hex"));
        }
        out
    }

    #[test]
    fn test_wots_pkgen_matches_sha2_128f_sphincs_master_leaf0() {
        let seed = hex_decode(
            "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E47",
        );
        let expected_leaf = hex_decode("BB82BCCC29CD6FC6548E25D90A326782");
        let sk_seed = &seed[..16];
        let pk_seed = &seed[32..48];

        let mut adrs = Adrs::new();
        adrs.set_layer_address((SLH_DSA_SHA2_128F.d - 1) as u32);
        adrs.set_tree_address(0);
        adrs.set_type_and_clear_not_keypair(WOTS_HASH);
        adrs.set_keypair_address(0);

        let leaf = wots_pkgen(sk_seed, pk_seed, &mut adrs, &SLH_DSA_SHA2_128F);
        assert_eq!(leaf, expected_leaf);
    }
}
